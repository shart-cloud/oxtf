//! Arrow export: columns are built in Rust with arrow-rs (GIL released) and
//! handed to any Arrow consumer through the Arrow PyCapsule interface
//! (`__arrow_c_stream__`, an `ArrowArrayStream` in a capsule named
//! `"arrow_array_stream"`). No Python object is created per cell; pyarrow
//! (or polars, duckdb, ...) imports the buffers zero-copy.

use std::ffi::CStr;
use std::sync::{Arc, Mutex};

use arrow_array::builder::{ListBuilder, StringBuilder, StructBuilder, UInt32Builder};
use arrow_array::ffi_stream::FFI_ArrowArrayStream;
use arrow_array::{ArrayRef, RecordBatch, RecordBatchIterator};
use arrow_schema::{ArrowError, DataType, Field, Fields, Schema};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyCapsule;

use crate::{ScanData, body_json, loc, mode_str, truth_str};

const STREAM_NAME: &CStr = c"arrow_array_stream";

/// Holds one RecordBatch until a consumer takes it.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct ArrowStream {
    batch: Mutex<Option<RecordBatch>>,
}

impl ArrowStream {
    pub fn new(batch: RecordBatch) -> Self {
        ArrowStream {
            batch: Mutex::new(Some(batch)),
        }
    }
}

#[pymethods]
impl ArrowStream {
    /// Arrow PyCapsule interface. The stream can be consumed once.
    #[pyo3(signature = (requested_schema = None))]
    fn __arrow_c_stream__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyCapsule>> {
        let _ = requested_schema; // schema negotiation not supported (allowed by the spec)
        let batch = self
            .batch
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("Arrow stream already consumed"))?;
        let schema = batch.schema();
        let reader = RecordBatchIterator::new(vec![Ok(batch)], schema);
        let stream = FFI_ArrowArrayStream::new(Box::new(reader));
        PyCapsule::new_with_value(py, stream, STREAM_NAME)
    }
    #[getter]
    fn num_rows(&self) -> usize {
        self.batch
            .lock()
            .unwrap()
            .as_ref()
            .map_or(0, |b| b.num_rows())
    }
}

fn utf8(name: &str, nullable: bool) -> Field {
    Field::new(name, DataType::Utf8, nullable)
}

fn step_fields() -> Fields {
    Fields::from(vec![
        utf8("kind", false),
        utf8("label", false),
        utf8("file", false),
        Field::new("line", DataType::UInt32, false),
        Field::new("column", DataType::UInt32, false),
        utf8("resource", true),
        utf8("attribute", true),
    ])
}

pub fn findings_schema() -> Schema {
    Schema::new(vec![
        utf8("fingerprint", false),
        utf8("rule", false),
        utf8("category", false),
        utf8("level", false),
        utf8("certainty", false),
        utf8("address", false),
        // Null for a finding on a file (a whole-file policy result).
        utf8("resource_type", true),
        utf8("module", false),
        utf8("message", false),
        utf8("root", false),
        utf8("attribute", true),
        utf8("file", false),
        Field::new("line", DataType::UInt32, false),
        Field::new("column", DataType::UInt32, false),
        Field::new(
            "provenance",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(step_fields()),
                true,
            ))),
            false,
        ),
        // The complete finding record as JSON, for fields with no column.
        utf8("record", false),
    ])
}

pub fn findings_batch(d: &ScanData) -> Result<RecordBatch, ArrowError> {
    let files = d.files();
    let fs = &d.result.findings;
    let mut cols: Vec<StringBuilder> = (0..11).map(|_| StringBuilder::new()).collect();
    let mut attribute = StringBuilder::new();
    let mut record = StringBuilder::new();
    let mut line = UInt32Builder::with_capacity(fs.len());
    let mut column = UInt32Builder::with_capacity(fs.len());
    let step_builders: Vec<Box<dyn arrow_array::builder::ArrayBuilder>> = vec![
        Box::new(StringBuilder::new()),
        Box::new(StringBuilder::new()),
        Box::new(StringBuilder::new()),
        Box::new(UInt32Builder::new()),
        Box::new(UInt32Builder::new()),
        Box::new(StringBuilder::new()),
        Box::new(StringBuilder::new()),
    ];
    let mut prov = ListBuilder::new(StructBuilder::new(step_fields(), step_builders));
    let mut repos = tf_linter::record::RepoRoots::new();
    for f in fs {
        let (file, l, c) = loc(files, f.primary);
        let root = f.root.display().to_string();
        let fingerprint = tf_linter::record::finding_fingerprint(files, f, &mut repos);
        let vals: [Option<&str>; 11] = [
            Some(&fingerprint),
            Some(&f.rule),
            Some(f.category.as_str()),
            Some(f.level.as_str()),
            Some(f.certainty.as_str()),
            Some(&f.address),
            f.resource_type.as_deref(),
            Some(&f.module),
            Some(&f.message),
            Some(&root),
            Some(&file),
        ];
        for (b, v) in cols.iter_mut().zip(vals) {
            b.append_option(v);
        }
        attribute.append_option(f.attribute.as_deref());
        record.append_value(tf_linter::render::finding_json(files, f).to_string());
        line.append_value(l);
        column.append_value(c);
        let sb = prov.values();
        for s in &f.provenance {
            let (sf, sl, sc) = loc(files, s.at);
            sb.field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(s.kind.as_str());
            sb.field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&s.label);
            sb.field_builder::<StringBuilder>(2)
                .unwrap()
                .append_value(sf);
            sb.field_builder::<UInt32Builder>(3)
                .unwrap()
                .append_value(sl);
            sb.field_builder::<UInt32Builder>(4)
                .unwrap()
                .append_value(sc);
            sb.field_builder::<StringBuilder>(5)
                .unwrap()
                .append_option(s.resource.as_deref());
            sb.field_builder::<StringBuilder>(6)
                .unwrap()
                .append_option(s.attribute.as_deref());
            sb.append(true);
        }
        prov.append(true);
    }
    let mut arrays: Vec<ArrayRef> = cols
        .iter_mut()
        .map(|b| Arc::new(b.finish()) as ArrayRef)
        .collect();
    // Column order: 10 strings up to root, then attribute, file, line, column, provenance, record.
    let file = arrays.pop().unwrap();
    arrays.push(Arc::new(attribute.finish()));
    arrays.push(file);
    arrays.push(Arc::new(line.finish()));
    arrays.push(Arc::new(column.finish()));
    arrays.push(Arc::new(prov.finish()));
    arrays.push(Arc::new(record.finish()));
    // The list's item field from ListBuilder is nullable "item"; match it.
    RecordBatch::try_new(Arc::new(findings_schema()), arrays)
}

pub fn resources_schema() -> Schema {
    Schema::new(vec![
        utf8("root", false),
        utf8("module", false),
        utf8("address", false),
        utf8("base_address", false),
        utf8("mode", false),
        utf8("type", false),
        utf8("name", false),
        utf8("key", true),
        utf8("existence", false),
        utf8("file", false),
        Field::new("line", DataType::UInt32, false),
        Field::new("column", DataType::UInt32, false),
        utf8("attributes", false),
    ])
}

pub fn resources_batch(d: &ScanData) -> Result<RecordBatch, ArrowError> {
    let files = d.files();
    let n = d.resources.len();
    let mut s: Vec<StringBuilder> = (0..10).map(|_| StringBuilder::new()).collect();
    let mut line = UInt32Builder::with_capacity(n);
    let mut column = UInt32Builder::with_capacity(n);
    let mut attrs = StringBuilder::new();
    for &(a, m, r) in &d.resources {
        let an = &d.analyses[a as usize];
        let res = &an.modules[m as usize].resources[r as usize];
        let (file, l, c) = loc(files, res.span);
        let root = an.root_dir.display().to_string();
        s[0].append_value(root);
        s[1].append_value(&res.module);
        s[2].append_value(&res.address);
        s[3].append_value(&res.base_address);
        s[4].append_value(mode_str(res.mode));
        s[5].append_value(&res.ty);
        s[6].append_value(&res.name);
        s[7].append_option(res.key.as_deref());
        s[8].append_value(truth_str(res.existence));
        s[9].append_value(file);
        line.append_value(l);
        column.append_value(c);
        attrs.append_value(body_json(&res.body).to_string());
    }
    let mut arrays: Vec<ArrayRef> = s
        .iter_mut()
        .map(|b| Arc::new(b.finish()) as ArrayRef)
        .collect();
    arrays.push(Arc::new(line.finish()));
    arrays.push(Arc::new(column.finish()));
    arrays.push(Arc::new(attrs.finish()));
    RecordBatch::try_new(Arc::new(resources_schema()), arrays)
}
