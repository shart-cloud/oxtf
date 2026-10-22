//! Prototype for open question 7: the raw arena AST across PyO3 with
//! `self_cell` + `Arc` + node index.
//!
//! - [`OwnedParse`] (a `self_cell`) owns the bump arena and the source text
//!   and borrows the parsed tree plus a flat node table (`AstKind<'a>` per
//!   node in pre-order, with parent and subtree-end indices).
//! - Python objects ([`Document`], [`Node`]) hold `Arc<SharedParse>` and a
//!   `u32` node id. Every accessor goes through
//!   `with_dependent(|owner, parsed| ...)` and copies the answer out.
//!
//! Two constraints showed up (details in `docs/findings/W6.md`):
//! 1. The tree is invariant in `'a` (`tf_allocator::Box<'a, T>` wraps
//!    `&'a mut T`), so the cell must be `#[not_covariant]`: no
//!    `borrow_dependent()`, only closures.
//! 2. The tree is `!Send + !Sync` (arena `Vec`s keep a `&bumpalo::Bump`, and
//!    `Bump` is `!Sync`), but `#[pyclass]` requires `Send + Sync` (unless
//!    `unsendable`) and `Python::detach` requires the parse result to be
//!    `Send`. Hence the two `unsafe impl`s on [`SharedParse`].

use std::sync::Arc;

use pyo3::exceptions::{PyIndexError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;
use self_cell::self_cell;
use tf_allocator::Allocator;
use tf_ast::{AstKind, Expression, GetSpan, Visit};

pub struct Owner {
    alloc: Allocator,
    src: String,
}

pub struct Parsed<'a> {
    nodes: Vec<AstKind<'a>>,
    parent: Vec<u32>,
    /// Pre-order index one past the last node of the subtree.
    end: Vec<u32>,
    errors: Vec<(u32, u32, String)>,
}

self_cell!(
    pub struct OwnedParse {
        owner: Owner,
        #[not_covariant]
        dependent: Parsed,
    }
);

/// `OwnedParse` made shareable across threads.
pub struct SharedParse(OwnedParse);

// SAFETY: the `!Send`/`!Sync` parts are bumpalo's interior mutability: the
// `Bump` (chunk list in `Cell`s) and the `&Bump` + raw pointers inside arena
// `Vec`s, which bumpalo uses only to allocate, grow or free. After
// construction nothing allocates: the tree is reachable only through shared
// references handed out by `with_dependent`, no `&mut` to an arena `Vec` can
// be obtained, and arena nodes never run destructors (the dependent's own
// fields are std `Vec`s of references). The only `Bump` method called after
// construction is `allocated_bytes()`, which reads the chunk list. The cell is
// dropped once, by whichever thread drops the last `Arc`, with exclusive
// access.
unsafe impl Send for SharedParse {}
// SAFETY: see above; all access after construction is read-only.
unsafe impl Sync for SharedParse {}

struct Collect<'a> {
    nodes: Vec<AstKind<'a>>,
    parent: Vec<u32>,
    end: Vec<u32>,
    stack: Vec<u32>,
}

impl<'a> Visit<'a> for Collect<'a> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        let id = self.nodes.len() as u32;
        self.nodes.push(kind);
        self.parent
            .push(self.stack.last().copied().unwrap_or(u32::MAX));
        self.end.push(0);
        self.stack.push(id);
    }
    fn leave_node(&mut self, _kind: AstKind<'a>) {
        let id = self.stack.pop().unwrap();
        self.end[id as usize] = self.nodes.len() as u32;
    }
}

pub fn parse(src: String) -> tf_allocator::AllocResult<SharedParse> {
    OwnedParse::try_new(
        Owner {
            alloc: Allocator::new(),
            src,
        },
        |o| {
            let r = tf_parser::parse(&o.alloc, &o.src);
            let errors = r
                .errors
                .iter()
                .map(|e| (e.span.start, e.span.end, e.message.clone()))
                .collect();
            let file = o.alloc.alloc(r.file)?;
            let mut c = Collect {
                nodes: Vec::new(),
                parent: Vec::new(),
                end: Vec::new(),
                stack: Vec::new(),
            };
            c.visit_file(file);
            Ok(Parsed {
                nodes: c.nodes,
                parent: c.parent,
                end: c.end,
                errors,
            })
        },
    )
    .map(SharedParse)
}

impl SharedParse {
    #[inline]
    fn with<R>(&self, f: impl for<'a> FnOnce(&'a Owner, &Parsed<'a>) -> R) -> R {
        self.0.with_dependent(|o, p| f(o, p))
    }
}

fn children(p: &Parsed<'_>, id: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut j = id + 1;
    while j < p.end[id as usize] {
        out.push(j);
        j = p.end[j as usize];
    }
    out
}

/// A parsed HCL file (arena AST kept alive by this object and its nodes).
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Document {
    inner: Arc<SharedParse>,
}

/// One AST node: `Arc` to the document plus a pre-order node id.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Node {
    doc: Arc<SharedParse>,
    id: u32,
}

impl Node {
    fn new(doc: &Arc<SharedParse>, id: u32) -> Node {
        Node {
            doc: doc.clone(),
            id,
        }
    }
}

#[pymethods]
impl Document {
    #[getter]
    fn node_count(&self) -> usize {
        self.inner.with(|_, p| p.nodes.len())
    }
    /// Parse errors as `(start, end, message)`.
    #[getter]
    fn errors(&self) -> Vec<(u32, u32, String)> {
        self.inner.with(|_, p| p.errors.clone())
    }
    #[getter]
    fn root(&self) -> Node {
        Node::new(&self.inner, 0)
    }
    /// Arena bytes allocated for this parse.
    #[getter]
    fn arena_bytes(&self) -> usize {
        self.inner.with(|o, _| o.alloc.allocated_bytes())
    }
    fn node(&self, id: u32) -> PyResult<Node> {
        if (id as usize) < self.node_count() {
            Ok(Node::new(&self.inner, id))
        } else {
            Err(PyIndexError::new_err(id))
        }
    }
    /// Top-level blocks.
    fn blocks(&self) -> Vec<Node> {
        Node::new(&self.inner, 0).blocks()
    }
    /// Every node in pre-order.
    fn walk(&self) -> Vec<Node> {
        (0..self.node_count() as u32)
            .map(|i| Node::new(&self.inner, i))
            .collect()
    }
}

#[pymethods]
impl Node {
    #[getter]
    fn id(&self) -> u32 {
        self.id
    }
    /// The `AstType` name (`Block`, `Attribute`, `StringLiteral`, ...).
    #[getter]
    fn kind(&self) -> String {
        self.doc
            .with(|_, p| format!("{:?}", p.nodes[self.id as usize].ty()))
    }
    /// Byte span `(start, end)`.
    #[getter]
    fn span(&self) -> (u32, u32) {
        self.doc.with(|_, p| {
            let s = p.nodes[self.id as usize].span();
            (s.start, s.end)
        })
    }
    /// Source text of the node.
    #[getter]
    fn text(&self) -> String {
        self.doc.with(|o, p| {
            let s = p.nodes[self.id as usize].span();
            o.src[s.start as usize..s.end as usize].to_string()
        })
    }
    #[getter]
    fn parent(&self) -> Option<Node> {
        let pa = self.doc.with(|_, p| p.parent[self.id as usize]);
        (pa != u32::MAX).then(|| Node::new(&self.doc, pa))
    }
    fn children(&self) -> Vec<Node> {
        self.doc
            .with(|_, p| children(p, self.id))
            .into_iter()
            .map(|i| Node::new(&self.doc, i))
            .collect()
    }
    /// For a Block: its type (`resource`, `ingress`, ...).
    #[getter]
    fn block_type(&self) -> Option<String> {
        self.doc.with(|_, p| {
            p.nodes[self.id as usize]
                .as_block()
                .map(|b| b.block_type().to_string())
        })
    }
    /// For a Block: its labels.
    #[getter]
    fn labels(&self) -> Option<Vec<String>> {
        self.doc.with(|_, p| {
            p.nodes[self.id as usize]
                .as_block()
                .map(|b| b.label_values().map(str::to_string).collect())
        })
    }
    /// Attribute key, identifier or variable name.
    #[getter]
    fn name(&self) -> Option<String> {
        self.doc.with(|_, p| match p.nodes[self.id as usize] {
            AstKind::Attribute(a) => Some(a.key.name.to_string()),
            AstKind::Identifier(i) => Some(i.name.to_string()),
            AstKind::VariableExpr(v) => Some(v.name.to_string()),
            AstKind::FunctionCall(f) => Some(f.name.name.to_string()),
            _ => None,
        })
    }
    /// Python value of a literal node (null, bool, number, plain string).
    fn literal(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        enum L {
            Null,
            Bool(bool),
            Num(String),
            Str(String),
        }
        let l = self.doc.with(|_, p| match p.nodes[self.id as usize] {
            AstKind::NullLiteral(_) => Some(L::Null),
            AstKind::BooleanLiteral(b) => Some(L::Bool(b.value)),
            AstKind::NumberLiteral(n) => Some(L::Num(n.raw.to_string())),
            AstKind::StringLiteral(s) => Some(L::Str(s.value.to_string())),
            _ => None,
        });
        Ok(match l {
            None => return Err(PyValueError::new_err("not a literal node")),
            Some(L::Null) => py.None(),
            Some(L::Bool(b)) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
            Some(L::Num(s)) => match s.parse::<i64>() {
                Ok(i) => i.into_pyobject(py)?.into_any().unbind(),
                Err(_) => s
                    .parse::<f64>()
                    .map_err(|e| PyValueError::new_err(e.to_string()))?
                    .into_pyobject(py)?
                    .into_any()
                    .unbind(),
            },
            Some(L::Str(s)) => s.into_pyobject(py)?.into_any().unbind(),
        })
    }
    /// Child blocks (of a File, Body or Block).
    fn blocks(&self) -> Vec<Node> {
        self.body_items(true)
    }
    /// Attributes (of a File, Body or Block) as Attribute nodes.
    fn attributes(&self) -> Vec<Node> {
        self.body_items(false)
    }
    /// For an Attribute: its value expression node.
    #[getter]
    fn value(&self) -> Option<Node> {
        let id = self.doc.with(|_, p| {
            let AstKind::Attribute(a) = p.nodes[self.id as usize] else {
                return None;
            };
            // The expression is the child whose span equals the value's span.
            let target = expr_span(&a.value);
            children(p, self.id)
                .into_iter()
                .find(|&c| p.nodes[c as usize].span() == target)
        });
        id.map(|i| Node::new(&self.doc, i))
    }
    fn __repr__(&self) -> String {
        let (s, e) = self.span();
        format!("Node({} #{} {s}..{e})", self.kind(), self.id)
    }
}

fn expr_span(e: &Expression<'_>) -> tf_span::Span {
    e.span()
}

impl Node {
    fn body_items(&self, blocks: bool) -> Vec<Node> {
        let ids = self.doc.with(|_, p| {
            // Find the Body: the node itself, or its Body child (File, Block).
            let body = match p.nodes[self.id as usize] {
                AstKind::Body(_) => Some(self.id),
                AstKind::File(_) | AstKind::Block(_) => children(p, self.id)
                    .into_iter()
                    .find(|&c| matches!(p.nodes[c as usize], AstKind::Body(_))),
                _ => None,
            };
            body.map(|b| {
                children(p, b)
                    .into_iter()
                    .filter(|&c| {
                        matches!(
                            (blocks, p.nodes[c as usize]),
                            (true, AstKind::Block(_)) | (false, AstKind::Attribute(_))
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        });
        ids.into_iter().map(|i| Node::new(&self.doc, i)).collect()
    }
}

/// Parse HCL source into an arena AST (GIL released while parsing).
#[pyfunction]
fn parse_hcl(py: Python<'_>, source: String) -> PyResult<Document> {
    let parsed = py
        .detach(move || parse(source))
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(Document {
        inner: Arc::new(parsed),
    })
}

/// Micro-benchmark for Q7: `n` accesses of node spans through
/// `with_dependent` + node table (`"cell"`), versus the same lookups in a
/// plain owned `Vec<(u32, u32)>` copied out of the tree (`"owned"`).
/// Returns nanoseconds per access. Runs without the GIL.
#[pyfunction]
fn _bench_node_access(py: Python<'_>, doc: &Document, n: u64, mode: &str) -> PyResult<f64> {
    let inner = doc.inner.clone();
    let mode = mode.to_string();
    py.detach(move || {
        let count = inner.with(|_, p| p.nodes.len() as u64);
        let owned: Vec<(u32, u32)> = inner.with(|_, p| {
            p.nodes
                .iter()
                .map(|k| {
                    let s = k.span();
                    (s.start, s.end)
                })
                .collect()
        });
        let t = std::time::Instant::now();
        let mut acc = 0u64;
        match mode.as_str() {
            "cell" => {
                for i in 0..n {
                    let id = (i % count) as usize;
                    acc += inner.with(|_, p| p.nodes[std::hint::black_box(id)].span().end) as u64;
                }
            }
            "owned" => {
                for i in 0..n {
                    let id = (i % count) as usize;
                    acc += owned[std::hint::black_box(id)].1 as u64;
                }
            }
            _ => return Err(PyValueError::new_err("mode: cell | owned")),
        }
        std::hint::black_box(acc);
        Ok(t.elapsed().as_nanos() as f64 / n as f64)
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Document>()?;
    m.add_class::<Node>()?;
    m.add_function(wrap_pyfunction!(parse_hcl, m)?)?;
    m.add_function(wrap_pyfunction!(_bench_node_access, m)?)?;
    let _ = PyList::empty(m.py());
    Ok(())
}
