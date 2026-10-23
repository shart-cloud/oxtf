//! Checkov resource checks written in Python, run natively.
//!
//! The importer (`tfscan/checkov_python.py`) serializes a check's
//! `scan_resource_conf` (with the methods and helper functions it calls,
//! and every constant it reads) as a restricted-Python AST. This module
//! interprets that AST over the Checkov-shaped configuration of a resource
//! ([`crate::checkov::configuration`]), with Python's semantics for the
//! subset: truthiness, `==` / `in` / ordering across types, indexing and
//! slicing, `dict` / `list` / `str` / `set` methods, the built-ins and
//! Checkov helpers the checks use, `re`, `try` / `except`, and in-place
//! mutation of the check's own copy of the configuration.
//!
//! Abstract values stay abstract until the program inspects them:
//!
//! - an `Unknown` or `Tainted` leaf that decides a branch, a comparison or
//!   an operation stops the run with that truth (no finding, or a
//!   conditional one), witnessed by the leaf;
//! - a `OneOf` is resolved by running the program once per alternative
//!   (forking at the first inspection) and joining the results as
//!   [`truth::combine_one_of`] does.
//!
//! `FAILED` is a finding; `PASSED` and `UNKNOWN` are not. A Python
//! exception that escapes the check, an operation outside the subset or an
//! exhausted step budget is a rule error, separate from an unknown input.
//! A finding is located by the check's
//! `evaluated_keys` (the paths Checkov reports), else the resource.

use rustc_hash::FxHashMap as HashMap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::truth::{self, Truth};
use tf_eval::{Kind, Known, Value, Verdict};
use tf_linter::RuleBudget;
use tf_semantic::Resource;

use crate::{py, pyre};

mod builtins;
mod convert;
mod expressions;
pub mod iam;
mod iam_queries;
mod interp;
mod methods;
mod program;
mod statements;
mod values;
use builtins::*;
use convert::*;
use iam_queries::*;
use interp::*;
use methods::*;
pub use program::*;
use values::*;

/// The program format this build reads (`version` in the program).
pub const PROGRAM_VERSION: u32 = 1;

/// Statements executed per resource before reporting a rule error.
const STEP_BUDGET: u32 = 200_000;
/// Runs per resource when forking over `OneOf` alternatives.
const RUN_BUDGET: usize = 64;

// -- running a check -----------------------------------------------------

/// A program ready to run: what [`compile`](crate::compile) keeps.
#[derive(Debug)]
pub struct Check {
    program: Arc<Program>,
    /// The program never changes its input in place ([`mutates`]), so
    /// every run on a resource can read the one conversion of its
    /// configuration instead of building its own.
    shares_input: bool,
}

impl Check {
    pub fn new(program: Program) -> Check {
        let shares_input = !program.functions.values().any(|f| mutates(&f.body));
        Check {
            program: Arc::new(program),
            shares_input,
        }
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    /// Run the check on `resource`.
    pub fn evaluate(&self, resource: &Resource) -> Result<Verdict, String> {
        self.evaluate_with_budget(resource, &RuleBudget::default())
    }

    pub fn evaluate_with_budget(
        &self,
        resource: &Resource,
        budget: &RuleBudget,
    ) -> Result<Verdict, String> {
        budget.finish(evaluate(self, resource, budget))
    }
}

/// Root-owned state shared by the checks that judge one resource in
/// turn: the resource's configuration as Python values (read by every
/// check whose program does not mutate it) and the mutable class
/// attributes (Checkov's class-level caches, shared by every check of the
/// resource as in Checkov's process). The engine judges a resource's
/// rules on one thread, one after the other, so one entry is enough.
struct ResourceCache {
    uid: u64,
    input: Option<(Py, Rc<Paths>)>,
    statics: HashMap<String, Py>,
}

impl Default for ResourceCache {
    fn default() -> Self {
        Self {
            uid: u64::MAX,
            input: None,
            statics: HashMap::default(),
        }
    }
}

/// The resource's configuration as the check receives it. Ids of `OneOf`
/// values are assigned in a fixed traversal order, so every run sees the
/// same `OneOf` under the same id, whether or not the conversion is
/// shared. Checkov's runner adds the resource's address (and its lines,
/// which no exported check reads).
fn input(resource: &Resource, conf: &Value) -> (Py, Rc<Paths>) {
    let mut converter = Converter {
        next_id: 0,
        path: Vec::new(),
        paths: Paths::default(),
    };
    let py_conf = converter.py(conf);
    if let Py::Dict(d) = &py_conf {
        d.borrow_mut()
            .push((Py::str("__address__"), Py::str(&resource.address)));
    }
    (py_conf, Rc::new(converter.paths))
}

fn run(
    check: &Check,
    resource: &Resource,
    conf: &Value,
    budget: &RuleBudget,
) -> Result<Verdict, String> {
    budget.with_cache(|cache: &mut ResourceCache| {
        if cache.uid != resource.uid {
            *cache = ResourceCache {
                uid: resource.uid,
                ..ResourceCache::default()
            };
        }
    });
    run_with(
        check,
        resource,
        conf,
        &mut HashMap::default(),
        &mut 0,
        budget,
    )
}

fn evaluate(check: &Check, resource: &Resource, budget: &RuleBudget) -> Result<Verdict, String> {
    let conf = crate::checkov::resource_configuration(resource);
    let timer = (debug() == "time").then(std::time::Instant::now);
    let v = run(check, resource, conf, budget);
    if let Some(t) = timer {
        eprintln!(
            "TIME {} {} {}us",
            check.program.entry,
            resource.address,
            t.elapsed().as_micros()
        );
    }
    v
}

fn run_with(
    check: &Check,
    resource: &Resource,
    conf: &Value,
    choices: &mut HashMap<usize, usize>,
    runs: &mut usize,
    budget: &RuleBudget,
) -> Result<Verdict, String> {
    budget.charge(1)?;
    let program = &*check.program;
    *runs += 1;
    if *runs > RUN_BUDGET {
        return Err("checkov_python: alternative run budget exhausted".into());
    }
    let (mut interp, py_conf) = interpreter(check, resource, conf, choices, budget);
    let shared = choices.is_empty();
    let outcome = interp.call_function(&program.entry, vec![py_conf], Vec::new());
    if shared && !matches!(outcome, Err(Flow::Fork(..))) {
        let statics = std::mem::take(&mut interp.statics);
        budget.with_cache(|cache: &mut ResourceCache| cache.statics = statics);
    }
    trace_outcome(program, resource, &outcome);
    Ok(match outcome {
        Ok(Py::Result(r)) if &*r == "FAILED" => {
            Verdict::new(Truth::True, Some(witness(&mut interp, program, conf)))
        }
        Ok(_) => Verdict::FALSE,
        Err(Flow::Abstract(w, tainted)) => Verdict::new(
            if tainted {
                Truth::Tainted
            } else {
                Truth::Unknown
            },
            Some((*w).clone()),
        ),
        Err(Flow::Fork(id, n)) => {
            let tainted = oneof_tainted(conf, id);
            let verdicts = (0..n)
                .map(|i| {
                    choices.insert(id, i);
                    let v = run_with(check, resource, conf, choices, runs, budget);
                    choices.remove(&id);
                    v
                })
                .collect::<Result<_, _>>()?;
            truth::combine_one_of(verdicts, tainted)
        }
        Err(Flow::Unsupported(why)) => {
            return Err(execution_error(program, resource, &why));
        }
        Err(Flow::Exc(name)) => {
            return Err(execution_error(
                program,
                resource,
                &format!("raised {name}"),
            ));
        }
        Err(_) => {
            return Err(format!(
                "checkov_python {}: control flow escaped",
                program.entry
            ));
        }
    })
}

fn execution_error(program: &Program, resource: &Resource, why: &str) -> String {
    if !debug().is_empty() {
        eprintln!(
            "checkov_python {}: {}: {why}",
            program.entry, resource.address
        );
    }
    format!("checkov_python {}: {why}", program.entry)
}

fn interpreter<'p>(
    check: &'p Check,
    resource: &'p Resource,
    conf: &Value,
    choices: &HashMap<usize, usize>,
    budget: &'p RuleBudget,
) -> (Interp<'p>, Py) {
    let program = &*check.program;
    let (py_conf, paths) = if check.shares_input {
        budget.with_cache(|cache: &mut ResourceCache| {
            cache
                .input
                .get_or_insert_with(|| input(resource, conf))
                .clone()
        })
    } else {
        input(resource, conf)
    };
    let mut self_attrs: HashMap<String, Py> = program
        .self_attrs
        .iter()
        .filter_map(|(k, v)| Py::from_const(v).ok().map(|p| (k.clone(), p)))
        .collect();
    self_attrs.insert("entity_type".into(), Py::str(&resource.ty));
    // Mutable class attributes are shared by every check of this
    // resource; a forked run starts afresh.
    let shared = choices.is_empty();
    let statics = if shared {
        budget.with_cache(|cache: &mut ResourceCache| cache.statics.clone())
    } else {
        HashMap::default()
    };
    let interp = Interp {
        program,
        resource,
        self_attrs,
        choices: choices.clone(),
        statics,
        steps: std::cell::Cell::new(0),
        budget,
        paths,
        reads: RefCell::new(Vec::new()),
        key_lists: RefCell::new(HashMap::default()),
        delegated: RefCell::new(None),
    };
    (interp, py_conf)
}

fn trace_outcome(program: &Program, resource: &Resource, outcome: &R<Py>) {
    if debug() == "2" {
        let what = match outcome {
            Ok(Py::Result(r)) => r.to_string(),
            Ok(other) => format!("returned {}", other.type_name()),
            Err(Flow::Abstract(w, t)) => format!("abstract (tainted={t}) {:?}", w.kind),
            Err(Flow::Fork(id, n)) => format!("fork {id}/{n}"),
            Err(Flow::Exc(e)) => format!("raised {e}"),
            Err(Flow::Unsupported(u)) => format!("unsupported {u}"),
            Err(_) => "control flow escaped".into(),
        };
        eprintln!(
            "checkov_python {}: {}: {what}",
            program.entry, resource.address
        );
    }
}

/// Whether the `OneOf` with traversal id `id` is tainted.
fn oneof_tainted(conf: &Value, id: usize) -> bool {
    fn walk(v: &Value, next: &mut usize, id: usize) -> Option<bool> {
        match &v.kind {
            Kind::Known(Known::List(items)) => items.iter().find_map(|x| walk(x, next, id)),
            Kind::Known(Known::Object(m)) => m.values().find_map(|x| walk(x, next, id)),
            Kind::Known(Known::Json(inner)) => walk(inner, next, id),
            Kind::OneOf(o) => {
                let mine = *next;
                *next += 1;
                if mine == id {
                    return Some(o.tainted);
                }
                o.alternatives.iter().find_map(|a| walk(a, next, id))
            }
            _ => None,
        }
    }
    walk(conf, &mut 0, id).unwrap_or(false)
}

/// The configured value a failing check reported in `evaluated_keys`
/// (paths like `a/[0]/b`); for a check that reports none, what its
/// lookups imply ([`traced`]); else the whole configuration.
fn witness(interp: &mut Interp, program: &Program, conf: &Value) -> Value {
    let mut keys = interp.self_attrs.get("evaluated_keys").cloned();
    let empty = |k: &Option<Py>| match k {
        Some(Py::List(l)) => l.borrow().is_empty(),
        Some(Py::Str(s)) => s.is_empty(),
        _ => true,
    };
    if empty(&keys)
        && let Some(f) = &program.evaluated_keys
        && let Ok(v) = interp.call_function(f, Vec::new(), Vec::new())
    {
        keys = Some(v);
    }
    let first = match keys {
        Some(Py::List(l)) => l.borrow().first().and_then(|k| match k {
            Py::Str(s) => Some(s.clone()),
            _ => None,
        }),
        Some(Py::Str(s)) => Some(s),
        _ => None,
    };
    let Some(path) = first.filter(|p| !p.is_empty()) else {
        return traced(interp, conf).unwrap_or_else(|| conf.clone());
    };
    let path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let reported = located(interp, conf, &path, true);
    if debug() == "trace" {
        // How the read trace would have located it, for comparing the
        // heuristic against checks that say.
        let attribute = |v: &Value| {
            v.prov
                .last()
                .and_then(|s| s.attribute.as_deref().map(str::to_string))
        };
        eprintln!(
            "checkov_python trace {}: reported={:?} traced={:?}",
            program.entry,
            attribute(&reported),
            traced(interp, conf).as_ref().and_then(attribute)
        );
    }
    reported
}

/// The witness a failing run's lookups imply: what the native check it
/// delegated to located, else the last configuration key it read, found
/// or not ([`located`]).
fn traced(interp: &Interp, conf: &Value) -> Option<Value> {
    if let Some(w) = interp.delegated.borrow().clone() {
        return Some(w);
    }
    let reads = interp.reads.borrow();
    // `__address__` and the like are the runner's, not configuration.
    let read = reads.iter().rev().find(|r| !r.key.starts_with("__"))?;
    let mut path: Vec<&str> = read.dict.iter().map(|s| &**s).collect();
    path.push(&read.key);
    Some(located(interp, conf, &path, read.present))
}

/// The witness for the configuration at `path`, so the finding names the
/// attribute: its configured value where that carries the attribute's
/// provenance; the value with a step naming the attribute at the resource
/// header where it does not (a rendered view); its absence when it is not
/// set (or `present` says the check did not find it).
fn located(interp: &Interp, conf: &Value, path: &[&str], present: bool) -> Value {
    let resource = interp.resource;
    // Indices are not part of an attribute path; Checkov spells them
    // `[0]` or `0`.
    let dotted: Vec<&str> = path
        .iter()
        .copied()
        .filter(|s| !s.starts_with('[') && s.parse::<usize>().is_err())
        .collect();
    let dotted = dotted.join(".");
    let owned = |v: &Value| {
        v.prov
            .any(|s| s.resource.as_deref() == Some(&*resource.base_address))
    };
    match value_at(conf, path).filter(|_| present) {
        Some(v) if owned(&v) => v,
        Some(v) => match &v.kind {
            // Attributes are wrapped in a one-element list.
            Kind::Known(Known::List(items)) if items.len() == 1 && owned(&items[0]) => {
                items[0].clone()
            }
            _ => resource.mentioned(&dotted, v),
        },
        None => resource.absent(&dotted),
    }
}

/// The value at a configuration path (keys and `[i]` elements). A key
/// read through an attribute's one-element list reads its element, as
/// Checkov's `evaluated_keys` sometimes omit the `[0]`.
fn value_at(conf: &Value, path: &[&str]) -> Option<Value> {
    let mut cur = conf.clone();
    for seg in path {
        let index = seg
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .or_else(|| seg.parse::<usize>().is_ok().then_some(*seg));
        let next = match (&cur.kind, index) {
            (Kind::Known(Known::List(items)), Some(i)) => {
                items.get(i.parse::<usize>().ok()?).cloned()
            }
            (Kind::Known(Known::Object(m)), None) => m.get(*seg).cloned(),
            (Kind::Known(Known::List(items)), None) if items.len() == 1 => match &items[0].kind {
                Kind::Known(Known::Object(m)) => m.get(*seg).cloned(),
                _ => None,
            },
            _ => None,
        }?;
        cur = next;
    }
    Some(cur)
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Program>();
    check::<Arc<Program>>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_characters_not_bytes() {
        assert!(glob("?", "é"));
        assert!(glob("s3:get*", "s3:getobject"));
        assert!(!glob("s3:get?", "s3:getobject"));
        assert!(glob("a*b*", "ab"));
        assert!(!glob("a", ""));
        assert!(glob("*", ""));
    }

    #[test]
    fn sort_fallible_is_stable_and_surfaces_the_first_error() {
        fn sorted<T: Ord + Clone>(items: &[(T, char)], reverse: bool) -> Vec<(T, char)> {
            sort_fallible(items.to_vec(), |a, b| {
                let o = a.0.cmp(&b.0);
                Ok(if reverse { o.reverse() } else { o })
            })
            .unwrap_or_else(|_| panic!("comparison failed"))
        }
        // Stable: equal keys keep their order, forwards and reversed.
        let items = [(2, 'a'), (1, 'b'), (2, 'c'), (1, 'd'), (0, 'e')];
        assert_eq!(
            sorted(&items, false),
            [(0, 'e'), (1, 'b'), (1, 'd'), (2, 'a'), (2, 'c')]
        );
        assert_eq!(
            sorted(&items, true),
            [(2, 'a'), (2, 'c'), (1, 'b'), (1, 'd'), (0, 'e')]
        );
        // Degenerate sizes.
        assert_eq!(sorted(&[] as &[(i32, char)], false), []);
        assert_eq!(sorted(&[(7, 'x')], false), [(7, 'x')]);
        // A failing comparison fails the sort (no panic, no partial order).
        let mixed = vec![Py::Int(1), Py::None, Py::Int(0)];
        let err = sort_fallible(mixed, |a, b| match (a, b) {
            (Py::Int(x), Py::Int(y)) => Ok(x.cmp(y)),
            _ => exc("TypeError"),
        });
        assert!(matches!(err, Err(Flow::Exc(name)) if &*name == "TypeError"));
    }
}
