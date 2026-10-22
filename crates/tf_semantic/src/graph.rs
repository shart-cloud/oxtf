//! Resource dependency graph over an entire analysed root, including children.
//! Edges come from evaluated traversals, never equal literals or explanation
//! spans. Instance keys and uncertain expansion remain part of the edge.
use crate::{Analysis, Body, Resource};
use std::collections::{HashMap, hash_map::Entry};
use tf_eval::{Kind, Known, Truth, Value, prov::ResourceDependency};
use tf_limits::{Exhaustion, Limits, WorkBudget, input::InputBudget};

pub fn value_dependencies(value: &Value, out: &mut Vec<ResourceDependency>) {
    out.extend(value.prov.dependencies().iter().cloned());
    // Container constructors aggregate dependencies. A direct traversal can
    // replace that aggregate, preventing accidental transitive resource edges.
    if !value.prov.dependencies().is_empty() {
        return;
    }
    match &value.kind {
        Kind::Known(Known::List(v)) => {
            for x in v.iter() {
                value_dependencies(x, out);
            }
        }
        Kind::Known(Known::Object(v)) => {
            for x in v.values() {
                value_dependencies(x, out);
            }
        }
        Kind::Known(Known::Json(v)) => value_dependencies(v, out),
        Kind::OneOf(v) => {
            for x in &v.alternatives {
                value_dependencies(x, out);
            }
        }
        _ => {}
    }
}

pub fn body_dependencies(body: &Body, out: &mut Vec<ResourceDependency>) {
    for a in &body.attrs {
        value_dependencies(&a.value, out);
    }
    for b in &body.blocks {
        let start = out.len();
        body_dependencies(&b.body, out);
        for dependency in &mut out[start..] {
            dependency.certainty = dependency.certainty.and(b.existence);
        }
    }
}

pub struct ResourceGraph<'a> {
    pub resources: Vec<&'a Resource>,
    /// Undirected adjacency: Checkov connections accept references either way.
    pub neighbours: Vec<Vec<(usize, Truth)>>,
}

/// One logical adjacency entry; sorted neighbour vectors hold the same pairs.
const EDGE_BYTES: u64 = size_of::<(usize, Truth)>() as u64;

impl<'a> ResourceGraph<'a> {
    /// Standalone construction with default allowances.
    pub fn new(analysis: &'a Analysis) -> Result<Self, Exhaustion> {
        let limits = Limits::default();
        let work = WorkBudget::for_resource(limits, tf_limits::Resource::RuleSteps);
        Self::with_budget(analysis, &work, &InputBudget::new(limits))
    }

    /// Instances of one base address make edge count quadratic in resources:
    /// every candidate pair charges `work` and every new edge admits storage.
    pub fn with_budget(
        analysis: &'a Analysis,
        work: &WorkBudget,
        storage: &InputBudget,
    ) -> Result<Self, Exhaustion> {
        let resources: Vec<_> = analysis
            .modules
            .iter()
            .flat_map(|m| &m.resources)
            .filter(|r| r.existence != Truth::False)
            .collect();
        work.charge(resources.len() as u64)?;
        let mut by_base: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, r) in resources.iter().enumerate() {
            by_base.entry(&r.base_address).or_default().push(i);
        }
        let mut adjacency: Vec<HashMap<usize, Truth>> = vec![HashMap::new(); resources.len()];
        let mut edges: u64 = 0;
        for (i, r) in resources.iter().enumerate() {
            let mut dependencies = r.dependencies.clone();
            body_dependencies(&r.body, &mut dependencies);
            for value in r.count.iter().chain(r.for_each.iter()) {
                value_dependencies(value, &mut dependencies);
            }
            work.charge(dependencies.len() as u64)?;
            for d in dependencies {
                for &j in by_base.get(d.resource.as_ref()).into_iter().flatten() {
                    work.charge(1)?;
                    if let Some(certainty) = edge_certainty(r, resources[j], &d, i == j) {
                        edges += connect(&mut adjacency, i, j, certainty, storage)?;
                    }
                }
            }
        }
        let neighbours = sorted(adjacency, edges, storage)?;
        Ok(Self {
            resources,
            neighbours,
        })
    }
}

/// `None` when the dependency cannot name `target`.
fn edge_certainty(
    source: &Resource,
    target: &Resource,
    d: &ResourceDependency,
    same: bool,
) -> Option<Truth> {
    let aggregate = target.key.is_none() && (target.count.is_some() || target.for_each.is_some());
    if same || (d.key.is_some() && d.key != target.key && !aggregate) {
        return None;
    }
    let certainty = if (d.key.is_some() && aggregate)
        || (d.key.is_none() && target.key.is_some() && d.certainty == Truth::True)
    {
        Truth::Unknown
    } else {
        d.certainty
    };
    Some(certainty.and(source.existence).and(target.existence))
}

/// Both directions; returns the number of new logical entries admitted.
fn connect(
    adjacency: &mut [HashMap<usize, Truth>],
    i: usize,
    j: usize,
    certainty: Truth,
    storage: &InputBudget,
) -> Result<u64, Exhaustion> {
    assert!(i != j);
    let mut added = 0;
    for (a, b) in [(i, j), (j, i)] {
        match adjacency[a].entry(b) {
            Entry::Occupied(mut edge) => {
                let merged = edge.get().or(certainty);
                edge.insert(merged);
            }
            Entry::Vacant(edge) => {
                storage.admit_collection(EDGE_BYTES)?;
                edge.insert(certainty);
                added += 1;
            }
        }
    }
    assert!(adjacency[i].contains_key(&j) && adjacency[j].contains_key(&i));
    Ok(added)
}

/// The sorted copy coexists with unconverted maps, so it is admitted again.
fn sorted(
    adjacency: Vec<HashMap<usize, Truth>>,
    edges: u64,
    storage: &InputBudget,
) -> Result<Vec<Vec<(usize, Truth)>>, Exhaustion> {
    let bytes = edges
        .checked_mul(EDGE_BYTES)
        .ok_or_else(|| storage.collection_refused())?;
    storage.admit_collection(bytes)?;
    let neighbours: Vec<Vec<(usize, Truth)>> = adjacency
        .into_iter()
        .map(|m| {
            let mut edges: Vec<_> = m.into_iter().collect();
            edges.sort_by_key(|e| e.0);
            edges
        })
        .collect();
    assert_eq!(neighbours.iter().map(Vec::len).sum::<usize>() as u64, edges);
    Ok(neighbours)
}
