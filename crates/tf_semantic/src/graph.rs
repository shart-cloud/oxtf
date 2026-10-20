//! Resource dependency graph over an entire analysed root, including children.
//! Edges come from evaluated traversals, never equal literals or explanation
//! spans. Instance keys and uncertain expansion remain part of the edge.
use crate::{Analysis, Body, Resource};
use std::collections::HashMap;
use tf_eval::{Kind, Known, Truth, Value, prov::ResourceDependency};

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

impl<'a> ResourceGraph<'a> {
    pub fn new(analysis: &'a Analysis) -> Self {
        let resources: Vec<_> = analysis
            .modules
            .iter()
            .flat_map(|m| &m.resources)
            .filter(|r| r.existence != Truth::False)
            .collect();
        let mut by_base: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, r) in resources.iter().enumerate() {
            by_base.entry(&r.base_address).or_default().push(i);
        }
        let mut adjacency: Vec<HashMap<usize, Truth>> = vec![HashMap::new(); resources.len()];
        for (i, r) in resources.iter().enumerate() {
            let mut dependencies = r.dependencies.clone();
            body_dependencies(&r.body, &mut dependencies);
            for value in r.count.iter().chain(r.for_each.iter()) {
                value_dependencies(value, &mut dependencies);
            }
            for d in dependencies {
                for &j in by_base.get(d.resource.as_ref()).into_iter().flatten() {
                    let target = resources[j];
                    let aggregate = target.key.is_none()
                        && (target.count.is_some() || target.for_each.is_some());
                    if i == j || (d.key.is_some() && d.key != target.key && !aggregate) {
                        continue;
                    }
                    let certainty = if (d.key.is_some() && aggregate)
                        || (d.key.is_none() && target.key.is_some() && d.certainty == Truth::True)
                    {
                        Truth::Unknown
                    } else {
                        d.certainty
                    }
                    .and(r.existence)
                    .and(target.existence);
                    for (a, b) in [(i, j), (j, i)] {
                        adjacency[a]
                            .entry(b)
                            .and_modify(|v| *v = v.or(certainty))
                            .or_insert(certainty);
                    }
                }
            }
        }
        let neighbours = adjacency
            .into_iter()
            .map(|m| {
                let mut edges: Vec<_> = m.into_iter().collect();
                edges.sort_by_key(|e| e.0);
                edges
            })
            .collect();
        Self {
            resources,
            neighbours,
        }
    }
}
