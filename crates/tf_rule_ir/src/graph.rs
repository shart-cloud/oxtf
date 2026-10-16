//! Checkov graph solver trees over the native resource dependency graph.
use crate::checkov::{AttributeCheck, AttributeFilter};
use crate::jsonpath::JsonPathCheck;
use serde::{Deserialize, Serialize};
use tf_eval::{Truth, Verdict};
use tf_semantic::graph::ResourceGraph;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphExpr {
    Attribute {
        resource_types: Vec<String>,
        check: AttributeCheck,
    },
    Jsonpath {
        resource_types: Vec<String>,
        check: JsonPathCheck,
    },
    Connection {
        resource_types: Vec<String>,
        connected_resource_types: Vec<String>,
        operator: ConnectionOp,
    },
    Filter {
        resource_types: Vec<String>,
        #[serde(default)]
        exclude: bool,
    },
    AttributeFilter {
        check: AttributeFilter,
    },
    And {
        args: Vec<GraphExpr>,
    },
    Or {
        args: Vec<GraphExpr>,
    },
    Not {
        arg: Box<GraphExpr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOp {
    Exists,
    NotExists,
    OneExists,
}

type Results = Vec<Option<Verdict>>;
fn combine(left: Verdict, right: Verdict, and: bool) -> Verdict {
    if left.truth == right.truth && left.witness.is_none() {
        return right;
    }
    if and { left.and(right) } else { left.or(right) }
}
pub(crate) fn matches(types: &[String], r: &tf_semantic::Resource) -> bool {
    types.iter().any(|t| {
        t == "*"
            || if r.mode == tf_semantic::Mode::Data {
                t.strip_prefix("data.") == Some(r.ty.as_ref())
            } else {
                t == r.ty.as_ref()
            }
    })
}

impl GraphExpr {
    pub fn validate(&self) -> Result<(), String> {
        fn types(ts: &[String]) -> Result<(), String> {
            if ts.is_empty()
                || ts
                    .iter()
                    .any(|t| t.is_empty() || (t != "*" && t.contains(['*', '?', '['])))
            {
                Err("graph resource_types must contain literal types or '*'".into())
            } else {
                Ok(())
            }
        }
        match self {
            Self::Attribute {
                resource_types,
                check,
            } => {
                types(resource_types)?;
                check.validate()
            }
            Self::Connection {
                resource_types,
                connected_resource_types,
                ..
            } => {
                types(resource_types)?;
                types(connected_resource_types)
            }
            Self::Jsonpath {
                resource_types,
                check,
            } => {
                types(resource_types)?;
                check.validate()
            }
            Self::Filter { resource_types, .. } => types(resource_types),
            Self::AttributeFilter { check } => check.validate(),
            Self::And { args } | Self::Or { args } => {
                if args.is_empty() {
                    return Err("graph boolean expression must not be empty".into());
                }
                if args.iter().all(Self::is_filter) {
                    return Err("graph filters require a predicate".into());
                }
                if args
                    .iter()
                    .any(|a| matches!(a, Self::AttributeFilter { .. }))
                    && !self.connection_tree()
                {
                    return Err("graph attribute filters require a connection expression".into());
                }
                for a in args {
                    a.validate()?;
                }
                Ok(())
            }
            Self::Not { arg } => {
                if arg.is_filter() {
                    return Err("cannot negate a graph filter".into());
                }
                arg.validate()
            }
        }
    }

    pub fn is_filter(&self) -> bool {
        matches!(self, Self::Filter { .. } | Self::AttributeFilter { .. })
    }

    pub fn connection_tree(&self) -> bool {
        match self {
            Self::Connection { .. } => true,
            Self::And { args } | Self::Or { args } => args.iter().any(Self::connection_tree),
            Self::Not { arg } => arg.connection_tree(),
            _ => false,
        }
    }

    pub fn targets(&self, resource: &tf_semantic::Resource) -> bool {
        match self {
            Self::Attribute { resource_types, .. } | Self::Jsonpath { resource_types, .. } => {
                matches(resource_types, resource)
            }
            Self::Connection {
                resource_types,
                connected_resource_types,
                ..
            } => matches(resource_types, resource) || matches(connected_resource_types, resource),
            Self::And { args } | Self::Or { args } => args.iter().any(|a| a.targets(resource)),
            Self::Not { arg } => arg.targets(resource),
            Self::Filter { .. } | Self::AttributeFilter { .. } => false,
        }
    }

    pub fn evaluate(&self, graph: &ResourceGraph<'_>) -> Results {
        if self.vertex_predicate() {
            return graph
                .resources
                .iter()
                .map(|r| self.targets(r).then(|| self.attribute_predicate(r)))
                .collect();
        }
        self.solve(graph, &vec![None; graph.resources.len()])
    }

    fn vertex_predicate(&self) -> bool {
        match self {
            Self::Attribute { .. } | Self::Jsonpath { .. } => true,
            Self::And { args } | Self::Or { args } => args.iter().all(Self::vertex_predicate),
            Self::Not { arg } => arg.vertex_predicate(),
            Self::Connection { .. } | Self::Filter { .. } | Self::AttributeFilter { .. } => false,
        }
    }

    /// Attribute-only boolean solvers evaluate every child on the same vertex;
    /// a different resource type is false, rather than a missing set member.
    fn attribute_predicate(&self, r: &tf_semantic::Resource) -> Verdict {
        match self {
            Self::Jsonpath {
                resource_types,
                check,
            } => {
                if matches(resource_types, r) {
                    check.evaluate(r)
                } else {
                    Verdict::FALSE
                }
            }
            Self::Attribute {
                resource_types,
                check,
            } => {
                if matches(resource_types, r) {
                    check.evaluate(r)
                } else {
                    Verdict::FALSE
                }
            }
            Self::Not { arg } => arg.attribute_predicate(r).negate(),
            Self::And { args } | Self::Or { args } => {
                let and = matches!(self, Self::And { .. });
                args.iter()
                    .map(|a| a.attribute_predicate(r))
                    .reduce(|a, b| combine(a, b, and))
                    .expect("validated nonempty boolean")
            }
            Self::Filter {
                resource_types,
                exclude,
            } => Verdict::new(
                Truth::from_bool(matches(resource_types, r) != *exclude),
                None,
            ),
            Self::AttributeFilter { check } => check.evaluate(r),
            Self::Connection { .. } => unreachable!("attribute-only tree"),
        }
    }

    fn solve(&self, graph: &ResourceGraph<'_>, prior: &Results) -> Results {
        let empty = || vec![None; graph.resources.len()];
        match self {
            Self::Jsonpath {
                resource_types,
                check,
            } => graph
                .resources
                .iter()
                .map(|r| matches(resource_types, r).then(|| check.evaluate(r)))
                .collect(),
            Self::Attribute {
                resource_types,
                check,
            } => graph
                .resources
                .iter()
                .map(|r| matches(resource_types, r).then(|| check.evaluate(r)))
                .collect(),
            Self::Filter { .. } | Self::AttributeFilter { .. } => empty(),
            Self::Not { arg } => arg
                .evaluate(graph)
                .into_iter()
                .map(|v| v.map(|v| v.negate()))
                .collect(),
            Self::Connection {
                resource_types: left,
                connected_resource_types: right,
                operator,
            } => graph
                .resources
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let (l, rr) = (matches(left, r), matches(right, r));
                    if !l && !rr {
                        return None;
                    }
                    let mut exists = Verdict::FALSE;
                    let mut all = Verdict::new(Truth::True, None);
                    for &(j, certainty) in &graph.neighbours[i] {
                        let t = graph.resources[j];
                        if !(l && matches(right, t) || rr && matches(left, t)) {
                            continue;
                        }
                        let edge = Verdict::new(certainty, None);
                        let gate = prior[i]
                            .clone()
                            .unwrap_or(Verdict::new(Truth::True, None))
                            .and(prior[j].clone().unwrap_or(Verdict::new(Truth::True, None)));
                        exists = combine(exists, combine(edge.clone(), gate.clone(), true), false);
                        all = combine(all, combine(edge.negate(), gate, false), true);
                    }
                    let result = if *operator == ConnectionOp::OneExists {
                        exists
                    } else {
                        all.and(exists)
                    };
                    Some(if *operator == ConnectionOp::NotExists {
                        result.negate()
                    } else {
                        result
                    })
                })
                .collect(),
            Self::And { args } | Self::Or { args } => {
                let and = matches!(self, Self::And { .. });
                let mut result = empty();
                let mut ordered: Vec<_> = args.iter().filter(|a| !a.is_filter()).collect();
                // Attributes exclude endpoints before joins. Connections involving
                // the result filter run last, as in the pinned Checkov solver.
                if and {
                    let filtered: Vec<_> = args
                        .iter()
                        .filter_map(|a| match a {
                            Self::Filter { resource_types, .. } => Some(resource_types),
                            _ => None,
                        })
                        .flatten()
                        .collect();
                    ordered.sort_by_key(|a| match a {
                        Self::Connection {
                            resource_types,
                            connected_resource_types,
                            ..
                        } => {
                            1 + usize::from(
                                resource_types
                                    .iter()
                                    .chain(connected_resource_types)
                                    .any(|t| filtered.contains(&t)),
                            )
                        }
                        _ if a.connection_tree() => 1,
                        _ => 0,
                    });
                }
                for arg in ordered {
                    let next = if and && matches!(arg, Self::Connection { .. }) {
                        arg.solve(graph, &result)
                    } else {
                        arg.evaluate(graph)
                    };
                    for (out, value) in result.iter_mut().zip(next) {
                        if let Some(value) = value {
                            *out = Some(match out.take() {
                                Some(old) => combine(old, value, and),
                                None => value,
                            });
                        }
                    }
                }
                for arg in args.iter().filter(|a| a.is_filter()) {
                    for (i, r) in graph.resources.iter().enumerate() {
                        if let Some(pass) = result[i].take() {
                            let eligible = arg.attribute_predicate(r);
                            result[i] = match eligible.truth {
                                Truth::False => None,
                                Truth::True => Some(pass),
                                // A violation requires both eligibility and
                                // failure. Preserve the deciding filter evidence.
                                _ => Some(combine(pass, eligible.negate(), false)),
                            };
                        }
                    }
                }
                result
            }
        }
    }
}
