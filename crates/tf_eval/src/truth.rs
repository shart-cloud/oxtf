//! Four-valued predicate results over abstract values, for rules.
//!
//! `Truth` is totally ordered `False < Unknown < Tainted < True`, so
//! `and = min` and `or = max`:
//!
//! - `True`: holds for the configuration as written → *definite* finding.
//! - `Tainted`: holds for some value of an unconstrained input → *conditional*.
//! - `Unknown`: depends on something only known at apply time (computed
//!   attribute, remote module, unsupported function) → no finding.
//! - `False`: does not hold.
//!
//! `and(Tainted, Unknown) = Unknown`: when part of the condition depends on
//! apply-time data, we do not report. `or(Tainted, Unknown) = Tainted`.
//!
//! On a `OneOf`, a predicate is `True` if it holds for every alternative. If
//! it holds for some alternatives, the result is `Tainted` when the
//! ambiguity is tainted (the OneOf's `tainted` flag, or a Tainted
//! alternative) and `Unknown` otherwise.

use crate::value::{Kind, Known, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Truth {
    False,
    Unknown,
    Tainted,
    True,
}

impl Truth {
    pub fn from_bool(b: bool) -> Truth {
        if b { Truth::True } else { Truth::False }
    }
    #[must_use]
    pub fn and(self, o: Truth) -> Truth {
        self.min(o)
    }
    #[must_use]
    pub fn or(self, o: Truth) -> Truth {
        self.max(o)
    }
    #[must_use]
    pub fn negate(self) -> Truth {
        match self {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            x => x,
        }
    }
}

/// A truth value plus the value that decided it (with its full provenance
/// chain), for reporting.
#[derive(Clone, Debug)]
pub struct Verdict {
    pub truth: Truth,
    pub witness: Option<Value>,
}

impl Verdict {
    pub const FALSE: Verdict = Verdict {
        truth: Truth::False,
        witness: None,
    };

    pub fn new(truth: Truth, witness: Option<Value>) -> Self {
        Verdict { truth, witness }
    }

    /// Conjunction; the witness comes from the deciding (weakest) side, but
    /// when both sides hold, the left witness is kept.
    #[must_use]
    pub fn and(self, o: Verdict) -> Verdict {
        if o.truth < self.truth { o } else { self }
    }

    /// Disjunction; the witness of the strongest side.
    #[must_use]
    pub fn or(self, o: Verdict) -> Verdict {
        if o.truth > self.truth { o } else { self }
    }

    pub fn holds(&self) -> bool {
        matches!(self.truth, Truth::True | Truth::Tainted)
    }
}

/// Evaluate a predicate on a scalar abstract value. `pred` is only called
/// on Known values.
pub fn test(v: &Value, pred: &dyn Fn(&Value) -> bool) -> Verdict {
    test_with(v, &|x| Truth::from_bool(pred(x)))
}

pub fn test_with(v: &Value, pred: &dyn Fn(&Value) -> Truth) -> Verdict {
    match &v.kind {
        Kind::Known(_) => Verdict::new(pred(v), Some(v.clone())),
        Kind::Tainted(_) => Verdict::new(Truth::Tainted, Some(v.clone())),
        Kind::Unknown(_) => Verdict::new(Truth::Unknown, Some(v.clone())),
        Kind::OneOf(o) => {
            let vs: Vec<Verdict> = o
                .alternatives
                .iter()
                .map(|a| test_with(&a.child_of(v), pred))
                .collect();
            combine_one_of(vs, o.tainted)
        }
    }
}

/// Apply a Verdict-valued function to a value, lifting over `OneOf`
/// (alternatives combined as in [`test`]) and mapping Tainted / Unknown to
/// themselves. `f` sees Known values (including null).
pub fn map(v: &Value, f: &dyn Fn(&Value) -> Verdict) -> Verdict {
    match &v.kind {
        Kind::Known(_) => f(v),
        Kind::Tainted(_) => Verdict::new(Truth::Tainted, Some(v.clone())),
        Kind::Unknown(_) => Verdict::new(Truth::Unknown, Some(v.clone())),
        Kind::OneOf(o) => {
            let vs: Vec<Verdict> = o
                .alternatives
                .iter()
                .map(|a| map(&a.child_of(v), f))
                .collect();
            combine_one_of(vs, o.tainted)
        }
    }
}

/// "Some element of the list `v` satisfies `pred`" (`pred` sees each element,
/// which may itself be abstract; use [`test`] inside it for scalars).
pub fn exists(v: &Value, pred: &dyn Fn(&Value) -> Verdict) -> Verdict {
    match &v.kind {
        Kind::Known(Known::List(l)) => {
            let mut acc = Verdict::FALSE;
            for e in l.iter() {
                acc = acc.or(pred(&e.child_of(v)));
                if acc.truth == Truth::True {
                    break;
                }
            }
            acc
        }
        Kind::Known(Known::Null) => Verdict::FALSE,
        Kind::Known(_) => pred(v),
        Kind::Tainted(_) => Verdict::new(Truth::Tainted, Some(v.clone())),
        Kind::Unknown(_) => Verdict::new(Truth::Unknown, Some(v.clone())),
        Kind::OneOf(o) => {
            let vs: Vec<Verdict> = o
                .alternatives
                .iter()
                .map(|a| exists(&a.child_of(v), pred))
                .collect();
            combine_one_of(vs, o.tainted)
        }
    }
}

fn combine_one_of(vs: Vec<Verdict>, tainted: bool) -> Verdict {
    let tainted = tainted || vs.iter().any(|x| x.truth == Truth::Tainted);
    if !vs.is_empty() && vs.iter().all(|x| x.truth == Truth::True) {
        return vs.into_iter().next().unwrap();
    }
    let best = vs
        .into_iter()
        .max_by_key(|x| x.truth)
        .unwrap_or(Verdict::FALSE);
    match best.truth {
        Truth::True | Truth::Tainted => Verdict::new(
            if tainted {
                Truth::Tainted
            } else {
                Truth::Unknown
            },
            best.witness,
        ),
        _ => best,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lattice() {
        use Truth::*;
        assert_eq!(Tainted.and(Unknown), Unknown);
        assert_eq!(Tainted.or(Unknown), Tainted);
        assert_eq!(True.and(Tainted), Tainted);
        let v = Value::list(vec![Value::string("10.0.0.0/8"), Value::tainted("x")]);
        let r = exists(&v, &|e| test(e, &|x| x.as_str() == Some("0.0.0.0/0")));
        assert_eq!(r.truth, Tainted);
        let o = Value::one_of(
            vec![Value::string("0.0.0.0/0"), Value::string("10.0.0.0/8")],
            false,
        );
        assert_eq!(
            test(&o, &|x| x.as_str() == Some("0.0.0.0/0")).truth,
            Unknown
        );
        let o = Value::one_of(
            vec![Value::string("0.0.0.0/0"), Value::string("10.0.0.0/8")],
            true,
        );
        assert_eq!(
            test(&o, &|x| x.as_str() == Some("0.0.0.0/0")).truth,
            Tainted
        );
    }
}
