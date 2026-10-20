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
    /// Position in the order `False < Unknown < Tainted < True`, for
    /// adapters that carry a truth value through a foreign engine.
    pub fn rank(self) -> u8 {
        match self {
            Truth::False => 0,
            Truth::Unknown => 1,
            Truth::Tainted => 2,
            Truth::True => 3,
        }
    }
    pub fn from_rank(rank: u8) -> Option<Truth> {
        Some(match rank {
            0 => Truth::False,
            1 => Truth::Unknown,
            2 => Truth::Tainted,
            3 => Truth::True,
            _ => return None,
        })
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

    /// Negation; the witness is kept (it still decided the result).
    #[must_use]
    pub fn negate(self) -> Verdict {
        Verdict::new(self.truth.negate(), self.witness)
    }
}

/// How an abstract value is uncertain: `True` for a Known value, `Tainted`
/// when the uncertainty traces to an unconstrained input (a Tainted value,
/// or a `OneOf` whose choice or some alternative is tainted), `Unknown`
/// otherwise. This is the one rule for classifying an abstract value, used
/// for resource existence (`count` / `for_each`) and by adapters.
pub fn uncertainty(v: &Value) -> Truth {
    match &v.kind {
        Kind::Known(_) => Truth::True,
        Kind::Tainted(_) => Truth::Tainted,
        Kind::Unknown(_) => Truth::Unknown,
        Kind::OneOf(o) => {
            if o.tainted
                || o.alternatives
                    .iter()
                    .any(|a| uncertainty(a) == Truth::Tainted)
            {
                Truth::Tainted
            } else {
                Truth::Unknown
            }
        }
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
    match try_map(v, &|v| Ok::<_, std::convert::Infallible>(f(v))) {
        Ok(v) => v,
        Err(never) => match never {},
    }
}

/// Fallible [`map`]. An evaluator failure is not an abstract truth value,
/// and must survive lifting over alternatives.
pub fn try_map<E>(v: &Value, f: &dyn Fn(&Value) -> Result<Verdict, E>) -> Result<Verdict, E> {
    Ok(match &v.kind {
        Kind::Known(_) => f(v)?,
        Kind::Tainted(_) => Verdict::new(Truth::Tainted, Some(v.clone())),
        Kind::Unknown(_) => Verdict::new(Truth::Unknown, Some(v.clone())),
        Kind::OneOf(o) => {
            let vs: Vec<Verdict> = o
                .alternatives
                .iter()
                .map(|a| try_map(&a.child_of(v), f))
                .collect::<Result<_, _>>()?;
            combine_one_of(vs, o.tainted)
        }
    })
}

/// "Some element of the list `v` satisfies `pred`" (`pred` sees each element,
/// which may itself be abstract; use [`test`] inside it for scalars).
pub fn exists(v: &Value, pred: &dyn Fn(&Value) -> Verdict) -> Verdict {
    match try_exists(v, &|v| Ok::<_, std::convert::Infallible>(pred(v))) {
        Ok(v) => v,
        Err(never) => match never {},
    }
}

/// Fallible [`exists`], with the same short-circuiting and uncertainty
/// semantics, but without turning evaluation failures into Unknown.
pub fn try_exists<E>(v: &Value, pred: &dyn Fn(&Value) -> Result<Verdict, E>) -> Result<Verdict, E> {
    Ok(match &v.kind {
        Kind::Known(Known::List(l)) => {
            let mut acc = Verdict::FALSE;
            for e in l.iter() {
                acc = acc.or(pred(&e.child_of(v))?);
                if acc.truth == Truth::True {
                    break;
                }
            }
            acc
        }
        Kind::Known(Known::Null) => Verdict::FALSE,
        Kind::Known(_) => pred(v)?,
        Kind::Tainted(_) => Verdict::new(Truth::Tainted, Some(v.clone())),
        Kind::Unknown(_) => Verdict::new(Truth::Unknown, Some(v.clone())),
        Kind::OneOf(o) => {
            let vs: Vec<Verdict> = o
                .alternatives
                .iter()
                .map(|a| try_exists(&a.child_of(v), pred))
                .collect::<Result<_, _>>()?;
            combine_one_of(vs, o.tainted)
        }
    })
}

/// "Every element of the list `v` satisfies `pred`"; the dual of [`exists`].
pub fn forall(v: &Value, pred: &dyn Fn(&Value) -> Verdict) -> Verdict {
    exists(v, &|e| pred(e).negate()).negate()
}

/// Combine the verdicts of a `OneOf`'s alternatives. `True` when every
/// alternative holds (the first one's witness); otherwise the strongest
/// alternative's witness with `Tainted` when the ambiguity is tainted (the
/// OneOf's flag or a Tainted alternative) and `Unknown` otherwise.
pub fn combine_one_of(vs: Vec<Verdict>, tainted: bool) -> Verdict {
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
    fn uncertainty_follows_the_one_of_rule() {
        use Truth::*;
        assert_eq!(uncertainty(&Value::bool(true)), True);
        assert_eq!(uncertainty(&Value::tainted("x")), Tainted);
        assert_eq!(uncertainty(&Value::other("computed")), Unknown);
        let alts = || vec![Value::number(1.0), Value::number(0.0)];
        assert_eq!(uncertainty(&Value::one_of(alts(), false)), Unknown);
        assert_eq!(uncertainty(&Value::one_of(alts(), true)), Tainted);
        // A Tainted alternative taints the choice even when the flag is off,
        // exactly as combine_one_of treats a Tainted alternative verdict.
        let mixed = Value::one_of(vec![Value::tainted("n"), Value::number(0.0)], false);
        assert_eq!(uncertainty(&mixed), Tainted);
        assert_eq!(
            test(&mixed, &|x| x.as_number().is_some_and(|n| n >= 1.0)).truth,
            Tainted
        );
    }

    #[test]
    fn forall_negate_and_ranks() {
        let all = Value::list(vec![Value::number(1.0), Value::number(2.0)]);
        let pos = |e: &Value| test(e, &|x| x.as_number().is_some_and(|n| n > 0.0));
        assert_eq!(forall(&all, &pos).truth, Truth::True);
        let some = Value::list(vec![Value::number(1.0), Value::number(-2.0)]);
        let v = forall(&some, &pos);
        assert_eq!(v.truth, Truth::False);
        assert_eq!(v.witness.and_then(|w| w.as_number()), Some(-2.0));
        let open = Value::list(vec![Value::number(1.0), Value::tainted("t")]);
        assert_eq!(forall(&open, &pos).truth, Truth::Tainted);
        assert_eq!(
            Verdict::new(Truth::Unknown, None).negate().truth,
            Truth::Unknown
        );
        for t in [Truth::False, Truth::Unknown, Truth::Tainted, Truth::True] {
            assert_eq!(Truth::from_rank(t.rank()), Some(t));
        }
        assert_eq!(Truth::from_rank(4), None);
    }

    #[test]
    fn field_or_null_is_lenient_and_lifts() {
        let obj = Value::object([("a".into(), Value::bool(true))].into());
        assert_eq!(obj.field_or_null("a").as_bool(), Some(true));
        assert!(obj.field_or_null("b").is_null());
        assert!(Value::null().field_or_null("a").is_null());
        assert!(Value::tainted("t").field_or_null("a").is_tainted());
        let o = Value::one_of(vec![obj, Value::null()], true);
        match &o.field_or_null("a").kind {
            Kind::OneOf(x) => assert!(x.tainted && x.alternatives.len() == 2),
            k => panic!("{k:?}"),
        }
    }

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
