use super::*;
use crate::text::Text;
use tf_ast::{Template, TemplateElement};

impl<'r, 'a> Evaluator<'r, 'a> {
    pub fn eval_template(&self, t: &'a Template<'a>, sc: Scope<'_>) -> Value {
        let guard = match self.enter(t.span, 1) {
            Ok(guard) => guard,
            Err(limit) => return limit,
        };
        self.finish(&guard, self.eval_template_inner(t, sc), t.span)
    }

    fn eval_template_inner(&self, t: &'a Template<'a>, sc: Scope<'_>) -> Value {
        // A template that is a single interpolation yields the value itself
        // (type preserved), as in Terraform.
        if t.elements.len() == 1
            && let TemplateElement::Interpolation(i) = &t.elements[0]
        {
            return self.eval(&i.expression, sc);
        }
        let mut parts = Buffer::new(self.budget.storage());
        if let Err(v) = self.template_parts(t, sc, false, false, &mut parts) {
            return failure(v, parts.iter().filter_map(Part::value));
        }
        concat_parts(&parts, self.budget.storage())
    }

    fn template_parts(
        &self,
        t: &'a Template<'a>,
        sc: Scope<'_>,
        lead: bool,
        trail: bool,
        out: &mut Buffer<'_, Part<'a>>,
    ) -> Result<(), Value> {
        let _guard = self.enter(t.span, 1 + t.elements.len() as u64)?;
        let els = &t.elements;
        let n = els.len();
        for (i, el) in els.iter().enumerate() {
            match el {
                TemplateElement::Literal(l) => {
                    let mut s: &str = &l.value;
                    if (i == 0 && lead) || (i > 0 && strip(&els[i - 1]).1) {
                        s = s.trim_start();
                    }
                    if (i + 1 == n && trail) || (i + 1 < n && strip(&els[i + 1]).0) {
                        s = s.trim_end();
                    }
                    if !s.is_empty() {
                        out.push(Part::Lit(s))?;
                    }
                }
                TemplateElement::Interpolation(x) => {
                    out.reserve(1)?;
                    let value = self.eval(&x.expression, sc);
                    if self.budget.is_exhausted() {
                        return Err(value);
                    }
                    out.push(Part::Val(value))?;
                }
                TemplateElement::If(x) => self.template_if(x, sc, out)?,
                TemplateElement::For(x) => self.template_collection(x, sc, out)?,
            }
        }
        Ok(())
    }
    fn template_if(
        &self,
        x: &'a tf_ast::TemplateIf<'a>,
        sc: Scope<'_>,
        out: &mut Buffer<'_, Part<'a>>,
    ) -> Result<(), Value> {
        let c = self.eval(&x.condition, sc);
        match c.as_bool() {
            Some(true) => {
                let trail = x.else_strip.map(|s| s.start).unwrap_or(x.endif_strip.start);
                self.template_parts(&x.then_template, sc, x.if_strip.end, trail, out)?;
            }
            Some(false) => {
                if let (Some(es), Some(et)) = (&x.else_strip, &x.else_template) {
                    self.template_parts(et, sc, es.end, x.endif_strip.start, out)?;
                }
            }
            None => {
                return Err(non_known_or(&c, "template if: condition is not a bool"));
            }
        }
        Ok(())
    }

    fn template_collection(
        &self,
        x: &'a tf_ast::TemplateFor<'a>,
        sc: Scope<'_>,
        out: &mut Buffer<'_, Part<'a>>,
    ) -> Result<(), Value> {
        let coll = self.eval(&x.collection, sc);
        let attempt = match &coll.kind {
            Kind::Known(Known::List(items)) => self.template_for(
                x,
                items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (Value::number(i as f64), v.child_of(&coll))),
                sc,
                out,
            ),
            Kind::Known(Known::Object(items)) => self.template_for(
                x,
                items
                    .iter()
                    .map(|(k, v)| (Value::string(k.clone()), v.child_of(&coll))),
                sc,
                out,
            ),
            _ => Err(non_known_or(&coll, "template for: not iterable")),
        };
        attempt.map_err(|v| failure(v, [&coll]))?;
        Ok(())
    }

    fn template_for(
        &self,
        directive: &'a tf_ast::TemplateFor<'a>,
        items: impl Iterator<Item = (Value, Value)>,
        sc: Scope<'_>,
        out: &mut Buffer<'_, Part<'a>>,
    ) -> Result<(), Value> {
        for (key, value) in items {
            sc.with_iteration(
                directive.key_var.as_ref().map(|v| v.name.as_str()),
                directive.value_var.name.as_str(),
                &key,
                &value,
                |scope| {
                    self.template_parts(
                        &directive.template,
                        scope,
                        directive.for_strip.end,
                        directive.endfor_strip.start,
                        out,
                    )
                },
            )?;
        }
        Ok(())
    }
}

pub(crate) enum Part<'a> {
    Lit(&'a str),
    Val(Value),
}

impl Part<'_> {
    fn value(&self) -> Option<&Value> {
        match self {
            Self::Val(v) => Some(v),
            Self::Lit(_) => None,
        }
    }
}

fn strip(element: &TemplateElement<'_>) -> (bool, bool) {
    match element {
        TemplateElement::Literal(_) => (false, false),
        TemplateElement::Interpolation(x) => (x.strip.start, x.strip.end),
        TemplateElement::If(x) => (x.if_strip.start, x.endif_strip.end),
        TemplateElement::For(x) => (x.for_strip.start, x.endfor_strip.end),
    }
}

fn concat_parts(parts: &[Part<'_>], budget: &tf_limits::input::InputBudget) -> Value {
    concat_parts_inner(parts, budget)
        .unwrap_or_else(|value| failure(value, parts.iter().filter_map(Part::value)))
}

fn concat_parts_inner(
    parts: &[Part<'_>],
    budget: &tf_limits::input::InputBudget,
) -> Result<Value, Value> {
    let mut alts = Buffer::with_capacity(1, budget)?;
    alts.push((Text::new(budget), Prov::EMPTY, false))?;
    for p in parts {
        match p {
            Part::Lit(s) => {
                for a in alts.iter_mut() {
                    a.0.push_str(s)?;
                }
            }
            Part::Val(v) => {
                let (choices, tainted): (&[Value], bool) = match &v.kind {
                    Kind::OneOf(o) => (&o.alternatives, o.tainted),
                    _ => (std::slice::from_ref(v), false),
                };
                let count = alts
                    .len()
                    .checked_mul(choices.len())
                    .filter(|&count| count <= MAX_ALTERNATIVES)
                    .ok_or_else(|| Value::limit("template: too many alternatives"))?;
                let mut next = Buffer::with_capacity(count, budget)?;
                for a in alts.iter() {
                    for c in choices {
                        let c = c.child_of(v);
                        let s = text::coerce(&c, budget)?;
                        let mut t = Text::new(budget);
                        t.push_str(a.0.as_str())?;
                        t.push_str(&s)?;
                        next.push((t, a.1.joined(&c.prov), a.2 || tainted))?;
                    }
                }
                alts = next;
            }
        }
    }
    let tainted = alts.iter().any(|a| a.2);
    let values = collections::try_collect(
        alts.finish()
            .into_iter()
            .map(|(s, p, _)| Ok(Value::string(s.finish()?).with_prov(p))),
        budget,
    )?;
    collections::one_of(values, tainted, budget)
}
