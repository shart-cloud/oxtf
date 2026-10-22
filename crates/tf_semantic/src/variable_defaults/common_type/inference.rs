use super::CommonType as Type;
use crate::default_budget::{DefaultContext, DefaultError};
use crate::variable_defaults::optional_type;
use tf_ast::{Expression, FunctionCall};
use tf_eval::{Kind, Known, Map, Value};

#[derive(Clone, Copy)]
struct Constraint<'e, 'a> {
    call: Option<&'e FunctionCall<'a>>,
    name: Option<&'e str>,
    dynamic: bool,
}

impl<'e, 'a> Constraint<'e, 'a> {
    fn new(expression: Option<&'e Expression<'a>>) -> Self {
        let expression = expression.map(Expression::without_parens);
        let call = match expression {
            Some(Expression::FunctionCall(f)) => Some(&**f),
            _ => None,
        };
        let name = call
            .map(|f| f.name.name.as_str())
            .or_else(|| match expression {
                Some(Expression::Variable(v)) => Some(v.name.as_str()),
                _ => None,
            });
        let dynamic = expression.is_none()
            || matches!(expression, Some(Expression::Variable(v)) if v.name == "any");
        Self {
            call,
            name,
            dynamic,
        }
    }

    fn argument(self) -> Option<&'e Expression<'a>> {
        self.call.and_then(|f| f.arguments.first())
    }
}

pub(super) fn infer(
    values: &[&Value],
    constraint: Option<&Expression<'_>>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    cx.charge(1)?;
    cx.charge(values.len())?;
    cx.charge(sources.len())?;
    let constraint = Constraint::new(constraint);
    if constraint.dynamic
        && let Some(Some(first)) = sources.first()
        && sources.iter().all(|s| *s == Some(*first))
    {
        return first.clone_with_context(cx);
    }
    let pairs = cx.scratch(
        values
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.is_null())
            .map(|(i, v)| (*v, sources.get(i).copied().flatten())),
    )?;
    let values = cx.collect(pairs.iter().map(|(v, _)| *v))?;
    if values.is_empty() {
        return empty(constraint, sources, cx);
    }
    let sources = cx.collect(pairs.iter().map(|(_, ty)| *ty))?;
    if values.iter().all(|v| {
        matches!(
            v.kind,
            Kind::Known(Known::Bool(_) | Known::Number(_) | Known::String(_))
        )
    }) {
        return primitive(&values);
    }
    if values
        .iter()
        .all(|v| matches!(v.kind, Kind::Known(Known::List(_))))
    {
        return lists(&values, constraint, &sources, cx);
    }
    if values
        .iter()
        .all(|v| matches!(v.kind, Kind::Known(Known::Object(_))))
    {
        return objects(&values, constraint, &sources, cx);
    }
    Err(DefaultError::Invalid)
}

fn primitive(values: &[&Value]) -> Result<Type, DefaultError> {
    assert!(!values.is_empty());
    if values
        .iter()
        .any(|v| matches!(v.kind, Kind::Known(Known::String(_))))
    {
        Ok(Type::String)
    } else if values
        .iter()
        .all(|v| matches!(v.kind, Kind::Known(Known::Number(_))))
    {
        Ok(Type::Number)
    } else if values
        .iter()
        .all(|v| matches!(v.kind, Kind::Known(Known::Bool(_))))
    {
        Ok(Type::Bool)
    } else {
        Err(DefaultError::Invalid)
    }
}

fn empty(
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    let elements = cx.collect(sources.iter().map(|s| s.and_then(|s| s.element(0))))?;
    match (constraint.name, constraint.argument()) {
        (Some("list" | "set"), element) => Ok(Type::List(
            cx.boxed(|| infer(&[], element, &elements, cx))?,
            constraint.name == Some("set"),
        )),
        (Some("map"), element) => {
            let fields = cx.collect(sources.iter().map(|s| s.and_then(|s| s.field(""))))?;
            Ok(Type::Map(cx.boxed(|| infer(&[], element, &fields, cx))?))
        }
        (Some("tuple"), Some(Expression::Tuple(t))) => Ok(Type::Tuple(cx.try_collect(
            t.elements.iter().enumerate().map(|(i, ty)| {
                let elements = cx.collect(sources.iter().map(|s| s.and_then(|s| s.element(i))))?;
                infer(&[], Some(ty), &elements, cx)
            }),
        )?)),
        (Some("object"), Some(Expression::Object(o))) => {
            Ok(Type::Object(cx.map(o.items.iter().map(|item| {
                let key = item.key.as_static_str().ok_or(DefaultError::Invalid)?;
                let fields = cx.collect(sources.iter().map(|s| s.and_then(|s| s.field(key))))?;
                Ok((
                    key.into(),
                    infer(&[], Some(optional_type(&item.value)), &fields, cx)?,
                ))
            }))?))
        }
        (Some("string"), _) => Ok(Type::String),
        (Some("number"), _) => Ok(Type::Number),
        (Some("bool"), _) => Ok(Type::Bool),
        _ => Ok(Type::Null),
    }
}

fn lists(
    values: &[&Value],
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    let lists = cx.collect(values.iter().map(|v| match &v.kind {
        Kind::Known(Known::List(v)) => v.as_ref(),
        _ => unreachable!(),
    }))?;
    assert!(!lists.is_empty());
    assert_eq!(lists.len(), sources.len());
    for list in &lists {
        cx.charge(list.len())?;
    }
    let collection = matches!(constraint.name, Some("list" | "set"))
        || (constraint.dynamic && sources.iter().any(|s| matches!(s, Some(Type::List(..)))));
    if collection || lists.iter().any(|v| v.len() != lists[0].len()) {
        return list(&lists, constraint, sources, cx);
    }
    let types = match constraint.argument() {
        Some(Expression::Tuple(t)) => Some(&t.elements),
        _ => None,
    };
    Ok(Type::Tuple(cx.try_collect((0..lists[0].len()).map(
        |i| {
            let values = cx.collect(lists.iter().map(|v| &v[i]))?;
            let sources = cx.collect(sources.iter().map(|s| s.and_then(|s| s.element(i))))?;
            infer(&values, types.and_then(|t| t.get(i)), &sources, cx)
        },
    ))?))
}

fn list(
    lists: &[&Vec<Value>],
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    assert_eq!(lists.len(), sources.len());
    let elements = cx.scratch(lists.iter().flat_map(|v| v.iter()))?;
    let mut element_sources = cx.scratch(lists.iter().enumerate().flat_map(|(i, list)| {
        (0..list.len()).map(move |j| sources[i].and_then(|s| s.element(j)))
    }))?;
    assert_eq!(elements.len(), element_sources.len());
    if elements.is_empty() {
        element_sources = cx.collect(sources.iter().map(|s| s.and_then(|s| s.element(0))))?;
    }
    let element = cx.boxed(|| infer(&elements, constraint.argument(), &element_sources, cx))?;
    let set = constraint.name == Some("set")
        || (constraint.dynamic
            && sources
                .iter()
                .all(|s| matches!(s, Some(Type::List(_, true)))));
    Ok(Type::List(element, set))
}

fn objects(
    values: &[&Value],
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    let objects = cx.collect(values.iter().map(|v| match &v.kind {
        Kind::Known(Known::Object(v)) => v.as_ref(),
        _ => unreachable!(),
    }))?;
    assert!(!objects.is_empty());
    assert_eq!(objects.len(), sources.len());
    for object in &objects {
        cx.charge(object.len())?;
    }
    let map = constraint.name == Some("map")
        || (constraint.dynamic && sources.iter().any(|s| matches!(s, Some(Type::Map(_)))));
    if !map && objects.iter().all(|v| v.keys().eq(objects[0].keys())) {
        match object(&objects, constraint, sources, cx) {
            Ok(fields) => return Ok(fields),
            Err(DefaultError::Limit) => return Err(DefaultError::Limit),
            Err(DefaultError::Invalid) => {}
        }
    }
    map_elements(&objects, constraint, sources, cx)
}

fn object(
    objects: &[&Map],
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    let types = match constraint.argument() {
        Some(Expression::Object(o)) => Some(o),
        _ => None,
    };
    Ok(Type::Object(cx.map(objects[0].keys().map(|key| {
        let constraint = types
            .and_then(|o| {
                o.items
                    .iter()
                    .find(|i| i.key.as_static_str() == Some(key.as_ref()))
            })
            .map(|i| optional_type(&i.value));
        let values = cx.collect(objects.iter().map(|v| &v[key]))?;
        let sources = cx.collect(sources.iter().map(|s| s.and_then(|s| s.field(key))))?;
        Ok((key.clone(), infer(&values, constraint, &sources, cx)?))
    }))?))
}

fn map_elements(
    objects: &[&Map],
    constraint: Constraint<'_, '_>,
    sources: &[Option<&Type>],
    cx: DefaultContext<'_>,
) -> Result<Type, DefaultError> {
    assert_eq!(objects.len(), sources.len());
    let elements = cx.scratch(objects.iter().flat_map(|v| v.values()))?;
    let mut element_sources = cx.scratch(objects.iter().enumerate().flat_map(|(i, object)| {
        object
            .keys()
            .map(move |key| sources[i].and_then(|s| s.field(key)))
    }))?;
    assert_eq!(elements.len(), element_sources.len());
    if elements.is_empty() {
        element_sources = cx.collect(sources.iter().map(|s| s.and_then(|s| s.field(""))))?;
    }
    let argument = constraint
        .call
        .filter(|f| f.name.name == "map")
        .and_then(|f| f.arguments.first());
    Ok(Type::Map(cx.boxed(|| {
        infer(&elements, argument, &element_sources, cx)
    })?))
}
