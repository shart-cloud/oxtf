//! Conversion of concrete variable defaults during override loading. Each
//! override consumes the previous converted value, as Terraform's loader does.
use crate::source::SourceFile;
use tf_ast::{Block, Expression};
use tf_eval::{Evaluator, Kind, Known, Map, NoResolver, Scope, Value};
use tf_span::{FileId, GetSpan};

/// Evaluation uses shared list/object values, but override conversion must
/// retain Terraform's concrete collection types between declarations.
#[derive(Clone)]
pub struct DefaultValue {
    pub value: Value,
    ty: CommonType,
}

impl DefaultValue {
    pub fn literal(value: Value) -> Self {
        let ty = CommonType::infer(&[&value], None).unwrap_or(CommonType::Null);
        Self { value, ty }
    }
}

/// Terraform retains the original declaration's optional defaults when an
/// override replaces its type constraint. Keep this tree independent of the
/// composed AST and apply it to runtime inputs before their final conversion.
#[derive(Default)]
pub struct TypeDefaults {
    defaults: Map,
    children: std::collections::BTreeMap<String, Self>,
}

impl TypeDefaults {
    pub fn from_type(ty: &Expression<'_>) -> Result<Self, ()> {
        let mut out = Self::default();
        let Expression::FunctionCall(f) = ty.without_parens() else {
            return Ok(out);
        };
        match (f.name.name.as_str(), f.arguments.first()) {
            ("object", Some(Expression::Object(o))) => {
                for item in o.items.iter() {
                    let key = item.key.as_static_str().ok_or(())?;
                    let inner = optional_type(&item.value);
                    if let Expression::FunctionCall(optional) = item.value.without_parens()
                        && optional.name.name == "optional"
                        && let Some(default) = optional.arguments.get(1)
                    {
                        let value = Evaluator::new(&NoResolver, FileId(0)).eval_static(default);
                        out.defaults
                            .insert(key.into(), convert(&value, inner, true)?);
                    }
                    out.children.insert(key.into(), Self::from_type(inner)?);
                }
            }
            ("tuple", Some(Expression::Tuple(t))) => {
                for (i, ty) in t.elements.iter().enumerate() {
                    out.children.insert(i.to_string(), Self::from_type(ty)?);
                }
            }
            ("list" | "set" | "map", Some(element)) => {
                out.children
                    .insert(String::new(), Self::from_type(element)?);
            }
            _ => {}
        }
        Ok(out)
    }

    pub fn apply(&self, value: Value) -> Value {
        let child =
            |key: &str, v: Value| match self.children.get(key).or_else(|| self.children.get("")) {
                Some(defaults) => defaults.apply(v),
                None => v,
            };
        let converted = match &value.kind {
            Kind::Known(Known::List(items)) => Value::list(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| child(&i.to_string(), v.clone()))
                    .collect(),
            ),
            Kind::Known(Known::Object(items)) => {
                let mut items = (**items).clone();
                for (key, default) in &self.defaults {
                    match items.get(key) {
                        Some(v) if !v.is_null() => continue,
                        Some(v) => {
                            items.insert(key.clone(), default.child_of(v));
                        }
                        None => {
                            items.insert(key.clone(), default.clone());
                        }
                    }
                }
                Value::object(
                    items
                        .into_iter()
                        .map(|(k, v)| {
                            let v = child(&k, v);
                            (k, v)
                        })
                        .collect(),
                )
            }
            _ => return value,
        };
        converted.with_prov(value.prov)
    }
}

pub fn literal(block: &Block<'_>, file: &SourceFile) -> Option<Value> {
    let attr = block.body.find_attribute("default")?;
    if file.path.extension().is_some_and(|e| e == "json") {
        return Some(Evaluator::new(&NoResolver, file.id).eval_static(&attr.value));
    }
    // Composition still owns mutable ASTs. Parse this constant into a short
    // lived arena so the evaluator cannot retain a borrow of a node we move.
    let alloc = tf_allocator::Allocator::new();
    let source = attr.value.span().source_text(&file.text);
    let (expr, errors) = tf_parser::parse_expression(&alloc, source);
    if !errors.is_empty() {
        return Some(Value::error("invalid variable default"));
    }
    Some(Evaluator::new(&NoResolver, file.id).eval(alloc.alloc(expr), Scope::EMPTY))
}

pub fn convert_default(
    default: DefaultValue,
    block: &Block<'_>,
    apply_defaults: bool,
) -> Result<DefaultValue, ()> {
    let value = &default.value;
    if !value.is_wholly_known() {
        return Err(());
    }
    if value.is_null()
        && block
            .body
            .find_attribute("nullable")
            .is_some_and(|a| matches!(&a.value, Expression::Bool(b) if !b.value))
    {
        return Err(());
    }
    match block.body.find_attribute("type") {
        Some(ty) => {
            default.ty.check_conversion(&ty.value)?;
            let value = convert(value, &ty.value, apply_defaults)?;
            let ty = CommonType::infer_typed(&[&value], Some(&ty.value), &[Some(&default.ty)])?;
            Ok(DefaultValue { value, ty })
        }
        None => Ok(default),
    }
}

pub fn valid_type(ty: &Expression<'_>) -> bool {
    match ty.without_parens() {
        Expression::Variable(v) => matches!(
            v.name.as_str(),
            "any" | "bool" | "number" | "string" | "list" | "map"
        ),
        Expression::FunctionCall(f) if f.arguments.len() == 1 => {
            match (f.name.name.as_str(), &f.arguments[0]) {
                ("list" | "set" | "map", element) => valid_type(element),
                ("tuple", Expression::Tuple(t)) => t.elements.iter().all(valid_type),
                ("object", Expression::Object(o)) => o.items.iter().all(|i| {
                    i.key.as_static_str().is_some()
                        && match i.value.without_parens() {
                            Expression::FunctionCall(f) if f.name.name == "optional" => {
                                (1..=2).contains(&f.arguments.len()) && valid_type(&f.arguments[0])
                            }
                            ty => valid_type(ty),
                        }
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

fn convert(value: &Value, ty: &Expression<'_>, apply_defaults: bool) -> Result<Value, ()> {
    if value.is_null() {
        return Ok(value.clone());
    }
    let converted = match ty.without_parens() {
        Expression::Variable(t) => match t.name.as_str() {
            "any" => value.clone(),
            "list" if matches!(value.kind, Kind::Known(Known::List(_))) => {
                CommonType::infer(&[value], Some(ty))?.convert(value)?
            }
            "map" if matches!(value.kind, Kind::Known(Known::Object(_))) => {
                CommonType::infer(&[value], Some(ty))?.convert(value)?
            }
            "bool" => match &value.kind {
                Kind::Known(Known::Bool(_)) => value.clone(),
                Kind::Known(Known::String(s)) if matches!(s.as_ref(), "true" | "false") => {
                    Value::bool(s.as_ref() == "true")
                }
                _ => return Err(()),
            },
            "number" => match &value.kind {
                Kind::Known(Known::Number(_)) => value.clone(),
                Kind::Known(Known::String(s)) => {
                    let n: f64 = s.trim().parse().map_err(|_| ())?;
                    if !n.is_finite() {
                        return Err(());
                    }
                    Value::number(n)
                }
                _ => return Err(()),
            },
            "string" => match &value.kind {
                Kind::Known(Known::String(_)) => value.clone(),
                Kind::Known(Known::Bool(_) | Known::Number(_)) => {
                    Value::string(value.to_str().ok_or(())?)
                }
                _ => return Err(()),
            },
            _ => return Err(()),
        },
        Expression::FunctionCall(f) if f.arguments.len() == 1 => {
            let arg = &f.arguments[0];
            match (f.name.name.as_str(), &value.kind, arg) {
                ("list" | "set", Kind::Known(Known::List(values)), _) => {
                    let mut result: Vec<_> = values
                        .iter()
                        .map(|v| convert(v, arg, apply_defaults))
                        .collect::<Result<_, _>>()?;
                    unify_elements(&mut result, arg)?;
                    if f.name.name == "set" {
                        let mut unique = Vec::<Value>::new();
                        for v in result {
                            if !unique.iter().any(|u| u.known_eq(&v) == Some(true)) {
                                unique.push(v);
                            }
                        }
                        // String sets have a stable lexical order in Terraform.
                        if unique.iter().all(|v| v.as_str().is_some()) {
                            unique.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                        }
                        result = unique;
                    }
                    Value::list(result)
                }
                ("map", Kind::Known(Known::Object(values)), _) => {
                    let mut converted: Vec<_> = values
                        .values()
                        .map(|v| convert(v, arg, apply_defaults))
                        .collect::<Result<_, _>>()?;
                    unify_elements(&mut converted, arg)?;
                    Value::object(values.keys().cloned().zip(converted).collect())
                }
                ("tuple", Kind::Known(Known::List(values)), Expression::Tuple(types))
                    if values.len() == types.elements.len() =>
                {
                    Value::list(
                        values
                            .iter()
                            .zip(types.elements.iter())
                            .map(|(v, t)| convert(v, t, apply_defaults))
                            .collect::<Result<_, _>>()?,
                    )
                }
                ("object", Kind::Known(Known::Object(values)), Expression::Object(types)) => {
                    let mut result = Map::new();
                    for item in types.items.iter() {
                        let key = item.key.as_static_str().ok_or(())?;
                        let (ty, default, optional) = match item.value.without_parens() {
                            Expression::FunctionCall(f)
                                if f.name.name == "optional"
                                    && (1..=2).contains(&f.arguments.len()) =>
                            {
                                (&f.arguments[0], f.arguments.get(1), true)
                            }
                            ty => (ty, None, false),
                        };
                        let v = match values.get(key) {
                            Some(v) if !v.is_null() || !optional || !apply_defaults => {
                                convert(v, ty, apply_defaults)?
                            }
                            _ if optional => match default.filter(|_| apply_defaults) {
                                Some(d) => convert(
                                    &Evaluator::new(&NoResolver, FileId(0)).eval_static(d),
                                    ty,
                                    apply_defaults,
                                )?,
                                None => Value::null(),
                            },
                            _ => return Err(()),
                        };
                        result.insert(key.into(), v);
                    }
                    Value::object(result)
                }
                _ => return Err(()),
            }
        }
        _ => return Err(()),
    };
    Ok(converted.with_prov(value.prov.clone()))
}

/// `any` in a collection denotes one common element type, including when it
/// occurs inside a nested object or collection constraint.
fn unify_elements(values: &mut [Value], constraint: &Expression<'_>) -> Result<(), ()> {
    let ty = CommonType::infer(&values.iter().collect::<Vec<_>>(), Some(constraint))?;
    for value in values {
        *value = ty.convert(value)?;
    }
    Ok(())
}

#[derive(Clone, PartialEq)]
enum CommonType {
    Null,
    Bool,
    Number,
    String,
    Tuple(Vec<Self>),
    List(Box<Self>, bool),
    Object(std::collections::BTreeMap<std::sync::Arc<str>, Self>),
    Map(Box<Self>),
}

impl CommonType {
    fn infer(values: &[&Value], constraint: Option<&Expression<'_>>) -> Result<Self, ()> {
        Self::infer_typed(values, constraint, &[])
    }

    fn infer_typed(
        values: &[&Value],
        constraint: Option<&Expression<'_>>,
        sources: &[Option<&Self>],
    ) -> Result<Self, ()> {
        let constraint = constraint.map(Expression::without_parens);
        let dynamic = constraint.is_none()
            || matches!(constraint, Some(Expression::Variable(v)) if v.name == "any");
        if dynamic
            && let Some(Some(first)) = sources.first()
            && sources.iter().all(|s| *s == Some(*first))
        {
            return Ok((*first).clone());
        }
        let call = match constraint {
            Some(Expression::FunctionCall(f)) => Some(f),
            _ => None,
        };
        let collection_name = call
            .map(|f| f.name.name.as_str())
            .or_else(|| match constraint {
                Some(Expression::Variable(v)) => Some(v.name.as_str()),
                _ => None,
            });
        let pairs: Vec<_> = values
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.is_null())
            .map(|(i, v)| (*v, sources.get(i).copied().flatten()))
            .collect();
        let values: Vec<_> = pairs.iter().map(|(v, _)| *v).collect();
        if values.is_empty() {
            let elements = sources
                .iter()
                .map(|s| s.and_then(|s| s.element(0)))
                .collect::<Vec<_>>();
            return match (collection_name, call.and_then(|f| f.arguments.first())) {
                (Some("list" | "set"), element) => Ok(Self::List(
                    Box::new(Self::infer_typed(&[], element, &elements)?),
                    collection_name == Some("set"),
                )),
                (Some("map"), element) => Ok(Self::Map(Box::new(Self::infer_typed(
                    &[],
                    element,
                    &sources
                        .iter()
                        .map(|s| s.and_then(|s| s.field("")))
                        .collect::<Vec<_>>(),
                )?))),
                (Some("tuple"), Some(Expression::Tuple(t))) => Ok(Self::Tuple(
                    t.elements
                        .iter()
                        .enumerate()
                        .map(|(i, ty)| {
                            Self::infer_typed(
                                &[],
                                Some(ty),
                                &sources
                                    .iter()
                                    .map(|s| s.and_then(|s| s.element(i)))
                                    .collect::<Vec<_>>(),
                            )
                        })
                        .collect::<Result<_, _>>()?,
                )),
                (Some("object"), Some(Expression::Object(o))) => Ok(Self::Object(
                    o.items
                        .iter()
                        .map(|i| {
                            let key = i.key.as_static_str().ok_or(())?;
                            Ok((
                                key.into(),
                                Self::infer_typed(
                                    &[],
                                    Some(optional_type(&i.value)),
                                    &sources
                                        .iter()
                                        .map(|s| s.and_then(|s| s.field(key)))
                                        .collect::<Vec<_>>(),
                                )?,
                            ))
                        })
                        .collect::<Result<_, ()>>()?,
                )),
                (Some("string"), _) => Ok(Self::String),
                (Some("number"), _) => Ok(Self::Number),
                (Some("bool"), _) => Ok(Self::Bool),
                _ => Ok(Self::Null),
            };
        }
        let sources: Vec<_> = pairs.iter().map(|(_, ty)| *ty).collect();
        if values.iter().all(|v| {
            matches!(
                v.kind,
                Kind::Known(Known::Bool(_) | Known::Number(_) | Known::String(_))
            )
        }) {
            return if values
                .iter()
                .any(|v| matches!(v.kind, Kind::Known(Known::String(_))))
            {
                Ok(Self::String)
            } else if values
                .iter()
                .all(|v| matches!(v.kind, Kind::Known(Known::Number(_))))
            {
                Ok(Self::Number)
            } else if values
                .iter()
                .all(|v| matches!(v.kind, Kind::Known(Known::Bool(_))))
            {
                Ok(Self::Bool)
            } else {
                Err(())
            };
        }
        if values
            .iter()
            .all(|v| matches!(v.kind, Kind::Known(Known::List(_))))
        {
            let lists: Vec<_> = values
                .iter()
                .map(|v| match &v.kind {
                    Kind::Known(Known::List(v)) => v.as_ref(),
                    _ => unreachable!(),
                })
                .collect();
            let collection = matches!(collection_name, Some("list" | "set"))
                || (dynamic && sources.iter().any(|s| matches!(s, Some(Self::List(..)))));
            if collection || lists.iter().any(|v| v.len() != lists[0].len()) {
                let elements = lists.iter().flat_map(|v| v.iter()).collect::<Vec<_>>();
                let mut element_sources = lists
                    .iter()
                    .enumerate()
                    .flat_map(|(i, list)| {
                        let sources = &sources;
                        (0..list.len()).map(move |j| sources[i].and_then(|s| s.element(j)))
                    })
                    .collect::<Vec<_>>();
                if elements.is_empty() {
                    element_sources = sources
                        .iter()
                        .map(|s| s.and_then(|s| s.element(0)))
                        .collect();
                }
                return Ok(Self::List(
                    Box::new(Self::infer_typed(
                        &elements,
                        call.and_then(|f| f.arguments.first()),
                        &element_sources,
                    )?),
                    collection_name == Some("set")
                        || (dynamic
                            && sources
                                .iter()
                                .all(|s| matches!(s, Some(Self::List(_, true))))),
                ));
            }
            let types = call
                .and_then(|f| f.arguments.first())
                .and_then(|e| match e {
                    Expression::Tuple(t) => Some(&t.elements),
                    _ => None,
                });
            return Ok(Self::Tuple(
                (0..lists[0].len())
                    .map(|i| {
                        Self::infer_typed(
                            &lists.iter().map(|v| &v[i]).collect::<Vec<_>>(),
                            types.and_then(|t| t.get(i)),
                            &sources
                                .iter()
                                .map(|s| s.and_then(|s| s.element(i)))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Result<_, _>>()?,
            ));
        }
        if values
            .iter()
            .all(|v| matches!(v.kind, Kind::Known(Known::Object(_))))
        {
            let objects: Vec<_> = values
                .iter()
                .map(|v| match &v.kind {
                    Kind::Known(Known::Object(v)) => v.as_ref(),
                    _ => unreachable!(),
                })
                .collect();
            let map = collection_name == Some("map")
                || (dynamic && sources.iter().any(|s| matches!(s, Some(Self::Map(_)))));
            if !map && objects.iter().all(|v| v.keys().eq(objects[0].keys())) {
                let types = call
                    .and_then(|f| f.arguments.first())
                    .and_then(|e| match e {
                        Expression::Object(o) => Some(o),
                        _ => None,
                    });
                let fields = objects[0]
                    .keys()
                    .map(|key| {
                        let constraint = types
                            .and_then(|o| {
                                o.items
                                    .iter()
                                    .find(|i| i.key.as_static_str() == Some(key.as_ref()))
                            })
                            .map(|i| optional_type(&i.value));
                        Ok((
                            key.clone(),
                            Self::infer_typed(
                                &objects.iter().map(|v| &v[key]).collect::<Vec<_>>(),
                                constraint,
                                &sources
                                    .iter()
                                    .map(|s| s.and_then(|s| s.field(key)))
                                    .collect::<Vec<_>>(),
                            )?,
                        ))
                    })
                    .collect::<Result<_, ()>>();
                if let Ok(fields) = fields {
                    return Ok(Self::Object(fields));
                }
            }
            let elements = objects.iter().flat_map(|v| v.values()).collect::<Vec<_>>();
            let mut element_sources = objects
                .iter()
                .enumerate()
                .flat_map(|(i, object)| {
                    let sources = &sources;
                    object
                        .keys()
                        .map(move |key| sources[i].and_then(|s| s.field(key)))
                })
                .collect::<Vec<_>>();
            if elements.is_empty() {
                element_sources = sources
                    .iter()
                    .map(|s| s.and_then(|s| s.field("")))
                    .collect();
            }
            return Ok(Self::Map(Box::new(Self::infer_typed(
                &elements,
                call.filter(|f| f.name.name == "map")
                    .and_then(|f| f.arguments.first()),
                &element_sources,
            )?)));
        }
        Err(())
    }

    fn element(&self, i: usize) -> Option<&Self> {
        match self {
            Self::Tuple(items) => items.get(i),
            Self::List(ty, _) => Some(ty),
            _ => None,
        }
    }

    fn field(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(key),
            Self::Map(ty) => Some(ty),
            _ => None,
        }
    }

    /// Check conversion availability independently of values: nulls and empty
    /// collections still carry concrete types after a declaration is decoded.
    fn check_conversion(&self, constraint: &Expression<'_>) -> Result<(), ()> {
        if matches!(self, Self::Null) {
            return Ok(());
        }
        let constraint = constraint.without_parens();
        if let Expression::Variable(v) = constraint {
            return match v.name.as_str() {
                "any" => Ok(()),
                "string" if matches!(self, Self::String | Self::Bool | Self::Number) => Ok(()),
                "bool" if matches!(self, Self::Bool | Self::String) => Ok(()),
                "number" if matches!(self, Self::Number | Self::String) => Ok(()),
                "list" if matches!(self, Self::List(..) | Self::Tuple(_)) => Ok(()),
                "map" if matches!(self, Self::Map(_) | Self::Object(_)) => Ok(()),
                _ => Err(()),
            };
        }
        let Expression::FunctionCall(f) = constraint else {
            return Err(());
        };
        let Some(arg) = f.arguments.first() else {
            return Err(());
        };
        match (f.name.name.as_str(), arg, self) {
            ("tuple", Expression::Tuple(t), Self::Tuple(items))
                if items.len() == t.elements.len() =>
            {
                for (source, ty) in items.iter().zip(t.elements.iter()) {
                    source.check_conversion(ty)?;
                }
                Ok(())
            }
            ("list" | "set", ty, Self::Tuple(items)) => {
                for source in items {
                    source.check_conversion(ty)?;
                }
                Ok(())
            }
            ("list" | "set", ty, Self::List(source, _)) => source.check_conversion(ty),
            ("object", Expression::Object(o), Self::Object(_) | Self::Map(_)) => {
                for item in o.items.iter() {
                    let ty = optional_type(&item.value);
                    let optional = matches!(
                        item.value.without_parens(),
                        Expression::FunctionCall(f) if f.name.name == "optional"
                    );
                    match self.field(item.key.as_static_str().ok_or(())?) {
                        // A map may omit an optional field even when its
                        // element type cannot convert to that field's type.
                        Some(_) if optional && matches!(self, Self::Map(_)) => {}
                        Some(source) => source.check_conversion(ty)?,
                        None if optional => {}
                        None => return Err(()),
                    }
                }
                Ok(())
            }
            ("map", ty, Self::Object(fields)) => {
                for source in fields.values() {
                    source.check_conversion(ty)?;
                }
                Ok(())
            }
            ("map", ty, Self::Map(source)) => source.check_conversion(ty),
            _ => Err(()),
        }
    }

    fn convert(&self, value: &Value) -> Result<Value, ()> {
        if value.is_null() {
            return Ok(value.clone());
        }
        let result = match (self, &value.kind) {
            (Self::String, _) => Value::string(value.to_str().ok_or(())?),
            (Self::Bool, Kind::Known(Known::Bool(_)))
            | (Self::Number, Kind::Known(Known::Number(_))) => value.clone(),
            (Self::Tuple(types), Kind::Known(Known::List(values))) => Value::list(
                types
                    .iter()
                    .zip(values.iter())
                    .map(|(t, v)| t.convert(v))
                    .collect::<Result<_, _>>()?,
            ),
            (Self::List(ty, set), Kind::Known(Known::List(values))) => {
                let mut result: Vec<_> = values
                    .iter()
                    .map(|v| ty.convert(v))
                    .collect::<Result<_, _>>()?;
                if *set {
                    let mut unique = Vec::<Value>::new();
                    for v in result {
                        if !unique.iter().any(|u| u.known_eq(&v) == Some(true)) {
                            unique.push(v);
                        }
                    }
                    if unique.iter().all(|v| v.as_str().is_some()) {
                        unique.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                    }
                    result = unique;
                }
                Value::list(result)
            }
            (Self::Object(types), Kind::Known(Known::Object(values))) => Value::object(
                types
                    .iter()
                    .map(|(k, t)| Ok((k.clone(), t.convert(values.get(k).ok_or(())?)?)))
                    .collect::<Result<_, ()>>()?,
            ),
            (Self::Map(ty), Kind::Known(Known::Object(values))) => Value::object(
                values
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), ty.convert(v)?)))
                    .collect::<Result<_, ()>>()?,
            ),
            _ => return Err(()),
        };
        Ok(result.with_prov(value.prov.clone()))
    }
}

fn optional_type<'a, 'v>(ty: &'v Expression<'a>) -> &'v Expression<'a> {
    match ty.without_parens() {
        Expression::FunctionCall(f) if f.name.name == "optional" => {
            f.arguments.first().unwrap_or(ty)
        }
        _ => ty,
    }
}
