use super::*;

#[expect(clippy::too_many_lines)]
pub(super) fn structural(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "length" => {
            arity(a, 1)?;
            match known(&a[0])? {
                Known::List(l) => Ok(num(l.len() as f64)),
                Known::Object(m) => Ok(num(m.len() as f64)),
                Known::String(s) => Ok(num(s.chars().count() as f64)),
                _ => Err(Value::error(
                    "length: argument must be a collection or string",
                )),
            }
        }
        "concat" => {
            let mut out = Buffer::new(budget);
            for x in a {
                let items = list(x)?;
                out.reserve(items.len())?;
                for item in items {
                    out.push(item.child_of(x))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "merge" => {
            let mut m = Map::new();
            for x in a {
                if x.is_null() {
                    continue;
                }
                for (k, v) in obj(x)? {
                    collections::insert(&mut m, k.clone(), v.child_of(x), budget)?;
                }
            }
            Ok(Value::object(m))
        }
        "lookup" => {
            if a.len() < 2 || a.len() > 3 {
                return Err(Value::error("lookup: wrong number of arguments"));
            }
            let m = obj(&a[0])?;
            match string(&a[1]) {
                Ok(k) => match m.get(&*k) {
                    Some(v) => Ok(v.child_of(&a[0])),
                    None => match a.get(2) {
                        Some(d) => Ok(d.clone()),
                        None => Err(Value::error(format!("lookup: key \"{k}\" not found"))),
                    },
                },
                Err(limit) if budget.exhaustion().is_some() => Err(limit),
                Err(_) if a[1].is_known() => Err(Value::error("lookup: key must be a string")),
                Err(_) => {
                    // Unknown key into a known map: any of its values, or the default.
                    if m.len().saturating_add(usize::from(a.len() == 3)) > MAX_ALTERNATIVES {
                        return Err(Value::limit("lookup: too many alternatives"));
                    }
                    let mut alts = Buffer::with_capacity(
                        m.len().saturating_add(usize::from(a.len() == 3)),
                        budget,
                    )?;
                    for value in m.values() {
                        alts.push(value.child_of(&a[0]))?;
                    }
                    if let Some(d) = a.get(2) {
                        alts.push(d.clone())?;
                    }
                    if alts.is_empty() {
                        return Err(a[1].clone());
                    }
                    collections::one_of(alts.finish(), a[1].is_tainted(), budget)
                }
            }
        }
        "element" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let i = number(&a[1])?;
            if l.is_empty() {
                return Err(Value::error("element: empty list"));
            }
            let idx = (i.floor() as i64).rem_euclid(l.len() as i64) as usize;
            Ok(l[idx].child_of(&a[0]))
        }
        "keys" => {
            arity(a, 1)?;
            Ok(Value::list(collections::collect(
                obj(&a[0])?.keys().map(|k| Value::string(k.clone())),
                budget,
            )?))
        }
        "values" => {
            arity(a, 1)?;
            Ok(Value::list(collections::collect(
                obj(&a[0])?.values().map(|v| v.child_of(&a[0])),
                budget,
            )?))
        }
        "contains" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let mut pending = Buffer::new(budget);
            for e in l {
                let equal = e.known_eq(&a[1]);
                meter::check()?;
                match equal {
                    Some(true) => return Ok(Value::bool(true)),
                    Some(false) => {}
                    None => pending.push(e.clone())?,
                }
            }
            if let Some(v) = dominant_non_known(pending.iter().chain(std::iter::once(&a[1]))) {
                return Err(v);
            }
            if !pending.is_empty() {
                return Err(Value::other("contains: partially unknown element"));
            }
            Ok(Value::bool(false))
        }
        "index" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            for (i, e) in l.iter().enumerate() {
                let equal = e.known_eq(&a[1]);
                meter::check()?;
                match equal {
                    Some(true) => return Ok(num(i as f64)),
                    Some(false) => {}
                    None => return Err(non_known_or(e, "index: unknown element")),
                }
            }
            Err(Value::error("index: item not found"))
        }
        "flatten" => {
            arity(a, 1)?;
            let mut out = Buffer::new(budget);
            flatten_into(&a[0], &mut out, budget)?;
            Ok(Value::list(out.finish()))
        }
        "distinct" | "toset" => {
            arity(a, 1)?;
            if a[0].is_null() && name == "toset" {
                return Ok(Value::null());
            }
            let l = list(&a[0])?;
            let mut out: Buffer<Value> = Buffer::new(budget);
            for e in l {
                if e.is_wholly_known() && contains_equal(&out, e)? {
                    continue;
                }
                out.push(e.child_of(&a[0]))?;
            }
            if name == "toset" && out.iter().all(|e| e.as_str().is_some()) {
                out.sort_unstable_by(|x, y| x.as_str().cmp(&y.as_str()));
            }
            Ok(Value::list(out.finish()))
        }
        "tolist" => {
            arity(a, 1)?;
            if a[0].is_null() {
                return Ok(Value::null());
            }
            list(&a[0])?;
            Ok(a[0].clone())
        }
        "tomap" => {
            arity(a, 1)?;
            if a[0].is_null() {
                return Ok(Value::null());
            }
            obj(&a[0])?;
            Ok(a[0].clone())
        }
        "compact" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            let mut out = Buffer::with_capacity(l.len(), budget)?;
            for e in l {
                if !(e.is_null() || e.as_str() == Some("")) {
                    out.push(e.child_of(&a[0]))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "coalesce" => {
            for x in a {
                match &x.kind {
                    Kind::Known(Known::Null) => continue,
                    Kind::Known(Known::String(s)) if s.is_empty() => continue,
                    Kind::Known(_) => return Ok(x.clone()),
                    _ => return Err(x.clone()),
                }
            }
            Err(Value::error("coalesce: no non-null, non-empty argument"))
        }
        "coalescelist" => {
            for x in a {
                match list(x) {
                    Ok([]) => continue,
                    Ok(_) => return Ok(x.clone()),
                    Err(e) => return Err(e),
                }
            }
            Err(Value::error("coalescelist: all lists empty"))
        }
        "reverse" => {
            arity(a, 1)?;
            let mut l =
                collections::collect(list(&a[0])?.iter().map(|e| e.child_of(&a[0])), budget)?;
            l.reverse();
            Ok(Value::list(l))
        }
        "slice" => {
            arity(a, 3)?;
            let l = list(&a[0])?;
            let (s, e) = (number(&a[1])? as usize, number(&a[2])? as usize);
            if s > e || e > l.len() {
                return Err(Value::error("slice: index out of range"));
            }
            Ok(Value::list(collections::collect(
                l[s..e].iter().map(|x| x.child_of(&a[0])),
                budget,
            )?))
        }
        "sort" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            let mut ss = Buffer::with_capacity(l.len(), budget)?;
            for e in l {
                ss.push(string(e)?)?;
            }
            ss.sort_unstable();
            Ok(Value::list(collections::collect(
                ss.finish().into_iter().map(Value::string),
                budget,
            )?))
        }
        "range" => {
            let ns = collections::try_collect(a.iter().map(number), budget)?;
            let (start, end, step) = match ns.as_slice() {
                [e] => (0.0, *e, 1.0),
                [s, e] => (*s, *e, if s <= e { 1.0 } else { -1.0 }),
                [s, e, st] => (*s, *e, *st),
                _ => return Err(Value::error("range: wrong number of arguments")),
            };
            if step == 0.0 {
                return Err(Value::error("range: step must not be zero"));
            }
            let mut out = Buffer::new(budget);
            let mut x = start;
            while (step > 0.0 && x < end) || (step < 0.0 && x > end) {
                if out.len() == 1024 {
                    return Err(Value::limit("range: too large"));
                }
                out.push(num(x))?;
                x += step;
            }
            Ok(Value::list(out.finish()))
        }
        "zipmap" => {
            arity(a, 2)?;
            let (ks, vs) = (list(&a[0])?, list(&a[1])?);
            if ks.len() != vs.len() {
                return Err(Value::error("zipmap: lists differ in length"));
            }
            let mut m = Map::new();
            for (k, v) in ks.iter().zip(vs.iter()) {
                collections::insert(&mut m, string(k)?, v.child_of(&a[1]), budget)?;
            }
            Ok(Value::object(m))
        }
        "one" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            match l.len() {
                0 => Ok(Value::null()),
                1 => Ok(l[0].child_of(&a[0])),
                _ => Err(Value::error("one: more than one element")),
            }
        }
        "chunklist" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let n = number(&a[1])? as usize;
            if n == 0 {
                return Ok(Value::list(collections::collect(
                    std::iter::once(a[0].clone()),
                    budget,
                )?));
            }
            Ok(Value::list(collections::try_collect(
                l.chunks(n).map(|c| {
                    collections::collect(c.iter().map(|x| x.child_of(&a[0])), budget)
                        .map(Value::list)
                }),
                budget,
            )?))
        }
        "setunion" | "setintersection" | "setsubtract" => {
            if a.is_empty() {
                return Err(Value::error("set function: no arguments"));
            }
            let mut sets = Buffer::with_capacity(a.len(), budget)?;
            for x in a {
                let l = list(x)?;
                if let Some(nk) = dominant_non_known(l.iter()) {
                    return Err(nk);
                }
                sets.push(collections::collect(
                    l.iter().map(|e| e.child_of(x)),
                    budget,
                )?)?;
            }
            let has = contains_equal;
            let mut out: Buffer<Value> = Buffer::new(budget);
            match name {
                "setunion" => {
                    for s in sets.iter() {
                        for v in s {
                            if !has(&out, v)? {
                                out.push(v.clone())?;
                            }
                        }
                    }
                }
                "setintersection" => {
                    for v in &sets[0] {
                        if all_contain(&sets[1..], v)? && !has(&out, v)? {
                            out.push(v.clone())?;
                        }
                    }
                }
                _ => {
                    for v in &sets[0] {
                        if !any_contains(&sets[1..], v)? && !has(&out, v)? {
                            out.push(v.clone())?;
                        }
                    }
                }
            }
            Ok(Value::list(out.finish()))
        }
        "setproduct" => setproduct(a, budget),
        "matchkeys" => {
            arity(a, 3)?;
            let (vals, keys, search) = (list(&a[0])?, list(&a[1])?, list(&a[2])?);
            let mut out = Buffer::new(budget);
            for (v, k) in vals.iter().zip(keys.iter()) {
                let mut hit = false;
                for s in search {
                    let equal = k.known_eq(s);
                    meter::check()?;
                    match equal {
                        Some(true) => hit = true,
                        Some(false) => {}
                        None => return Err(non_known_or(k, "matchkeys: unknown key")),
                    }
                }
                if hit {
                    out.push(v.child_of(&a[0]))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "transpose" => {
            arity(a, 1)?;
            let mut m: BTreeMap<Arc<str>, Buffer<Value>> = BTreeMap::new();
            for (k, v) in obj(&a[0])? {
                for e in list(v)? {
                    let key = string(e)?;
                    if !m.contains_key(&key) {
                        collections::insert(&mut m, key.clone(), Buffer::new(budget), budget)?;
                    }
                    m.get_mut(&key)
                        .expect("inserted group")
                        .push(Value::string(k.clone()))?;
                }
            }
            let mut out = Map::new();
            for (key, group) in m {
                collections::insert(&mut out, key, Value::list(group.finish()), budget)?;
            }
            Ok(Value::object(out))
        }
        "sum" => {
            arity(a, 1)?;
            let mut s = 0.0;
            for e in list(&a[0])? {
                s += number(e)?;
            }
            Ok(num(s))
        }
        "alltrue" | "anytrue" => {
            arity(a, 1)?;
            let all = name == "alltrue";
            let mut pending = Buffer::new(budget);
            for e in list(&a[0])? {
                match e.as_bool() {
                    Some(b) if b != all => return Ok(Value::bool(!all)),
                    Some(_) => {}
                    None => pending.push(e.clone())?,
                }
            }
            match dominant_non_known(pending.iter()) {
                Some(v) => Err(v),
                None if pending.is_empty() => Ok(Value::bool(all)),
                None => Err(Value::error(format!("{name}: non-bool element"))),
            }
        }
        _ => numbers(name, a, budget),
    }
}

pub(super) fn setproduct(args: &[Value], budget: &InputBudget) -> R {
    if args.is_empty() {
        return Err(Value::error("setproduct: no arguments"));
    }
    if args.len() > PRODUCT_VALUES_MAX {
        return Err(Value::limit("setproduct: too many tuple elements"));
    }
    let lists = collections::try_collect(args.iter().map(list), budget)?;
    // An empty factor makes even an otherwise huge product empty.
    if lists.iter().any(|items| items.is_empty()) {
        return Ok(Value::list(Vec::new()));
    }
    let rows = lists.iter().try_fold(1usize, |rows, items| {
        rows.checked_mul(items.len())
            .filter(|&rows| rows <= PRODUCT_ROWS_MAX)
    });
    let rows = rows.ok_or_else(|| Value::limit("setproduct: too large"))?;
    let values = rows.checked_mul(args.len());
    if values.is_none_or(|values| values > PRODUCT_VALUES_MAX) {
        return Err(Value::limit("setproduct: too many tuple elements"));
    }
    assert!(rows <= PRODUCT_ROWS_MAX);
    let mut result = Buffer::with_capacity(rows, budget)?;
    let mut indices = collections::collect(std::iter::repeat_n(0, args.len()), budget)?;
    for _ in 0..rows {
        // Construct each final row once; repeated prefix cloning is quadratic in tuple width.
        let row = collections::collect(
            lists
                .iter()
                .zip(args)
                .zip(&indices)
                .map(|((items, arg), &index)| items[index].child_of(arg)),
            budget,
        )?;
        assert_eq!(row.len(), args.len());
        result.push(Value::list(row))?;
        for (index, items) in indices.iter_mut().zip(&lists).rev() {
            *index += 1;
            if *index < items.len() {
                break;
            }
            *index = 0;
        }
    }
    assert_eq!(result.len(), rows);
    Ok(Value::list(result.finish()))
}

/// Whether `items` holds a value known equal to `v`; stops at the work allowance.
pub(super) fn contains_equal(items: &[Value], v: &Value) -> Result<bool, Value> {
    for item in items {
        let equal = item.known_eq(v);
        meter::check()?;
        if equal == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn all_contain<S: std::ops::Deref<Target = [Value]>>(
    sets: &[S],
    v: &Value,
) -> Result<bool, Value> {
    for set in sets {
        if !contains_equal(set, v)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn any_contains<S: std::ops::Deref<Target = [Value]>>(
    sets: &[S],
    v: &Value,
) -> Result<bool, Value> {
    for set in sets {
        if contains_equal(set, v)? {
            return Ok(true);
        }
    }
    Ok(false)
}
