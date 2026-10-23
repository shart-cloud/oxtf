use super::*;

impl<'p> Interp<'p> {
    #[expect(clippy::too_many_lines)]
    pub(super) fn expr(&mut self, e: &Expr, env: &mut Env) -> R<Py> {
        self.step()?;
        Ok(match e {
            Expr::Const { v } => Py::from_const(v).map_err(Flow::Unsupported)?,
            Expr::Name { id } => self.lookup(id, env)?,
            Expr::SelfAttr { attr } => self.self_attr(attr)?,
            Expr::Call { func, args, kwargs } => self.call(func, args, kwargs, env)?,
            Expr::Sub { value, index } => {
                let (c, i) = (self.expr(value, env)?, self.expr(index, env)?);
                self.subscript(&c, &i)?
            }
            Expr::Slice {
                value,
                lower,
                upper,
                step,
            } => {
                let c = self.expr(value, env)?;
                let mut bound = |b: &Option<Box<Expr>>, this: &mut Self| -> R<Option<i64>> {
                    match b {
                        None => Ok(None),
                        Some(e) => match this.expr(e, env)? {
                            Py::None => Ok(None),
                            Py::Int(i) => Ok(Some(i)),
                            Py::Bool(b) => Ok(Some(b as i64)),
                            _ => exc("TypeError"),
                        },
                    }
                };
                let (lo, hi, st) = (bound(lower, self)?, bound(upper, self)?, bound(step, self)?);
                self.slice(&c, lo, hi, st)?
            }
            Expr::Cmp {
                left,
                ops,
                comparators,
            } => {
                let mut a = self.expr(left, env)?;
                for (op, c) in ops.iter().zip(comparators) {
                    let b = self.expr(c, env)?;
                    if !self.compare(*op, &a, &b)? {
                        return Ok(Py::Bool(false));
                    }
                    a = b;
                }
                Py::Bool(true)
            }
            Expr::And { values } => {
                let mut last = Py::Bool(true);
                for v in values {
                    last = self.expr(v, env)?;
                    if !self.truthy(&last)? {
                        return Ok(last);
                    }
                }
                last
            }
            Expr::Or { values } => {
                let mut last = Py::Bool(false);
                for v in values {
                    last = self.expr(v, env)?;
                    if self.truthy(&last)? {
                        return Ok(last);
                    }
                }
                last
            }
            Expr::Not { operand } => {
                let v = self.expr(operand, env)?;
                Py::Bool(!self.truthy(&v)?)
            }
            Expr::Neg { operand } | Expr::Pos { operand } => {
                let v = self.expr(operand, env)?;
                let neg = matches!(e, Expr::Neg { .. });
                match self.concrete(&v)? {
                    Py::Int(i) => Py::Int(if neg {
                        i.checked_neg().ok_or_else(overflow)?
                    } else {
                        i
                    }),
                    Py::Bool(b) => Py::Int(if neg { -(b as i64) } else { b as i64 }),
                    Py::Float(f) => Py::Float(if neg { -f } else { f }),
                    _ => return exc("TypeError"),
                }
            }
            Expr::Bin { op, left, right } => {
                let (a, b) = (self.expr(left, env)?, self.expr(right, env)?);
                self.binop(*op, &a, &b, false)?
            }
            Expr::Ifexp { test, body, orelse } => {
                let t = self.expr(test, env)?;
                if self.truthy(&t)? {
                    self.expr(body, env)?
                } else {
                    self.expr(orelse, env)?
                }
            }
            Expr::List { elts } => Py::list(self.exprs(elts, env)?),
            Expr::Tuple { elts } => Py::tuple(self.exprs(elts, env)?),
            Expr::Set { elts } => {
                let items = self.exprs(elts, env)?;
                Py::Set(Rc::new(RefCell::new(self.dedup(items)?)))
            }
            Expr::Dict { keys, values } => {
                let mut out = DictBuilder::default();
                for (k, v) in keys.iter().zip(values) {
                    let (k, v) = (self.expr(k, env)?, self.expr(v, env)?);
                    out.insert(self, k, v)?;
                }
                Py::Dict(Rc::new(RefCell::new(out.entries)))
            }
            Expr::Listcomp { elt, generators } | Expr::Genexp { elt, generators } => {
                let mut out = Vec::new();
                self.comprehension(generators, env, &mut |this, env| {
                    out.push(this.expr(elt, env)?);
                    Ok(true)
                })?;
                Py::list(out)
            }
            Expr::Setcomp { elt, generators } => {
                let mut out = Vec::new();
                self.comprehension(generators, env, &mut |this, env| {
                    out.push(this.expr(elt, env)?);
                    Ok(true)
                })?;
                Py::Set(Rc::new(RefCell::new(self.dedup(out)?)))
            }
            Expr::Dictcomp {
                key,
                value,
                generators,
            } => {
                let mut out = DictBuilder::default();
                self.comprehension(generators, env, &mut |this, env| {
                    let (k, v) = (this.expr(key, env)?, this.expr(value, env)?);
                    out.insert(this, k, v)?;
                    Ok(true)
                })?;
                Py::Dict(Rc::new(RefCell::new(out.entries)))
            }
            Expr::Lambda { params, body } => {
                Py::Lambda(Rc::new((params.clone(), (**body).clone())))
            }
            Expr::Fstr { parts } => {
                let mut s = String::new();
                for p in parts {
                    let v = self.expr(p, env)?;
                    match self.concrete(&v)? {
                        Py::Str(x) => s.push_str(&x),
                        other => s.push_str(&self.to_str(&other)?),
                    }
                }
                Py::str(&s)
            }
            Expr::Exception { ty } => Py::Exception(Rc::from(ty.as_str())),
            Expr::Attr { value, attr } => {
                let obj = self.expr(value, env)?;
                self.get_attr(&obj, attr)?
            }
            Expr::Static { key, v } => match self.statics.get(key) {
                Some(p) => p.clone(),
                None => {
                    let p = Py::from_const(v).map_err(Flow::Unsupported)?;
                    self.statics.insert(key.clone(), p.clone());
                    p
                }
            },
        })
    }

    pub(super) fn exprs(&mut self, es: &[Expr], env: &mut Env) -> R<Vec<Py>> {
        es.iter().map(|e| self.expr(e, env)).collect()
    }

    pub(super) fn dedup(&self, items: Vec<Py>) -> R<Vec<Py>> {
        let mut out: Vec<Py> = Vec::new();
        let mut members = Members::of(&[]);
        for item in items {
            if !self.member(&members, &out, &item)? {
                members.insert(&item);
                out.push(item);
            }
        }
        Ok(out)
    }

    pub(super) fn dict_insert(&self, out: &mut Vec<(Py, Py)>, k: Py, v: Py) -> R<()> {
        let k = self.concrete(&k)?;
        for entry in out.iter_mut() {
            if self.eq(&entry.0, &k)? {
                entry.1 = v;
                return Ok(());
            }
        }
        out.push((k, v));
        Ok(())
    }

    /// Run `body` for each binding of the generators; it returns `false`
    /// to stop early (`any` / `all`). Comprehension variables are restored
    /// afterwards, as their own scope would leave the enclosing one.
    pub(super) fn comprehension(
        &mut self,
        gens: &[Generator],
        env: &mut Env,
        body: &mut dyn FnMut(&mut Self, &mut Env) -> R<bool>,
    ) -> R<bool> {
        let mut names = Vec::new();
        for g in gens {
            target_names(&g.target, &mut names);
        }
        let saved: Vec<(String, Option<Py>)> = names
            .iter()
            .map(|n| (n.clone(), env.get(n).cloned()))
            .collect();
        let result = self.generate(gens, env, body);
        for (n, v) in saved {
            match v {
                Some(v) => env.insert(n, v),
                None => env.remove(&n),
            };
        }
        result
    }

    pub(super) fn generate(
        &mut self,
        gens: &[Generator],
        env: &mut Env,
        body: &mut dyn FnMut(&mut Self, &mut Env) -> R<bool>,
    ) -> R<bool> {
        let Some((g, rest)) = gens.split_first() else {
            return body(self, env);
        };
        let it = self.expr(&g.iter, env)?;
        'items: for item in self.iterate(&it)? {
            self.assign(&g.target, item, env)?;
            for cond in &g.ifs {
                let c = self.expr(cond, env)?;
                if !self.truthy(&c)? {
                    continue 'items;
                }
            }
            if !self.generate(rest, env, body)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn slice(
        &self,
        c: &Py,
        lo: Option<i64>,
        hi: Option<i64>,
        step: Option<i64>,
    ) -> R<Py> {
        let step = step.unwrap_or(1);
        if step == 0 {
            return exc("ValueError");
        }
        let pick = |len: usize| -> Vec<usize> {
            let len = len as i64;
            let clamp = |x: i64, low: i64, high: i64| x.max(low).min(high);
            let norm = |x: i64| if x < 0 { x + len } else { x };
            let mut out = Vec::new();
            if step > 0 {
                let mut i = clamp(lo.map_or(0, norm), 0, len);
                let end = clamp(hi.map_or(len, norm), 0, len);
                while i < end {
                    out.push(i as usize);
                    i += step;
                }
            } else {
                let mut i = clamp(lo.map_or(len - 1, norm), -1, len - 1);
                let end = clamp(hi.map_or(-1, norm), -1, len - 1);
                while i > end {
                    out.push(i as usize);
                    i += step;
                }
            }
            out
        };
        Ok(match self.concrete(c)? {
            Py::List(l) => {
                let items = l.borrow();
                Py::list(
                    pick(items.len())
                        .into_iter()
                        .map(|i| items[i].clone())
                        .collect(),
                )
            }
            Py::Tuple(t) => Py::tuple(pick(t.len()).into_iter().map(|i| t[i].clone()).collect()),
            Py::Str(s) => {
                let chars: Vec<char> = s.chars().collect();
                Py::str(
                    &pick(chars.len())
                        .into_iter()
                        .map(|i| chars[i])
                        .collect::<String>(),
                )
            }
            _ => return exc("TypeError"),
        })
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn binop(&self, op: BinOp, a: &Py, b: &Py, in_place: bool) -> R<Py> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        let int = |v: &Py| match v {
            Py::Int(i) => Some(*i),
            Py::Bool(b) => Some(*b as i64),
            _ => None,
        };
        // Set algebra: `-` `|` `&` `^`, keeping the left operand's order.
        if let (Py::Set(x), Py::Set(y)) = (&a, &b)
            && matches!(
                op,
                BinOp::Sub | BinOp::Bitor | BinOp::Bitand | BinOp::Bitxor
            )
        {
            let (xs, ys) = (x.borrow().clone(), y.borrow().clone());
            let (in_xs, in_ys) = (Members::of(&xs), Members::of(&ys));
            let mut out = Vec::new();
            for v in &xs {
                let in_y = self.member(&in_ys, &ys, v)?;
                if match op {
                    BinOp::Sub | BinOp::Bitxor => !in_y,
                    BinOp::Bitand => in_y,
                    _ => true,
                } {
                    out.push(v.clone());
                }
            }
            if matches!(op, BinOp::Bitor | BinOp::Bitxor) {
                for v in &ys {
                    if !self.member(&in_xs, &xs, v)? {
                        out.push(v.clone());
                    }
                }
            }
            if in_place {
                *x.borrow_mut() = out;
                return Ok(a.clone());
            }
            return Ok(Py::Set(Rc::new(RefCell::new(out))));
        }
        if matches!(op, BinOp::Bitor | BinOp::Bitand | BinOp::Bitxor) {
            return match (int(&a), int(&b)) {
                (Some(x), Some(y)) => {
                    let r = match op {
                        BinOp::Bitor => x | y,
                        BinOp::Bitand => x & y,
                        _ => x ^ y,
                    };
                    // bool op bool stays bool.
                    Ok(if matches!((&a, &b), (Py::Bool(_), Py::Bool(_))) {
                        Py::Bool(r != 0)
                    } else {
                        Py::Int(r)
                    })
                }
                _ => exc("TypeError"),
            };
        }
        match (&a, &b, op) {
            (Py::Str(x), Py::Str(y), BinOp::Add) => return Ok(Py::str(&format!("{x}{y}"))),
            (Py::List(x), Py::List(y), BinOp::Add) => {
                if in_place {
                    let extra = y.borrow().clone();
                    x.borrow_mut().extend(extra);
                    return Ok(a.clone());
                }
                let mut out = x.borrow().clone();
                out.extend(y.borrow().iter().cloned());
                return Ok(Py::list(out));
            }
            (Py::Tuple(x), Py::Tuple(y), BinOp::Add) => {
                return Ok(Py::tuple(x.iter().chain(y.iter()).cloned().collect()));
            }
            (Py::Str(s), Py::Int(n), BinOp::Mul) | (Py::Int(n), Py::Str(s), BinOp::Mul) => {
                return Ok(Py::str(&s.repeat((*n).max(0) as usize)));
            }
            (Py::Str(_), _, BinOp::Mod) => return unsupported("printf-style formatting"),
            _ => {}
        }
        if let (Some(x), Some(y)) = (int(&a), int(&b)) {
            return Ok(match op {
                BinOp::Add => Py::Int(x.checked_add(y).ok_or_else(overflow)?),
                BinOp::Sub => Py::Int(x.checked_sub(y).ok_or_else(overflow)?),
                BinOp::Mul => Py::Int(x.checked_mul(y).ok_or_else(overflow)?),
                BinOp::Div => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    Py::Float(x as f64 / y as f64)
                }
                BinOp::Floordiv => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    Py::Int(
                        x.div_euclid(y)
                            - if (x.rem_euclid(y) != 0) && (y < 0) {
                                1
                            } else {
                                0
                            },
                    )
                }
                BinOp::Mod => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    let r = x % y;
                    Py::Int(if r != 0 && (r < 0) != (y < 0) {
                        r + y
                    } else {
                        r
                    })
                }
                BinOp::Pow => {
                    if y < 0 {
                        Py::Float((x as f64).powf(y as f64))
                    } else {
                        Py::Int(
                            x.checked_pow(y.try_into().map_err(|_| overflow())?)
                                .ok_or_else(overflow)?,
                        )
                    }
                }
                BinOp::Bitor | BinOp::Bitand | BinOp::Bitxor => unreachable!("handled above"),
            });
        }
        match (number(&a), number(&b)) {
            (Some(x), Some(y)) => Ok(Py::Float(match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Div => x / y,
                BinOp::Floordiv if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Floordiv => (x / y).floor(),
                BinOp::Mod if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Mod => x - y * (x / y).floor(),
                BinOp::Pow => x.powf(y),
                BinOp::Bitor | BinOp::Bitand | BinOp::Bitxor => unreachable!("handled above"),
            })),
            _ => exc("TypeError"),
        }
    }

    // -- calls -----------------------------------------------------------

    pub(super) fn call(
        &mut self,
        func: &Func,
        args: &[Expr],
        kwargs: &[(String, Expr)],
        env: &mut Env,
    ) -> R<Py> {
        // `any` / `all` over a generator stop at the first decisive element,
        // as Python's lazy iteration does.
        if let Func::Builtin { builtin } = func
            && (builtin == "any" || builtin == "all")
            && let [Expr::Genexp { elt, generators }] = args
            && kwargs.is_empty()
        {
            let want = builtin == "any";
            let mut found = false;
            self.comprehension(generators, env, &mut |this, env| {
                let v = this.expr(elt, env)?;
                if this.truthy(&v)? == want {
                    found = true;
                    return Ok(false);
                }
                Ok(true)
            })?;
            return Ok(Py::Bool(if want { found } else { !found }));
        }
        let receiver = match func {
            Func::Method { obj, .. } => Some(self.expr(obj, env)?),
            _ => None,
        };
        let args = self.exprs(args, env)?;
        let mut kw = Vec::new();
        for (k, e) in kwargs {
            kw.push((k.clone(), self.expr(e, env)?));
        }
        match func {
            Func::Builtin { builtin } => self.builtin(builtin, args, kw),
            Func::Func { func } => self.call_function(func, args, kw),
            Func::Local { local } => {
                let f = self.lookup(local, env)?;
                self.call_value(&f, args)
            }
            Func::Method { method, .. } => {
                self.method(receiver.expect("receiver"), method, args, kw)
            }
            Func::Class { class } => self.instantiate(class, args, kw),
        }
    }

    pub(super) fn class(&self, name: &str) -> R<&'p Class> {
        let program = self.program;
        program
            .classes
            .get(name)
            .ok_or_else(|| Flow::Unsupported(format!("class {name} not exported")))
    }

    pub(super) fn instantiate(
        &mut self,
        class: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        let def = self.class(class)?;
        let obj = Py::Instance(Rc::new(Instance {
            class: Rc::from(class),
            attrs: RefCell::new(HashMap::default()),
        }));
        if let Some(init) = def.methods.get("__init__") {
            let mut all = vec![obj.clone()];
            all.extend(args);
            self.call_function(init, all, kwargs)?;
        } else if !args.is_empty() || !kwargs.is_empty() {
            return exc("TypeError");
        }
        Ok(obj)
    }

    /// `obj.attr` for an object of an inlined class: its own attribute, a
    /// property, a bound method or a class attribute.
    pub(super) fn get_attr(&mut self, obj: &Py, attr: &str) -> R<Py> {
        let Py::Instance(i) = self.concrete(obj)? else {
            return exc("AttributeError");
        };
        if let Some(v) = i.attrs.borrow().get(attr) {
            return Ok(v.clone());
        }
        let def = self.class(&i.class)?;
        if let Some(getter) = def.properties.get(attr) {
            let v = self.call_function(getter, vec![obj.clone()], Vec::new())?;
            if def.cached.iter().any(|c| c == attr) {
                i.attrs.borrow_mut().insert(attr.to_string(), v.clone());
            }
            return Ok(v);
        }
        if def.methods.contains_key(attr) {
            return Ok(Py::Bound(Rc::new((obj.clone(), Rc::from(attr)))));
        }
        match def.attrs.get(attr) {
            Some(v) => Py::from_const(v).map_err(Flow::Unsupported),
            None => exc("AttributeError"),
        }
    }

    /// `obj.name(args)` for an object of an inlined class.
    pub(super) fn call_method(
        &mut self,
        obj: Py,
        name: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        let Py::Instance(i) = &obj else {
            return exc("AttributeError");
        };
        let def = self.class(&i.class)?;
        if let Some(key) = def.methods.get(name) {
            let mut all = Vec::new();
            if !def.statics.iter().any(|s| s == name) {
                all.push(obj.clone());
            }
            all.extend(args);
            return self.call_function(key, all, kwargs);
        }
        let f = self.get_attr(&obj, name)?;
        if !kwargs.is_empty() {
            return unsupported("keywords to a callable attribute");
        }
        self.call_value(&f, args)
    }

    pub(super) fn call_function(
        &mut self,
        key: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        let program = self.program;
        let Some(f) = program.functions.get(key) else {
            return unsupported(format!("undefined function {key}"));
        };
        let mut env = Env::default();
        if args.len() > f.params.len() && f.vararg.is_none() {
            return exc("TypeError");
        }
        for (p, a) in f.params.iter().zip(args.iter()) {
            env.insert(p.clone(), a.clone());
        }
        if let Some(rest) = &f.vararg {
            let extra = args.get(f.params.len()..).unwrap_or_default().to_vec();
            env.insert(rest.clone(), Py::tuple(extra));
        }
        for (k, v) in kwargs {
            if !f.params.contains(&k) || env.contains_key(&k) {
                return exc("TypeError");
            }
            env.insert(k, v);
        }
        for (i, p) in f.params.iter().enumerate() {
            if !env.contains_key(p) {
                match f.defaults.get(i).and_then(Option::as_ref) {
                    Some(d) => {
                        let v = self.expr(d, &mut Env::default())?;
                        env.insert(p.clone(), v);
                    }
                    None => return exc("TypeError"),
                }
            }
        }
        match self.block(&f.body, &mut env) {
            Ok(()) => Ok(Py::None),
            Err(Flow::Return(v)) => Ok(v),
            Err(Flow::Break | Flow::Continue) => unsupported("break outside a loop"),
            Err(f) => Err(f),
        }
    }

    /// Call a function value (a lambda, e.g. a sort key).
    pub(super) fn call_value(&mut self, f: &Py, args: Vec<Py>) -> R<Py> {
        match f {
            Py::FuncRef(key) => self.call_function(key, args, Vec::new()),
            Py::Bound(b) => {
                let (obj, name) = (b.0.clone(), b.1.clone());
                self.call_method(obj, &name, args, Vec::new())
            }
            Py::Builtin(name) | Py::Type(name) => {
                let name = name.clone();
                self.builtin(&name, args, Vec::new())
            }
            Py::Lambda(l) => {
                let (params, body) = &**l;
                if params.len() != args.len() {
                    return exc("TypeError");
                }
                let mut env: Env = params.iter().cloned().zip(args).collect();
                self.expr(body, &mut env)
            }
            _ => exc("TypeError"),
        }
    }

    pub(super) fn arg(args: &[Py], kwargs: &[(String, Py)], i: usize, name: &str) -> Option<Py> {
        args.get(i).cloned().or_else(|| {
            kwargs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }
}
