//! Terraform address and reference strings as they appear in plan JSON
//! (`module.a[0].aws_s3_bucket.b["x"]`, `aws_s3_bucket.data.id`,
//! `data.aws_iam_policy_document.admin.json`, `var.x`, `local.y`).

/// One segment of an address: a name or a bracketed index (quotes kept).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seg {
    Name(String),
    Index(String),
}

/// Split an address / traversal into name and index segments.
pub fn segments(s: &str) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !cur.is_empty() {
                    out.push(Seg::Name(std::mem::take(&mut cur)));
                }
            }
            '[' => {
                if !cur.is_empty() {
                    out.push(Seg::Name(std::mem::take(&mut cur)));
                }
                let mut idx = String::new();
                let mut in_str = false;
                let mut escaped = false;
                for d in chars.by_ref() {
                    if in_str {
                        idx.push(d);
                        if escaped {
                            escaped = false;
                        } else if d == '\\' {
                            escaped = true;
                        } else if d == '"' {
                            in_str = false;
                        }
                        continue;
                    }
                    match d {
                        ']' => break,
                        '"' => {
                            in_str = true;
                            idx.push(d);
                        }
                        _ => idx.push(d),
                    }
                }
                out.push(Seg::Index(idx));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(Seg::Name(cur));
    }
    out
}

/// An index segment as an instance key: `"a"` → `a`, `0` → `0`.
pub fn index_key(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        serde_json::from_str::<String>(t).unwrap_or_else(|_| t[1..t.len() - 1].to_string())
    } else {
        t.to_string()
    }
}

/// `module.a[0].module.b["k"]` → `module.a.module.b` (instance keys dropped;
/// the plan's `configuration` section is per module *call*, not instance).
pub fn strip_keys(addr: &str) -> String {
    segments(addr)
        .into_iter()
        .filter_map(|s| match s {
            Seg::Name(n) => Some(n),
            Seg::Index(_) => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The module part of a resource address: `module.a[0].aws_s3_bucket.b` →
/// `module.a[0]` (keys kept), `aws_s3_bucket.b` → `""`.
pub fn parent_module(module_addr: &str) -> Option<String> {
    if module_addr.is_empty() {
        return None;
    }
    // Drop the last `module.<name>[idx]?` group.
    let segs = segments(module_addr);
    let mut groups: Vec<String> = Vec::new();
    let mut i = 0;
    while i < segs.len() {
        let mut g = String::new();
        if let (Some(Seg::Name(m)), Some(Seg::Name(n))) = (segs.get(i), segs.get(i + 1)) {
            g.push_str(m);
            g.push('.');
            g.push_str(n);
            i += 2;
            if let Some(Seg::Index(ix)) = segs.get(i) {
                g.push('[');
                g.push_str(ix);
                g.push(']');
                i += 1;
            }
        } else {
            i += 1;
        }
        groups.push(g);
    }
    groups.pop();
    Some(groups.join("."))
}

/// What a reference in `configuration...expressions.<attr>.references`
/// points at. References are relative to the module the expression is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ref {
    Var(String),
    Local(String),
    /// A managed resource (`aws_s3_bucket.b`) or data source
    /// (`data.aws_iam_policy_document.p`), optionally an instance key and
    /// the first attribute after it.
    Resource {
        local: String,
        key: Option<String>,
        attr: Option<String>,
    },
    Module(String),
    /// `each.*`, `count.*`, `path.*`, `self`, `terraform.*`, ...
    Other,
}

const IMPLICIT: &[&str] = &["each", "count", "path", "self", "terraform"];

pub fn classify(r: &str) -> Ref {
    let segs = segments(r);
    let name = |i: usize| match segs.get(i) {
        Some(Seg::Name(n)) => Some(n.as_str()),
        _ => None,
    };
    let tail = |i: usize| -> (Option<String>, Option<String>) {
        match segs.get(i) {
            Some(Seg::Index(ix)) => (Some(index_key(ix)), name(i + 1).map(str::to_string)),
            Some(Seg::Name(n)) => (None, Some(n.clone())),
            None => (None, None),
        }
    };
    match (name(0), name(1)) {
        (Some("var"), Some(n)) => Ref::Var(n.into()),
        (Some("local"), Some(n)) => Ref::Local(n.into()),
        (Some("module"), Some(n)) => Ref::Module(n.into()),
        (Some("data"), Some(t)) => match name(2) {
            Some(n) => {
                let (key, attr) = tail(3);
                Ref::Resource {
                    local: format!("data.{t}.{n}"),
                    key,
                    attr,
                }
            }
            None => Ref::Other,
        },
        (Some(root), Some(n)) if !IMPLICIT.contains(&root) => {
            let (key, attr) = tail(2);
            Ref::Resource {
                local: format!("{root}.{n}"),
                key,
                attr,
            }
        }
        _ => Ref::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(
            segments(r#"module.a[0].aws_s3_bucket.b["x.y"]"#),
            vec![
                Seg::Name("module".into()),
                Seg::Name("a".into()),
                Seg::Index("0".into()),
                Seg::Name("aws_s3_bucket".into()),
                Seg::Name("b".into()),
                Seg::Index("\"x.y\"".into()),
            ]
        );
        assert_eq!(
            strip_keys(r#"module.a[0].module.b["k"]"#),
            "module.a.module.b"
        );
        assert_eq!(
            parent_module(r#"module.a[0].module.b["k"]"#).as_deref(),
            Some("module.a[0]")
        );
        assert_eq!(parent_module("module.a").as_deref(), Some(""));
        assert_eq!(parent_module(""), None);
        assert_eq!(
            classify("aws_s3_bucket.data.id"),
            Ref::Resource {
                local: "aws_s3_bucket.data".into(),
                key: None,
                attr: Some("id".into())
            }
        );
        assert_eq!(
            classify(r#"aws_s3_bucket.b["a"].bucket"#),
            Ref::Resource {
                local: "aws_s3_bucket.b".into(),
                key: Some("a".into()),
                attr: Some("bucket".into())
            }
        );
        assert_eq!(
            classify("data.aws_iam_policy_document.admin.json"),
            Ref::Resource {
                local: "data.aws_iam_policy_document.admin".into(),
                key: None,
                attr: Some("json".into())
            }
        );
        assert_eq!(classify("var.x"), Ref::Var("x".into()));
        assert_eq!(classify("local.y"), Ref::Local("y".into()));
        assert_eq!(classify("each.value"), Ref::Other);
        assert_eq!(classify("path.module"), Ref::Other);
    }
}
