//! The identity of a resource instance (CONTEXT.md: *resource instance*).
//!
//! An [`Address`] is the one place that knows how Terraform spells a
//! resource instance: module path, `data.` prefix, type, name and instance
//! key, with the key quoted the way Terraform quotes it. Both front ends
//! (HCL and plan JSON) build resources and computed origins through it, so
//! identity matching never depends on two formatters agreeing by accident.

use std::fmt;
use std::sync::Arc;

use tf_eval::Origin;

use crate::module::Mode;

/// A `count` index or a `for_each` key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InstanceKey {
    /// `[0]`
    Index(u64),
    /// `["key"]`
    Key(Arc<str>),
}

impl InstanceKey {
    /// The key as the model stores it: `0` or `key`.
    pub fn as_str(&self) -> Arc<str> {
        match self {
            InstanceKey::Index(i) => i.to_string().into(),
            InstanceKey::Key(k) => k.clone(),
        }
    }
}

impl fmt::Display for InstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstanceKey::Index(i) => write!(f, "[{i}]"),
            InstanceKey::Key(k) => write!(f, "[{}]", quote(k)),
        }
    }
}

/// Terraform's quoting of a string instance key: `"` with `\\`, `\"`,
/// `\n`, `\r`, `\t` escaped and other control characters as `\uXXXX`.
pub fn quote(key: &str) -> String {
    let mut s = String::with_capacity(key.len() + 2);
    s.push('"');
    for c in key.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if c.is_control() => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    /// Module instance path: `""` for the root, else `module.a` or
    /// `module.a["k"].module.b`.
    pub module: Arc<str>,
    pub mode: Mode,
    pub ty: Arc<str>,
    pub name: Arc<str>,
    pub key: Option<InstanceKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressError(pub String);

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid resource address: {}", self.0)
    }
}
impl std::error::Error for AddressError {}

impl Address {
    pub fn new(
        module: impl Into<Arc<str>>,
        mode: Mode,
        ty: impl Into<Arc<str>>,
        name: impl Into<Arc<str>>,
        key: Option<InstanceKey>,
    ) -> Self {
        Address {
            module: module.into(),
            mode,
            ty: ty.into(),
            name: name.into(),
            key,
        }
    }

    /// Parse `[module.a["k"].]…[data.]type.name[[key]]`.
    pub fn parse(s: &str) -> Result<Address, AddressError> {
        let err = |m: &str| AddressError(format!("{m} in {s:?}"));
        let (module, rest) = split_module(s).map_err(&err)?;
        let (mode, rest) = match rest.strip_prefix("data.") {
            Some(r) => (Mode::Data, r),
            None => (Mode::Managed, rest),
        };
        let (ty, rest) = rest
            .split_once('.')
            .ok_or_else(|| err("missing resource name"))?;
        let (name, key) = match rest.find('[') {
            Some(i) => (&rest[..i], Some(parse_key(&rest[i..]).map_err(&err)?)),
            None => (rest, None),
        };
        if ty.is_empty() || name.is_empty() || name.contains('.') {
            return Err(err("malformed type or name"));
        }
        Ok(Address::new(module, mode, ty, name, key))
    }

    /// Parse a local address (`type.name`, `data.type.name`, with or without
    /// a key) relative to a module instance.
    pub fn parse_local(module: &str, local: &str) -> Result<Address, AddressError> {
        let mut a = Address::parse(local)?;
        if !a.module.is_empty() {
            return Err(AddressError(format!("{local:?} is not a local address")));
        }
        a.module = module.into();
        Ok(a)
    }

    /// The same address without the instance key.
    pub fn base(&self) -> Address {
        Address {
            key: None,
            ..self.clone()
        }
    }

    pub fn with_key(mut self, key: Option<InstanceKey>) -> Address {
        self.key = key;
        self
    }

    /// `type.name` or `data.type.name`: no module path, no key.
    pub fn local(&self) -> String {
        match self.mode {
            Mode::Managed => format!("{}.{}", self.ty, self.name),
            Mode::Data => format!("data.{}.{}", self.ty, self.name),
        }
    }

    /// Module path plus local address, no key: what `Origin::Computed` and
    /// provenance steps carry as the resource.
    pub fn base_string(&self) -> String {
        if self.module.is_empty() {
            self.local()
        } else {
            format!("{}.{}", self.module, self.local())
        }
    }

    /// The instance key as the model stores it.
    pub fn key_str(&self) -> Option<Arc<str>> {
        self.key.as_ref().map(InstanceKey::as_str)
    }

    /// The origin of a provider-computed attribute of this instance.
    pub fn computed(&self, attr: impl Into<Arc<str>>) -> Origin {
        Origin::Computed {
            resource: self.base_string().into(),
            key: self.key_str(),
            attr: attr.into(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base_string())?;
        match &self.key {
            Some(k) => write!(f, "{k}"),
            None => Ok(()),
        }
    }
}

/// Split the leading `module.…` path (which may contain quoted keys with
/// dots inside) from the resource part.
fn split_module(s: &str) -> Result<(&str, &str), &'static str> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut end = 0; // end of the module path, exclusive of the separating dot
    loop {
        if !s[i..].starts_with("module.") {
            break;
        }
        i += "module.".len();
        // module name
        while i < b.len() && b[i] != b'.' && b[i] != b'[' {
            i += 1;
        }
        if i < b.len() && b[i] == b'[' {
            let close = skip_key(s, i)?;
            i = close;
        }
        end = i;
        if i < b.len() && b[i] == b'.' {
            i += 1;
        } else if i == b.len() {
            return Err("address names a module, not a resource");
        } else {
            return Err("unexpected character after module path");
        }
    }
    Ok((&s[..end], &s[i..]))
}

/// From a `[` at `open`, return the index just past the matching `]`.
fn skip_key(s: &str, open: usize) -> Result<usize, &'static str> {
    let b = s.as_bytes();
    let mut i = open + 1;
    if i < b.len() && b[i] == b'"' {
        i += 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => break,
                _ => i += 1,
            }
        }
        i += 1; // closing quote
    } else {
        while i < b.len() && b[i] != b']' {
            i += 1;
        }
    }
    if i < b.len() && b[i] == b']' {
        Ok(i + 1)
    } else {
        Err("unterminated instance key")
    }
}

fn parse_key(s: &str) -> Result<InstanceKey, &'static str> {
    let inner = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or("malformed instance key")?;
    if let Some(q) = inner.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return unescape(q).map(|k| InstanceKey::Key(k.into()));
    }
    inner
        .parse::<u64>()
        .map(InstanceKey::Index)
        .map_err(|_| "instance key is neither an index nor a quoted string")
}

fn unescape(q: &str) -> Result<String, &'static str> {
    let mut out = String::with_capacity(q.len());
    let mut chars = q.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let code = u32::from_str_radix(&hex, 16).map_err(|_| "bad \\u escape")?;
                out.push(char::from_u32(code).ok_or("bad \\u escape")?);
            }
            _ => return Err("bad escape in instance key"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_shape() {
        for s in [
            "aws_s3_bucket.b",
            "data.aws_caller_identity.cur",
            "aws_s3_bucket.b[0]",
            "aws_s3_bucket.b[\"a\"]",
            "module.m.aws_s3_bucket.b",
            "module.m.data.aws_vpc.v[\"x\"]",
            "module.a[\"k.1\"].module.b[2].aws_instance.i[\"q\"]",
            "aws_s3_bucket.b[\"a\\\"b\\\\c\\n\"]",
        ] {
            let a = Address::parse(s).unwrap();
            assert_eq!(a.to_string(), s);
        }
    }

    #[test]
    fn parts_and_derived_strings() {
        let a = Address::parse("module.a[\"k\"].module.b.data.aws_vpc.v[\"x\"]").unwrap();
        assert_eq!(&*a.module, "module.a[\"k\"].module.b");
        assert_eq!(a.mode, Mode::Data);
        assert_eq!((&*a.ty, &*a.name), ("aws_vpc", "v"));
        assert_eq!(a.key, Some(InstanceKey::Key("x".into())));
        assert_eq!(a.key_str().as_deref(), Some("x"));
        assert_eq!(a.local(), "data.aws_vpc.v");
        assert_eq!(a.base_string(), "module.a[\"k\"].module.b.data.aws_vpc.v");
        assert_eq!(a.base().to_string(), a.base_string());
        assert_eq!(
            a.computed("id"),
            Origin::Computed {
                resource: "module.a[\"k\"].module.b.data.aws_vpc.v".into(),
                key: Some("x".into()),
                attr: "id".into()
            }
        );
        let i = Address::parse("aws_instance.i[3]").unwrap();
        assert_eq!(i.key, Some(InstanceKey::Index(3)));
        assert_eq!(i.key_str().as_deref(), Some("3"));
        let l = Address::parse_local("module.m", "data.aws_vpc.v").unwrap();
        assert_eq!(l.to_string(), "module.m.data.aws_vpc.v");
        assert!(Address::parse_local("module.m", "module.x.aws_vpc.v").is_err());
    }

    #[test]
    fn quoting_matches_terraform() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("tab\there"), "\"tab\\there\"");
        assert_eq!(quote("bell\u{7}"), "\"bell\\u0007\"");
        assert_eq!(quote("ünïcode"), "\"ünïcode\"");
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "aws_s3_bucket",
            "module.m",
            "aws_s3_bucket.b[",
            "aws_s3_bucket.b[x]",
            "a.b.c",
        ] {
            assert!(Address::parse(s).is_err(), "{s}");
        }
    }
}
