//! Python built-ins that Checkov's solvers apply to policy operands and
//! configured values: `str()`, `int()` (and Checkov's `force_int`), and
//! `ipaddress.ip_network(..., strict=False)`.
//!
//! Each returns `None` where Python would raise, or where the exact Python
//! result cannot be reproduced (for example `repr` of a non-ASCII string
//! inside a list, which depends on Unicode printability tables).

use serde_json::Value as Json;

/// Python's `repr(float)`: shortest round-trip digits, positional for
/// exponents in -4..16.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("integer exponent");
    if (-4..16).contains(&exp) {
        let s = format!("{f}");
        if s.contains('.') { s } else { format!("{s}.0") }
    } else {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.abs())
    }
}

/// A number as Python holds it after HCL parsing: integral values are `int`.
pub fn number_str(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e16 {
        format!("{}", n as i64)
    } else {
        float_repr(n)
    }
}

/// `repr(str)` for ASCII strings; `None` when non-ASCII characters would
/// need Python's printability tables.
fn str_repr(s: &str) -> Option<String> {
    if !s.is_ascii() {
        return None;
    }
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (' '..='~').contains(&c) => out.push(c),
            c => out.push_str(&format!("\\x{:02x}", c as u32)),
        }
    }
    out.push(quote);
    Some(out)
}

/// Python's `repr` of a JSON value (as a list element or dict value).
pub fn repr(v: &Json) -> Option<String> {
    match v {
        Json::String(s) => str_repr(s),
        Json::Array(items) => {
            let parts: Option<Vec<_>> = items.iter().map(repr).collect();
            Some(format!("[{}]", parts?.join(", ")))
        }
        Json::Object(map) => {
            let parts: Option<Vec<_>> = map
                .iter()
                .map(|(k, v)| Some(format!("{}: {}", str_repr(k)?, repr(v)?)))
                .collect();
            Some(format!("{{{}}}", parts?.join(", ")))
        }
        other => str(other),
    }
}

/// Python's `str()` of a JSON value.
pub fn str(v: &Json) -> Option<String> {
    match v {
        Json::Null => Some("None".into()),
        Json::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        Json::Number(n) if n.is_f64() => Some(float_repr(n.as_f64()?)),
        Json::Number(n) => Some(n.to_string()),
        Json::String(s) => Some(s.clone()),
        _ => repr(v),
    }
}

/// Python's `int(str)`, saturated to the i128 range (wide enough that a
/// saturated result orders the same against any i64).
pub fn int_str(s: &str) -> Option<i128> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let b = digits.as_bytes();
    let ok = !b.is_empty()
        && b[0].is_ascii_digit()
        && b[b.len() - 1].is_ascii_digit()
        && b.iter().all(|c| c.is_ascii_digit() || *c == b'_')
        && !digits.contains("__");
    if !ok {
        return None;
    }
    let mut n: i128 = 0;
    for c in digits.bytes().filter(|c| *c != b'_') {
        n = n.saturating_mul(10).saturating_add((c - b'0') as i128);
    }
    Some(if neg { -n } else { n })
}

/// Checkov's `force_int`: ints (and bools) unchanged, otherwise `int(x)` or
/// `None` if that raises.
pub fn force_int(v: &Json) -> Option<i128> {
    match v {
        Json::Bool(b) => Some(*b as i128),
        Json::Number(n) => match n.as_i64() {
            Some(i) => Some(i as i128),
            None => {
                let f = n.as_f64()?;
                f.is_finite()
                    .then(|| f.trunc().clamp(-1.7e38, 1.7e38) as i128)
            }
        },
        Json::String(s) => int_str(s),
        _ => None,
    }
}

/// An IP network after `ip_network(value, strict=False)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    V4 { first: u32, last: u32 },
    V6 { first: u128, last: u128 },
}

impl Network {
    /// `self.subnet_of(other)` (false across versions).
    pub fn subnet_of(&self, other: &Network) -> bool {
        match (self, other) {
            (Network::V4 { first, last }, Network::V4 { first: f, last: l }) => {
                f <= first && l >= last
            }
            (Network::V6 { first, last }, Network::V6 { first: f, last: l }) => {
                f <= first && l >= last
            }
            _ => false,
        }
    }
}

fn v4_address(s: &str) -> Option<u32> {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut out = 0u32;
    for o in octets {
        if o.is_empty()
            || o.len() > 3
            || !o.bytes().all(|c| c.is_ascii_digit())
            || (o.len() > 1 && o.starts_with('0'))
        {
            return None;
        }
        let n: u32 = o.parse().ok()?;
        if n > 255 {
            return None;
        }
        out = out << 8 | n;
    }
    Some(out)
}

fn v6_address(s: &str) -> Option<u128> {
    if s.is_empty() || s.contains('%') {
        // Scoped addresses compare by scope as well; not reproduced.
        return None;
    }
    let mut parts: Vec<String> = s.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|p| p.contains('.')) {
        let v4 = v4_address(&parts.pop()?)?;
        parts.push(format!("{:x}", v4 >> 16));
        parts.push(format!("{:x}", v4 & 0xFFFF));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let (hi, lo, skipped) = match skip {
        Some(i) => {
            let mut hi = i;
            let mut lo = parts.len() - i - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi != 0 {
                    return None;
                }
            }
            if parts.last().is_some_and(String::is_empty) {
                lo -= 1;
                if lo != 0 {
                    return None;
                }
            }
            let skipped = 8i32 - (hi + lo) as i32;
            if skipped < 1 {
                return None;
            }
            (hi, lo, skipped as usize)
        }
        None => {
            if parts.len() != 8 || parts[0].is_empty() || parts[7].is_empty() {
                return None;
            }
            (8, 0, 0)
        }
    };
    let hextet = |p: &str| -> Option<u128> {
        if p.is_empty() || p.len() > 4 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u128::from_str_radix(p, 16).ok()
    };
    let mut out: u128 = 0;
    for p in &parts[..hi] {
        out = out << 16 | hextet(p)?;
    }
    out = out.checked_shl(16 * skipped as u32).unwrap_or(0);
    for p in &parts[parts.len() - lo..] {
        out = out << 16 | hextet(p)?;
    }
    Some(out)
}

/// A decimal prefix length as `_prefix_from_prefix_string` reads it.
fn prefix_len(s: &str, max: u32) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u128 = s.parse().ok().or(Some(u128::MAX))?;
    (n <= max as u128).then_some(n as u32)
}

/// A contiguous IPv4 netmask, or its inverse (a hostmask).
fn v4_mask(s: &str) -> Option<u32> {
    let ip = v4_address(s)?;
    let contiguous = |ip: u32| {
        let zeros = if ip == 0 { 32 } else { ip.trailing_zeros() };
        let prefix = 32 - zeros;
        let ones = if zeros == 32 { 0 } else { ip >> zeros };
        let all = if prefix == 0 {
            0
        } else {
            u32::MAX >> (32 - prefix)
        };
        (ones == all).then_some(prefix)
    };
    contiguous(ip).or_else(|| contiguous(!ip))
}

fn v4_network(addr: u32, prefix: u32) -> Network {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Network::V4 {
        first: addr & mask,
        last: (addr & mask) | !mask,
    }
}

fn v6_network(addr: u128, prefix: u32) -> Network {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Network::V6 {
        first: addr & mask,
        last: (addr & mask) | !mask,
    }
}

/// `ipaddress.ip_network(value, strict=False)` for a string.
pub fn network_str(s: &str) -> Option<Network> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let v4 = || {
        let addr = v4_address(parts[0])?;
        let prefix = match parts.get(1) {
            None => 32,
            Some(p) => prefix_len(p, 32).or_else(|| v4_mask(p))?,
        };
        Some(v4_network(addr, prefix))
    };
    let v6 = || {
        let addr = v6_address(parts[0])?;
        let prefix = match parts.get(1) {
            None => 128,
            Some(p) => prefix_len(p, 128)?,
        };
        Some(v6_network(addr, prefix))
    };
    v4().or_else(v6)
}

/// `ip_network` of a list element (strings, or ints as addresses).
pub fn network(v: &Json) -> Option<Network> {
    match v {
        Json::String(s) => network_str(s),
        Json::Bool(b) => Some(v4_network(*b as u32, 32)),
        Json::Number(n) => {
            let i = n.as_u64()?;
            Some(match u32::try_from(i) {
                Ok(v4) => v4_network(v4, 32),
                Err(_) => v6_network(i as u128, 128),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_str() {
        assert_eq!(
            str(&json!(["a", 1, true, null, 1.5, {"k": "it's"}])).as_deref(),
            Some(r#"['a', 1, True, None, 1.5, {'k': "it's"}]"#)
        );
        assert_eq!(str(&json!(["é"])), None);
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(1e-5), "1e-05");
    }

    #[test]
    fn python_int() {
        assert_eq!(force_int(&json!(" 1_0 ")), Some(10));
        assert_eq!(force_int(&json!(3.9)), Some(3));
        assert_eq!(force_int(&json!("3.0")), None);
        assert_eq!(
            force_int(&json!("99999999999999999999999999999999999999999")),
            Some(i128::MAX)
        );
    }

    #[test]
    fn ip_networks() {
        let n = |s: &str| network_str(s);
        assert_eq!(
            n("10.1.2.3/8"),
            Some(Network::V4 {
                first: 0x0A00_0000,
                last: 0x0AFF_FFFF
            })
        );
        assert_eq!(n("10.0.0.0/255.0.0.0"), n("10.0.0.0/8"));
        assert_eq!(n("10.0.0.0/0.255.255.255"), n("10.0.0.0/8"));
        assert_eq!(n("10.0.0.0/08"), n("10.0.0.0/8"));
        assert_eq!(n("010.0.0.0/8"), None);
        assert_eq!(
            n("::/0"),
            Some(Network::V6 {
                first: 0,
                last: u128::MAX
            })
        );
        assert_eq!(
            n("::ffff:1.2.3.4"),
            Some(Network::V6 {
                first: 0xffff_0102_0304,
                last: 0xffff_0102_0304
            })
        );
        assert!(n("1::2::3").is_none() && n(":1::2").is_none() && n("fe80::1%eth0").is_none());
        assert!(n("10.0.0.0/8").unwrap().subnet_of(&n("0.0.0.0/0").unwrap()));
    }
}
