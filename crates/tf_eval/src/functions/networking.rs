use super::*;

pub(super) fn networking(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "cidrsubnet" => {
            network_text(budget, a.len())?;
            arity(a, 3)?;
            let (p, bits, n) = (string(&a[0])?, number(&a[1])?, number(&a[2])?);
            cidrsubnet(&p, bits as u32, n as u128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrsubnets" => {
            network_text(budget, a.len())?;
            if a.is_empty() {
                return Err(Value::error("cidrsubnets: missing prefix"));
            }
            let p = string(&a[0])?;
            let bits = collections::try_collect(
                a[1..].iter().map(|x| number(x).map(|n| n as u32)),
                budget,
            )?;
            // The network helper grows a Vec<String> geometrically, up to twice its length.
            collections::admit::<[String; 2]>(bits.len().max(2), budget)?;
            let subnets = cidrsubnets(&p, &bits).map_err(Value::error)?;
            Ok(Value::list(collections::collect(
                subnets.into_iter().map(Value::string),
                budget,
            )?))
        }
        "cidrhost" => {
            network_text(budget, a.len())?;
            arity(a, 2)?;
            let (p, h) = (string(&a[0])?, number(&a[1])?);
            cidrhost(&p, h as i128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrnetmask" => {
            network_text(budget, a.len())?;
            let p = string(one_arg(a)?)?;
            let (_, len, v6) = parse_cidr(&p).map_err(Value::error)?;
            if v6 {
                return Err(Value::error("cidrnetmask: IPv6 not supported"));
            }
            let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            Ok(Value::string(std::net::Ipv4Addr::from(mask).to_string()))
        }
        _ => Err(Value::unknown(Origin::UnsupportedFunction(name.into()))),
    }
}

// ---- CIDR math -------------------------------------------------------------

pub(super) fn parse_cidr(p: &str) -> Result<(u128, u32, bool), String> {
    let (addr, len) = p
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR \"{p}\""))?;
    let len: u32 = len
        .parse()
        .map_err(|_| format!("invalid prefix length in \"{p}\""))?;
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        if len > 32 {
            return Err("prefix length > 32".into());
        }
        Ok((u32::from(v4) as u128, len, false))
    } else if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        if len > 128 {
            return Err("prefix length > 128".into());
        }
        Ok((u128::from(v6), len, true))
    } else {
        Err(format!("invalid IP address in \"{p}\""))
    }
}

pub(super) fn render(addr: u128, v6: bool) -> String {
    if v6 {
        std::net::Ipv6Addr::from(addr).to_string()
    } else {
        std::net::Ipv4Addr::from(addr as u32).to_string()
    }
}

pub(super) fn cidrsubnet(p: &str, newbits: u32, netnum: u128) -> Result<String, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let nl = len + newbits;
    if nl > total {
        return Err(format!(
            "cidrsubnet: insufficient address space to extend prefix of {len} by {newbits}"
        ));
    }
    if newbits < 128 && netnum >= (1u128 << newbits) {
        return Err(format!(
            "cidrsubnet: netnum {netnum} does not fit in {newbits} bits"
        ));
    }
    let host_bits = total - nl;
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    let base = addr & mask & if v6 { !0u128 } else { 0xffff_ffff };
    let sub = if host_bits >= 128 {
        0
    } else {
        netnum << host_bits
    };
    Ok(format!("{}/{}", render(base | sub, v6), nl))
}

pub(super) fn cidrsubnets(p: &str, bits: &[u32]) -> Result<Vec<String>, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    // Allocation starts at the network address and must stay inside the prefix.
    let base = addr & mask;
    let end = base
        + if total - len >= 128 {
            u128::MAX
        } else {
            (1u128 << (total - len)) - 1
        };
    let mut out = Vec::new();
    let mut cur = base;
    for &b in bits {
        let nl = len + b;
        if b == 0 || nl > total {
            return Err("cidrsubnets: not enough space".into());
        }
        let size = 1u128 << (total - nl);
        // align
        if cur % size != 0 {
            cur = (cur / size + 1)
                .checked_mul(size)
                .ok_or("cidrsubnets: not enough remaining address space")?;
        }
        if cur > end || end - cur < size - 1 {
            return Err("cidrsubnets: not enough remaining address space".into());
        }
        out.push(format!("{}/{}", render(cur, v6), nl));
        cur = cur.saturating_add(size);
    }
    Ok(out)
}

pub(super) fn cidrhost(p: &str, h: i128) -> Result<String, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let host_bits = total - len;
    let size: i128 = if host_bits >= 127 {
        i128::MAX
    } else {
        1i128 << host_bits
    };
    if h >= size || h < -size {
        return Err("cidrhost: host number out of range".into());
    }
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    let base = addr & mask;
    let off = if h >= 0 { h } else { size + h } as u128;
    Ok(render(base + off, v6))
}

pub(super) fn network_text(budget: &InputBudget, count: usize) -> Result<(), Value> {
    let bytes = (count as u64)
        .checked_mul(128)
        .and_then(|n| n.checked_add(512))
        .ok_or_else(|| Value::limit(budget.text_refused().to_string()))?;
    budget
        .admit_text(bytes)
        .map_err(|e| Value::limit(e.to_string()))
}
