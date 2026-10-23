use super::*;

pub(super) fn encoding(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "jsonencode" => {
            arity(a, 1)?;
            match &a[0].kind {
                Kind::Known(_) => encoded(a[0].clone(), budget),
                _ => Err(a[0].clone()),
            }
        }
        "jsondecode" => {
            arity(a, 1)?;
            if let Kind::Known(Known::Json(inner)) = &a[0].kind {
                return Ok((**inner).clone());
            }
            let s = string(&a[0])?;
            // Parser scratch, decoded strings/keys and their abstract-value copies.
            // Reserve parser and abstract container payload before either tree exists.
            collections::admit::<[u8; JSON_COLLECTION_BYTES_PER_INPUT_BYTE]>(s.len(), budget)?;
            let maximum = (s.len() as u64)
                .checked_mul(4)
                .ok_or_else(|| Value::limit(budget.text_refused().to_string()))?;
            budget
                .admit_text(maximum)
                .map_err(|e| Value::limit(e.to_string()))?;
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(j) => Ok(from_json(&j, &a[0].prov)),
                Err(e) => Err(Value::error(format!("jsondecode: {e}"))),
            }
        }
        _ => networking(name, a, budget),
    }
}

pub(super) const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(super) fn b64decode(s: &str, budget: &InputBudget) -> Result<Option<Vec<u8>>, Value> {
    budget
        .admit_text(s.len() as u64)
        .map_err(|e| Value::limit(e.to_string()))?;
    let mut out = Vec::new();
    out.try_reserve_exact(s.len())
        .map_err(|_| Value::limit(budget.text_refused().to_string()))?;
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let Some(v) = B64.iter().position(|&x| x == ch) else {
            return Ok(None);
        };
        let v = v as u32;
        buf = buf << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits & 0xff) as u8);
        }
    }
    Ok(Some(out))
}

/// Hash raw file bytes without decoding binary files as UTF-8.
pub fn hash_bytes(name: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest;
    let digest = match name {
        "md5" => md5::Md5::digest(bytes).to_vec(),
        "sha1" => sha1::Sha1::digest(bytes).to_vec(),
        "sha256" | "base64sha256" => sha2::Sha256::digest(bytes).to_vec(),
        "sha512" | "base64sha512" => sha2::Sha512::digest(bytes).to_vec(),
        _ => return None,
    };
    Some(if name.starts_with("base64") {
        b64encode(&digest)
    } else {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    })
}

pub fn b64encode_budgeted(data: &[u8], budget: &InputBudget) -> Result<Arc<str>, Value> {
    let mut out = Text::new(budget);
    let bytes = data
        .len()
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or_else(|| out.refused())?;
    out.reserve(bytes)?;
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            })?;
        }
    }
    assert_eq!(out.as_str().len(), bytes);
    out.finish()
}

pub fn hash_budgeted(name: &str, bytes: &[u8], budget: &InputBudget) -> R {
    // Digests are fixed size; include encoding temporaries and final string payload.
    budget
        .admit_text(1024)
        .map_err(|e| Value::limit(e.to_string()))?;
    Ok(Value::string(
        hash_bytes(name, bytes).expect("validated hash function"),
    ))
}

/// Admit potential JSON text before exposing a structured encoding to predicates
/// and projections that may materialize it later. Unknown children stay structured.
pub fn encoded(value: Value, budget: &InputBudget) -> R {
    if let Err(stopped) = text::json(&value, budget)
        && let Some(Origin::Limit(message)) = stopped.origin()
    {
        return Err(Value::limit_from(message.clone(), [&value]));
    }
    Ok(Value::json(value.clone()).with_prov(value.prov))
}
