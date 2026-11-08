//! The second strict reader (C: TJ_* in agent_trust.h), used for everything that
//! changes this host's state. Stricter than json.rs about keys: at every object
//! level read, keys are plain and unique ignoring case.

pub fn ws(s: &[u8], mut p: usize) -> usize {
    while matches!(s.get(p), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        p += 1;
    }
    p
}

pub fn skip_string(s: &[u8], mut p: usize) -> Option<usize> {
    if s.get(p) != Some(&b'"') {
        return None;
    }
    p += 1;
    while let Some(&c) = s.get(p) {
        if c == b'\\' {
            if s.len() - p < 2 {
                return None;
            }
            p += 2;
            continue;
        }
        if c == b'"' {
            return Some(p + 1);
        }
        if c < 0x20 {
            return None;
        }
        p += 1;
    }
    None
}

pub fn skip_value(s: &[u8], p: usize, depth: i32) -> Option<usize> {
    let mut p = ws(s, p);
    if p >= s.len() || depth > 16 {
        return None;
    }
    let c = *s.get(p)?;
    if c == b'"' {
        return skip_string(s, p);
    }
    if c == b'{' || c == b'[' {
        let close = if c == b'{' { b'}' } else { b']' };
        let object = c == b'{';
        p = ws(s, p + 1);
        if s.get(p) == Some(&close) {
            return Some(p + 1);
        }
        loop {
            if object {
                p = skip_string(s, ws(s, p))?;
                p = ws(s, p);
                if s.get(p) != Some(&b':') {
                    return None;
                }
                p += 1;
            }
            p = skip_value(s, p, depth + 1)?;
            p = ws(s, p);
            match s.get(p) {
                Some(b',') => p += 1,
                Some(&x) if x == close => return Some(p + 1),
                _ => return None,
            }
        }
    }
    let start = p;
    while let Some(&d) = s.get(p) {
        if d.is_ascii_alphanumeric() || matches!(d, b'-' | b'+' | b'.') {
            p += 1;
        } else {
            break;
        }
    }
    if p > start {
        Some(p)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mem {
    /// The value's start and end offsets in the object slice.
    Found(usize, usize),
    Absent,
    Bad,
}

pub fn member(obj: &[u8], key: &[u8]) -> Mem {
    let mut p = ws(obj, 0);
    if obj.get(p) != Some(&b'{') {
        return Mem::Bad;
    }
    p = ws(obj, p + 1);
    if obj.get(p) == Some(&b'}') {
        return Mem::Absent;
    }
    let mut keys: [(usize, usize); 48] = [(0, 0); 48];
    let mut nkeys = 0usize;
    let mut found = Mem::Absent;
    loop {
        p = ws(obj, p);
        let Some(ke) = skip_string(obj, p) else { return Mem::Bad };
        let ks = p + 1;
        let klen = ke - 1 - ks;
        let Some(k) = obj.get(ks..ks + klen) else { return Mem::Bad };
        if k.contains(&b'\\') {
            return Mem::Bad;
        }
        for &(s, l) in keys.iter().take(nkeys) {
            if l == klen && obj.get(s..s + l).is_some_and(|o| o.eq_ignore_ascii_case(k)) {
                return Mem::Bad;
            }
        }
        let Some(slot) = keys.get_mut(nkeys) else { return Mem::Bad };
        *slot = (ks, klen);
        nkeys += 1;
        p = ws(obj, ke);
        if obj.get(p) != Some(&b':') {
            return Mem::Bad;
        }
        p = ws(obj, p + 1);
        let Some(ve) = skip_value(obj, p, 1) else { return Mem::Bad };
        if k == key {
            found = Mem::Found(p, ve);
        }
        p = ws(obj, ve);
        match obj.get(p) {
            Some(b',') => p += 1,
            Some(b'}') => return found,
            _ => return Mem::Bad,
        }
    }
}

/// The value of key when present, as a slice of obj.
pub fn value<'a>(obj: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    match member(obj, key) {
        Mem::Found(a, b) => obj.get(a..b),
        _ => None,
    }
}

/// A string with no escapes: its content, which fits cap with a terminator.
pub fn plain_span(v: &[u8], cap: usize) -> Option<&[u8]> {
    if v.first() != Some(&b'"') {
        return None;
    }
    let e = skip_string(v, 0)?;
    let len = e - 2;
    if len + 1 > cap {
        return None;
    }
    let text = v.get(1..1 + len)?;
    if text.contains(&b'\\') {
        return None;
    }
    Some(text)
}

pub fn plain(v: &[u8], out: &mut [u8]) -> bool {
    let Some(text) = plain_span(v, out.len()) else { return false };
    let (head, tail) = out.split_at_mut(text.len());
    head.copy_from_slice(text);
    match tail.first_mut() {
        Some(n) => {
            *n = 0;
            true
        }
        None => false,
    }
}

pub fn member_plain(obj: &[u8], key: &[u8], out: &mut [u8]) -> bool {
    value(obj, key).is_some_and(|v| plain(v, out))
}

/// An array of plain strings; a value opening with null reads as empty.
pub fn plain_array(v: &[u8], out: &mut [[u8; 64]]) -> Option<usize> {
    let mut p = ws(v, 0);
    if v.get(p..p + 4) == Some(b"null") {
        return Some(0);
    }
    if v.get(p) != Some(&b'[') {
        return None;
    }
    p = ws(v, p + 1);
    if v.get(p) == Some(&b']') {
        return Some(0);
    }
    let mut n = 0usize;
    loop {
        p = ws(v, p);
        let e = skip_string(v, p)?;
        let slot = out.get_mut(n)?;
        if !plain(v.get(p..e)?, slot) {
            return None;
        }
        n += 1;
        p = ws(v, e);
        match v.get(p) {
            Some(b',') => p += 1,
            Some(b']') => return Some(n),
            _ => return None,
        }
    }
}

/// An integer at the start of the value; what follows the digits is not read.
pub fn int(v: &[u8]) -> Option<i64> {
    let mut p = ws(v, 0);
    let neg = v.get(p) == Some(&b'-');
    if neg {
        p += 1;
    }
    if !v.get(p)?.is_ascii_digit() {
        return None;
    }
    let mut x = 0i64;
    while let Some(&c) = v.get(p) {
        if !c.is_ascii_digit() {
            break;
        }
        if x > (i64::MAX - 9) / 10 {
            return None;
        }
        x = x * 10 + i64::from(c - b'0');
        p += 1;
    }
    Some(if neg { -x } else { x })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_refuses_twins_and_escapes() {
        assert_eq!(member(br#"{"a":1,"b":2}"#, b"b"), Mem::Found(11, 12));
        assert_eq!(member(br#"{"a":1,"A":2}"#, b"a"), Mem::Bad);
        assert_eq!(member(br#"{"\u0061":1}"#, b"a"), Mem::Bad);
        assert_eq!(member(br#"{}"#, b"a"), Mem::Absent);
        assert_eq!(member(br#"{"a":1"#, b"a"), Mem::Bad);
    }

    #[test]
    fn plain_array_and_int_quirks_match_c() {
        let mut o = [[0u8; 64]; 2];
        assert_eq!(plain_array(b"nullx", &mut o), Some(0));
        assert_eq!(plain_array(br#"["a","b"]"#, &mut o), Some(2));
        assert_eq!(plain_array(br#"["a","b","c"]"#, &mut o), None);
        assert_eq!(plain_array(br#"["a\n"]"#, &mut o), None);
        assert_eq!(int(b" -12abc"), Some(-12));
        assert_eq!(int(b"x"), None);
        assert_eq!(int(b"9223372036854775807"), None);
    }
}
