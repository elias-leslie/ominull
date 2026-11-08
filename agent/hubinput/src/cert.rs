//! client_certificate in the heartbeat reply (C: CertRenewal_Field,
//! CertRenewal_DecodePEM). The field reader is the C one's plain search, kept
//! as it is; the hub writes base64 values with no escaping.

use crate::b64::strict_decode;

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

const OBJ: &[u8] = b"\"client_certificate\":{";

/// Copies the base64 value of key; false when absent, too long or not base64.
pub fn field(json: &[u8], key: &[u8], out: &mut [u8]) -> bool {
    if out.len() < 2 {
        return false;
    }
    out[0] = 0;
    let Some(obj) = find(json, OBJ) else { return false };
    let Some(after) = json.get(obj + OBJ.len()..) else { return false };
    let Some(end_rel) = after.iter().position(|&b| b == b'}') else { return false };
    let end = obj + OBJ.len() + end_rel;
    // needle: "<key>":" in a 64-byte buffer, as in C.
    let mut needle = [0u8; 64];
    let n = key.len() + 4;
    if n >= needle.len() {
        return false;
    }
    needle[0] = b'"';
    needle[1..=key.len()].copy_from_slice(key);
    needle[key.len() + 1..n].copy_from_slice(b"\":\"");
    let Some(rest) = json.get(obj..) else { return false };
    let Some(p_rel) = find(rest, &needle[..n]) else { return false };
    let p = obj + p_rel;
    if p > end {
        return false;
    }
    let Some(val) = json.get(p + n..) else { return false };
    let mut i = 0usize;
    while let Some(&c) = val.get(i) {
        if c == b'"' {
            break;
        }
        let ok = c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=');
        if !ok || i + 1 >= out.len() {
            out[0] = 0;
            return false;
        }
        out[i] = c;
        i += 1;
    }
    if val.get(i) != Some(&b'"') || i == 0 {
        out[0] = 0;
        return false;
    }
    out[i] = 0;
    true
}

/// Decodes into out as a NUL-terminated PEM document opening with begin and
/// holding an END line; 0 (and out wiped) when it does not.
pub fn decode_pem(b64: &[u8], begin: &[u8], out: &mut [u8]) -> usize {
    if out.len() < 2 {
        return 0;
    }
    let cap = out.len() - 1;
    let n = strict_decode(b64, &mut out[..cap]);
    if n == 0 {
        return 0;
    }
    out[n] = 0;
    let doc = &out[..n];
    let ok = !doc.contains(&0) && doc.starts_with(begin) && find(doc, b"\n-----END ").is_some();
    if !ok {
        out.fill(0);
        return 0;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_stays_in_the_object() {
        let mut o = [0u8; 32];
        assert!(field(br#"{"client_certificate":{"a":"QUJD"},"b":"x"}"#, b"a", &mut o));
        assert_eq!(&o[..5], b"QUJD\0");
        assert!(!field(br#"{"client_certificate":{"a":"QUJD"},"b":"eA=="}"#, b"b", &mut o));
        assert!(!field(br#"{"client_certificate":{"a":"Q!"}}"#, b"a", &mut o));
        assert!(!field(br#"{"client_certificate":{"a":""}}"#, b"a", &mut o));
    }
}
