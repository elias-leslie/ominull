//! The plain-search field readers the update descriptor, enrollment reply and
//! threat list still use (C: ExtractJsonString in linux/main.c and updater.c,
//! ExtractDeviceCredential, ParseAddressList). Same results as the C; a strict
//! reader for these replies is a separate change.

use crate::cert::find;

fn needle<'a>(buf: &'a mut [u8; 64], key: &[u8], tail: &[u8]) -> Option<&'a [u8]> {
    let n = 1 + key.len() + tail.len();
    if n >= buf.len() {
        return None;
    }
    let dst = buf.get_mut(..n)?;
    let (q, rest) = dst.split_first_mut()?;
    *q = b'"';
    let (k, t) = rest.split_at_mut(key.len());
    k.copy_from_slice(key);
    t.copy_from_slice(tail);
    Some(dst)
}

fn copy_until_quote(val: &[u8], out: &mut [u8]) -> bool {
    let cap = out.len();
    if cap == 0 {
        return false;
    }
    let mut i = 0usize;
    while let Some(&c) = val.get(i) {
        if c == b'"' || i >= cap - 1 {
            break;
        }
        if let Some(o) = out.get_mut(i) {
            *o = c;
        }
        i += 1;
    }
    if let Some(o) = out.get_mut(i) {
        *o = 0;
    }
    i > 0
}

/// "key":"value" with nothing between; a long value is cut at the buffer.
pub fn string_flat(json: &[u8], key: &[u8], out: &mut [u8]) -> bool {
    let mut buf = [0u8; 64];
    let Some(pat) = needle(&mut buf, key, b"\":\"") else { return false };
    let Some(p) = find(json, pat) else { return false };
    let Some(val) = json.get(p + pat.len()..) else { return false };
    copy_until_quote(val, out)
}

/// "key": then spaces or tabs, then a string.
pub fn string_spaced(json: &[u8], key: &[u8], out: &mut [u8]) -> bool {
    let mut buf = [0u8; 64];
    let Some(pat) = needle(&mut buf, key, b"\":") else { return false };
    let Some(p) = find(json, pat) else { return false };
    let mut q = p + pat.len();
    while matches!(json.get(q), Some(b' ' | b'\t')) {
        q += 1;
    }
    if json.get(q) != Some(&b'"') {
        return false;
    }
    let Some(val) = json.get(q + 1..) else { return false };
    copy_until_quote(val, out)
}

const CRED: &[u8] = b"\"device_credential\":\"";

pub fn device_credential(json: &[u8], out: &mut [u8]) -> bool {
    let Some(p) = find(json, CRED) else { return false };
    if out.is_empty() {
        return false;
    }
    let Some(val) = json.get(p + CRED.len()..) else { return false };
    let mut n = 0usize;
    while matches!(val.get(n), Some(&c) if c != b'"') && n < out.len() - 1 {
        n += 1;
    }
    if val.get(n) != Some(&b'"') {
        return false;
    }
    let (Some(dst), Some(src)) = (out.get_mut(..n), val.get(..n)) else { return false };
    dst.copy_from_slice(src);
    if let Some(nul) = out.get_mut(n) {
        *nul = 0;
    }
    n == 68 && src.starts_with(b"omd_")
}

/// The tokens of the flat array "key":[...], each handed to take with its
/// NUL-terminated text. A token longer than 63 bytes arrives in pieces, as in C.
pub fn address_list(json: &[u8], key: &[u8], mut take: impl FnMut(&[u8; 64])) {
    let mut buf = [0u8; 64];
    let Some(pat) = needle(&mut buf, key, b"\":[") else { return };
    let Some(start) = find(json, pat) else { return };
    let mut p = start + pat.len();
    while let Some(&c0) = json.get(p) {
        if c0 == b']' {
            break;
        }
        while matches!(json.get(p), Some(b' ' | b',' | b'"' | b'\n' | b'\r')) {
            p += 1;
        }
        if matches!(json.get(p), None | Some(b']')) {
            break;
        }
        let mut ip = [0u8; 64];
        let mut idx = 0usize;
        while let Some(&c) = json.get(p) {
            if matches!(c, b'"' | b']' | b',') || idx >= 63 {
                break;
            }
            if let Some(o) = ip.get_mut(idx) {
                *o = c;
            }
            idx += 1;
            p += 1;
        }
        if ip[0] != 0 {
            take(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::cstr;

    #[test]
    fn flat_and_spaced() {
        let mut o = [0u8; 8];
        assert!(string_flat(br#"{"url":"abc"}"#, b"url", &mut o));
        assert_eq!(cstr(&o), b"abc");
        assert!(!string_flat(br#"{"url": "abc"}"#, b"url", &mut o));
        assert!(string_spaced(br#"{"url": "abc"}"#, b"url", &mut o));
        assert!(string_flat(br#"{"url":"0123456789"}"#, b"url", &mut o));
        assert_eq!(cstr(&o), b"0123456");
        assert!(!string_spaced(br#"{"url":1}"#, b"url", &mut o));
    }

    #[test]
    fn list_tokens() {
        let mut seen = 0;
        address_list(br#"{"t":["1.1.1.1", "2.2.2.2"],"u":["x"]}"#, b"t", |ip| {
            seen += 1;
            assert!(cstr(ip).ends_with(b".1") || cstr(ip).ends_with(b".2"));
        });
        assert_eq!(seen, 2);
    }

    #[test]
    fn credential_shape() {
        let mut o = [0u8; 128];
        let v = [b'a'; 64];
        let mut j = b"{\"device_credential\":\"omd_".to_vec();
        j.extend_from_slice(&v);
        j.extend_from_slice(b"\"}");
        assert!(device_credential(&j, &mut o));
        assert!(!device_credential(br#"{"device_credential":"omd_x"}"#, &mut o));
    }
}
