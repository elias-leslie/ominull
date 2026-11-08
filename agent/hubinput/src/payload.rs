//! Offer payloads other than script_exec (C: Response_ForensicsPayload,
//! ScreenCanonicalFromOffer, TerminalCanonicalFromOffer).

use crate::frame::parse_term_payload;
use crate::json::{classify, copy_string, cstr, decode_string, Known, Reader, Step, VType};
use crate::offers::int64;

pub fn bundle_id_ok(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// Forensic payload; the caller's defaults stay when a member is absent, empty or <= 0.
pub fn forensics(json: &[u8], bundle_id: &mut [u8], profile: &mut [u8], max_bytes: &mut i64, timeout: &mut core::ffi::c_int) -> bool {
    if json.iter().all(|&c| matches!(c, b' ' | b'\t' | b'\n' | b'\r')) {
        return true;
    }
    let Some(mut j) = Reader::begin(json) else { return false };
    const KNOWN: &[&[u8]] = &[b"bundle_id", b"profile", b"max_bytes", b"timeout_seconds"];
    let (mut seen_b, mut seen_p, mut seen_m, mut seen_t) = (false, false, false, false);
    loop {
        let m = match j.next_member() {
            Step::End => return true,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        match classify(m.key, KNOWN) {
            Known::Twin => return false,
            Known::Unknown => {}
            Known::At(0) => {
                let mut tmp = [0u8; 128];
                if seen_b || m.vtype != VType::Str {
                    return false;
                }
                let Some(n) = decode_string(m.val, Some(&mut tmp)) else { return false };
                seen_b = true;
                if n == 0 {
                    continue;
                }
                let text = tmp.get(..n).unwrap_or(&[]);
                if !bundle_id_ok(text) || !put_cstr(bundle_id, text) {
                    return false;
                }
            }
            Known::At(1) => {
                let mut tmp = [0u8; 128];
                if seen_p || m.vtype != VType::Str {
                    return false;
                }
                let Some(n) = decode_string(m.val, Some(&mut tmp)) else { return false };
                seen_p = true;
                if n == 0 {
                    continue;
                }
                if !put_cstr(profile, tmp.get(..n).unwrap_or(&[])) {
                    return false;
                }
            }
            Known::At(2) => {
                let Some(x) = int64(m.vtype, m.val).filter(|_| !seen_m) else { return false };
                seen_m = true;
                if x > 0 {
                    *max_bytes = x;
                }
            }
            Known::At(_) => {
                let Some(x) = int64(m.vtype, m.val).filter(|_| !seen_t) else { return false };
                seen_t = true;
                if x > 0 {
                    *timeout = if x > 86400 { 86400 } else { x as core::ffi::c_int };
                }
            }
        }
    }
}

fn put_cstr(out: &mut [u8], text: &[u8]) -> bool {
    if text.len() >= out.len() {
        return false;
    }
    let (head, tail) = out.split_at_mut(text.len());
    head.copy_from_slice(text);
    if let Some(n) = tail.first_mut() {
        *n = 0;
    }
    true
}

struct Cursor<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl Cursor<'_> {
    fn push(&mut self, bytes: &[u8]) -> bool {
        let end = self.n + bytes.len();
        // Fits with its terminator, or the rebuild fails: never a cut-short digest input.
        if end >= self.out.len() {
            return false;
        }
        let Some(dst) = self.out.get_mut(self.n..end) else { return false };
        dst.copy_from_slice(bytes);
        self.n = end;
        true
    }
    fn finish(self) -> bool {
        match self.out.get_mut(self.n) {
            Some(nul) => {
                *nul = 0;
                self.n > 0
            }
            None => false,
        }
    }
}

/// The bytes the hub digested for a screen_session grant.
pub fn screen_canonical(json: &[u8], out: &mut [u8]) -> bool {
    let mut mode = [0u8; 16];
    let (mut have_mode, mut unattended, mut ask_first) = (false, false, false);
    let Some(mut j) = Reader::begin(json) else { return false };
    const KNOWN: &[&[u8]] = &[b"session_id", b"mode", b"connect_token", b"operator", b"unattended", b"ask_first"];
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        let is_true = m.vtype == VType::Scalar && m.val == b"true";
        match classify(m.key, KNOWN) {
            Known::Twin => return false,
            Known::At(1) => {
                if have_mode || m.vtype != VType::Str || !copy_string(m.val, &mut mode) {
                    return false;
                }
                have_mode = true;
            }
            Known::At(4) => {
                if unattended || !is_true {
                    return false;
                }
                unattended = true;
            }
            Known::At(5) => {
                if ask_first || !is_true {
                    return false;
                }
                ask_first = true;
            }
            _ => {}
        }
    }
    let mode_text = cstr(&mode);
    if !have_mode || (mode_text != b"control" && mode_text != b"view") {
        return false;
    }
    let mut c = Cursor { out, n: 0 };
    c.push(b"{\"mode\":\"")
        && c.push(mode_text)
        && c.push(b"\"")
        && (!unattended || c.push(b",\"unattended\":true"))
        && (!ask_first || c.push(b",\"ask_first\":true"))
        && c.push(b"}")
        && c.finish()
}

/// The bytes the hub digested for a terminal_session grant: the program member's
/// raw JSON string content, unchanged, in {"program":"..."}.
pub fn terminal_canonical(json: &[u8], out: &mut [u8]) -> bool {
    match out.first_mut() {
        Some(x) => *x = 0,
        None => return false,
    }
    let (mut sid, mut prog, mut tok) = ([0u8; 64], [0u8; 64], [0u8; 128]);
    if !parse_term_payload(json, &mut sid, &mut prog, &mut tok) {
        return false;
    }
    let Some(mut j) = Reader::begin(json) else { return false };
    let mut raw: Option<&[u8]> = None;
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        if m.key == b"program" {
            if m.vtype != VType::Str || raw.is_some() {
                return false;
            }
            raw = Some(m.val);
        }
    }
    let Some(raw) = raw else { return false };
    let mut c = Cursor { out, n: 0 };
    c.push(b"{\"program\":\"") && c.push(raw) && c.push(b"\"}") && c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_canonical_is_the_signed_subset() {
        let mut o = [0u8; 64];
        assert!(screen_canonical(br#"{"session_id":"s","mode":"view","operator":"a","ask_first":true}"#, &mut o));
        assert_eq!(cstr(&o), br#"{"mode":"view","ask_first":true}"#);
        assert!(!screen_canonical(br#"{"mode":"view","unattended":false}"#, &mut o));
        assert!(!screen_canonical(br#"{"mode":"both"}"#, &mut o));
    }

    #[test]
    fn terminal_canonical_keeps_the_raw_escapes() {
        let mut o = [0u8; 192];
        assert!(terminal_canonical(br#"{"program":"\/bin\/sh"}"#, &mut o));
        assert_eq!(cstr(&o), br#"{"program":"\/bin\/sh"}"#);
    }

    #[test]
    fn forensics_keeps_defaults() {
        let (mut b, mut p, mut mb, mut t) = ([0u8; 64], [0u8; 32], 7i64, 9i32);
        assert!(forensics(b"  ", &mut b, &mut p, &mut mb, &mut t));
        assert!(forensics(br#"{"bundle_id":"","max_bytes":0,"timeout_seconds":90000}"#, &mut b, &mut p, &mut mb, &mut t));
        assert_eq!((mb, t), (7, 86400));
        assert!(!forensics(br#"{"bundle_id":"../x"}"#, &mut b, &mut p, &mut mb, &mut t));
    }
}
