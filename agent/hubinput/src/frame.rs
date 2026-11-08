//! Terminal relay frames and the terminal and screen offer payloads
//! (C: TermFrame_Parse, TermPayload_Parse, Screen_ParsePayloadWindows' reader).

use crate::json::{classify, copy_string, int_long, Known, Reader, Step, VType};
use core::ffi::c_long;

pub struct Frame<'a> {
    pub data: Option<&'a [u8]>,
    pub rows: c_long,
    pub cols: c_long,
}

/// Fills ty (the frame type, NUL-terminated). False on a malformed frame or no type.
pub fn parse_term_frame<'a>(json: &'a [u8], ty: &mut [u8]) -> Option<Frame<'a>> {
    let mut f = Frame { data: None, rows: 0, cols: 0 };
    let mut j = Reader::begin(json)?;
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return None,
            Step::Member(m) => m,
        };
        match m.key {
            b"type" => {
                if m.vtype != VType::Str || !copy_string(m.val, ty) {
                    return None;
                }
            }
            b"data" => {
                if m.vtype == VType::Str {
                    f.data = Some(m.val);
                } else if !(m.vtype == VType::Scalar && m.val == b"null") {
                    return None;
                }
            }
            b"rows" => f.rows = scalar_long(&m).unwrap_or(0),
            b"cols" => f.cols = scalar_long(&m).unwrap_or(0),
            _ => {}
        }
    }
    if ty.first().copied().unwrap_or(0) == 0 {
        return None;
    }
    Some(f)
}

fn scalar_long(m: &crate::json::Member<'_>) -> Option<c_long> {
    if m.vtype != VType::Scalar {
        return None;
    }
    int_long(m.val)
}

/// The offer payload {"session_id","program","connect_token"}: each at most once.
pub fn parse_term_payload(json: &[u8], sid: &mut [u8], prog: &mut [u8], tok: &mut [u8]) -> bool {
    for b in [&mut *sid, &mut *prog, &mut *tok] {
        match b.first_mut() {
            Some(x) => *x = 0,
            None => return false,
        }
    }
    let (mut seen_sid, mut seen_prog, mut seen_tok) = (false, false, false);
    let Some(mut j) = Reader::begin(json) else { return false };
    const KNOWN: &[&[u8]] = &[b"session_id", b"program", b"connect_token"];
    loop {
        let m = match j.next_member() {
            Step::End => return true,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        let (dst, seen): (&mut [u8], &mut bool) = match classify(m.key, KNOWN) {
            Known::Twin => return false,
            Known::Unknown => continue,
            Known::At(0) => (&mut *sid, &mut seen_sid),
            Known::At(1) => (&mut *prog, &mut seen_prog),
            Known::At(_) => (&mut *tok, &mut seen_tok),
        };
        if *seen || m.vtype != VType::Str || !copy_string(m.val, dst) {
            return false;
        }
        *seen = true;
    }
}

pub struct ScreenOut<'a> {
    pub session_id: &'a mut [u8],
    pub mode: &'a mut [u8],
    pub connect_token: &'a mut [u8],
    pub operator_raw: &'a mut [u8],
    pub unattended: &'a mut bool,
    pub ask_first: &'a mut bool,
}

/// The screen offer payload's members; the caller applies the session rules.
pub fn parse_screen_payload(json: &[u8], out: ScreenOut<'_>) -> bool {
    let (mut seen_sid, mut seen_mode, mut seen_tok, mut seen_op) = (false, false, false, false);
    let Some(mut j) = Reader::begin(json) else { return false };
    const KNOWN: &[&[u8]] = &[b"session_id", b"mode", b"connect_token", b"operator", b"unattended", b"ask_first"];
    loop {
        let m = match j.next_member() {
            Step::End => return true,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        let idx = match classify(m.key, KNOWN) {
            Known::Twin => return false,
            Known::Unknown => continue,
            Known::At(i) => i,
        };
        let is_true = m.vtype == VType::Scalar && m.val == b"true";
        let ok = match idx {
            0 => !core::mem::replace(&mut seen_sid, true) && m.vtype == VType::Str && copy_string(m.val, out.session_id),
            1 => !core::mem::replace(&mut seen_mode, true) && m.vtype == VType::Str && copy_string(m.val, out.mode),
            2 => !core::mem::replace(&mut seen_tok, true) && m.vtype == VType::Str && copy_string(m.val, out.connect_token),
            3 => !core::mem::replace(&mut seen_op, true) && m.vtype == VType::Str && copy_string(m.val, out.operator_raw),
            4 => {
                let fresh = !*out.unattended && is_true;
                if fresh {
                    *out.unattended = true;
                }
                fresh
            }
            _ => {
                let fresh = !*out.ask_first && is_true;
                if fresh {
                    *out.ask_first = true;
                }
                fresh
            }
        };
        if !ok {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_fields() {
        let mut ty = [0u8; 16];
        let f = parse_term_frame(br#"{"type":"resize","rows":40,"cols":"x","data":null}"#, &mut ty).unwrap();
        assert_eq!(&ty[..6], b"resize");
        assert_eq!((f.rows, f.cols), (40, 0));
        assert!(f.data.is_none());
        assert!(parse_term_frame(br#"{"rows":1}"#, &mut [0u8; 16]).is_none());
    }

    #[test]
    fn term_payload_refuses_repeats_and_twins() {
        let (mut s, mut p, mut t) = ([0u8; 64], [0u8; 64], [0u8; 128]);
        assert!(parse_term_payload(br#"{"session_id":"s","program":"/bin/sh","connect_token":"t","x":{"program":"y"}}"#, &mut s, &mut p, &mut t));
        assert_eq!(&p[..7], b"/bin/sh");
        assert!(!parse_term_payload(br#"{"program":"a","program":"b"}"#, &mut s, &mut p, &mut t));
        assert!(!parse_term_payload(br#"{"Program":"a"}"#, &mut s, &mut p, &mut t));
    }
}
