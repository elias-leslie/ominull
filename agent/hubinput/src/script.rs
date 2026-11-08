//! The script_exec offer payload (C: ScriptPayload_Parse, ScriptPayload_Params).

use crate::abi::{ScriptParam, SCRIPT_PARAM_NAME_MAX};
use crate::json::{classify, cstr, decode_string, Known, Reader, Step, VType};
use core::ffi::c_int;

pub struct Fields<'a> {
    pub script_id: &'a mut [u8],
    pub script_version: &'a mut c_int,
    pub script_digest: &'a mut [u8],
    pub interpreter: &'a mut [u8],
    pub source: &'a mut [u8],
    pub source_len: &'a mut usize,
    pub parameters_json: &'a mut [u8],
    pub parameters_len: &'a mut usize,
    pub params: &'a mut [ScriptParam],
    pub param_count: &'a mut usize,
    pub timeout_seconds: &'a mut c_int,
    pub timeout_max: c_int,
    pub max_output_bytes: &'a mut usize,
    pub max_output_min: usize,
    pub max_output_max: usize,
}

fn name_ok(n: &[u8]) -> bool {
    !n.is_empty() && n.len() < SCRIPT_PARAM_NAME_MAX && n.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

/// Digits with an optional minus, at most 18 of them.
pub fn plain_int(v: &[u8]) -> Option<i64> {
    let (neg, digits) = match v.first() {
        Some(b'-') => (true, v.get(1..)?),
        _ => (false, v),
    };
    if digits.is_empty() || digits.len() > 18 {
        return None;
    }
    let mut x = 0i64;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        x = x * 10 + i64::from(c - b'0');
    }
    Some(if neg { -x } else { x })
}

pub fn params(v: &[u8], out: &mut [ScriptParam], count: &mut usize) -> bool {
    *count = 0;
    let Some(mut j) = Reader::begin(v) else { return false };
    let mut n = 0usize;
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        if n >= out.len() {
            return false;
        }
        let (done, rest) = out.split_at_mut(n);
        let Some(e) = rest.first_mut() else { return false };
        if decode_string(m.key, Some(&mut e.name)).is_none() || !name_ok(cstr(&e.name)) {
            return false;
        }
        let name = cstr(&e.name);
        if done.iter().any(|p| cstr(&p.name).eq_ignore_ascii_case(name)) {
            return false;
        }
        e.env_skip = 0;
        match m.vtype {
            VType::Str => {
                if decode_string(m.val, Some(&mut e.value)).is_none() {
                    if decode_string(m.val, None).is_none() {
                        return false;
                    }
                    e.value[0] = 0;
                    e.env_skip = 1;
                }
            }
            VType::Scalar => {
                if m.val.len() >= e.value.len() {
                    e.value[0] = 0;
                    e.env_skip = 1;
                } else {
                    let l = m.val.len();
                    let Some(dst) = e.value.get_mut(..l) else { return false };
                    dst.copy_from_slice(m.val);
                    if let Some(nul) = e.value.get_mut(l) {
                        *nul = 0;
                    }
                }
            }
            VType::Composite => return false,
        }
        n += 1;
    }
    *count = n;
    true
}

fn set0(b: &mut [u8]) -> bool {
    match b.first_mut() {
        Some(x) => {
            *x = 0;
            true
        }
        None => false,
    }
}

pub fn parse(json: &[u8], f: Fields<'_>) -> bool {
    if !(set0(f.script_id) && set0(f.script_digest) && set0(f.source) && set0(f.parameters_json)) {
        return false;
    }
    *f.script_version = 0;
    *f.source_len = 0;
    *f.parameters_len = 0;
    *f.param_count = 0;
    const NAMES: &[&[u8]] = &[
        b"script_id",
        b"script_version",
        b"version",
        b"script_digest",
        b"interpreter",
        b"source",
        b"parameters",
        b"timeout_seconds",
        b"max_output_bytes",
    ];
    let mut seen = [false; 9];
    let mut legacy_version = 0i64;
    let Some(mut j) = Reader::begin(json) else { return false };
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        let idx = match classify(m.key, NAMES) {
            Known::Twin => return false,
            Known::Unknown => continue,
            Known::At(i) => i,
        };
        let Some(slot) = seen.get_mut(idx) else { return false };
        if *slot {
            return false;
        }
        *slot = true;
        let (vt, v) = (m.vtype, m.val);
        let scalar = || if vt == VType::Scalar { plain_int(v) } else { None };
        match idx {
            0 => {
                if vt != VType::Str || decode_string(v, Some(&mut *f.script_id)).is_none() {
                    return false;
                }
            }
            1 | 2 => {
                let Some(x) = scalar().filter(|x| (0..=2_147_483_647).contains(x)) else { return false };
                if idx == 1 {
                    *f.script_version = x as c_int;
                } else {
                    legacy_version = x;
                }
            }
            3 => {
                if vt != VType::Str || decode_string(v, Some(&mut *f.script_digest)).is_none() {
                    return false;
                }
            }
            4 => {
                if vt != VType::Str || decode_string(v, Some(&mut *f.interpreter)).is_none() {
                    return false;
                }
            }
            5 => {
                if vt != VType::Str {
                    return false;
                }
                match decode_string(v, Some(&mut *f.source)) {
                    Some(n) => *f.source_len = n,
                    None => return false,
                }
            }
            6 => {
                if vt != VType::Composite || v.first() != Some(&b'{') || v.len() >= f.parameters_json.len() {
                    return false;
                }
                let l = v.len();
                let Some(dst) = f.parameters_json.get_mut(..l) else { return false };
                dst.copy_from_slice(v);
                if let Some(nul) = f.parameters_json.get_mut(l) {
                    *nul = 0;
                }
                *f.parameters_len = l;
                if !params(v, &mut *f.params, &mut *f.param_count) {
                    return false;
                }
            }
            7 => {
                let Some(x) = scalar() else { return false };
                if x > 0 && x <= i64::from(f.timeout_max) {
                    *f.timeout_seconds = x as c_int;
                }
            }
            _ => {
                let Some(x) = scalar() else { return false };
                if x > 0 && (x as u64) > f.max_output_min as u64 && (x as u64) <= f.max_output_max as u64 {
                    *f.max_output_bytes = x as usize;
                }
            }
        }
    }
    if !seen[1] && seen[2] {
        *f.script_version = legacy_version as c_int;
    }
    *f.source_len > 0
}
