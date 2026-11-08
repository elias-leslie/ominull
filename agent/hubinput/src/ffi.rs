//! The C ABI (agent/include/hub_input.h). The only unsafe code in the crate: it
//! turns the agent's pointers into slices and hands them to the safe readers.
//!
//! Contract with the C side, the same one the static inline functions had:
//! pointers are valid for the lengths given; strings are NUL-terminated; output
//! buffers are written, never read before being written, and stay untouched
//! where the C left them untouched, so a caller's defaults survive. A NULL input
//! reads as the C function's NULL check did.
#![allow(unsafe_code, clippy::missing_safety_doc)]

use crate::abi::*;
use crate::tj::Mem;
use crate::{b64, cert, crypto, frame, offers, payload, scrape, script, tj, trust};
use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use core::slice;

unsafe fn input<'a>(p: *const c_char, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        slice::from_raw_parts(p.cast::<u8>(), n)
    }
}

unsafe fn text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        None
    } else {
        Some(CStr::from_ptr(p).to_bytes())
    }
}

unsafe fn span<'a>(v: *const c_char, ve: *const c_char) -> &'a [u8] {
    if v.is_null() || ve.is_null() || ve <= v {
        &[]
    } else {
        input(v, ve.offset_from(v) as usize)
    }
}

unsafe fn out<'a>(p: *mut c_char, cap: usize) -> &'a mut [u8] {
    if p.is_null() || cap == 0 {
        &mut []
    } else {
        slice::from_raw_parts_mut(p.cast::<u8>(), cap)
    }
}

/// The agent's view of each shared struct, checked by the header's static
/// asserts and by the tests.
#[no_mangle]
pub extern "C" fn hi_abi_size(which: c_int) -> usize {
    use core::mem::size_of;
    match which {
        0 => size_of::<TermInFrame>(),
        1 => size_of::<ResponseGrant>(),
        2 => size_of::<ResponseJobOffer>(),
        3 => size_of::<ScriptParam>(),
        4 => size_of::<ScriptPayloadFields>(),
        5 => size_of::<TrustRule>(),
        6 => size_of::<TrustManifest>(),
        7 => size_of::<TrustAction>(),
        8 => size_of::<Sha256Ctx>(),
        _ => 0,
    }
}

/* ---- terminal frames ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_term_frame_parse(json: *const c_char, len: usize, f: *mut c_void) -> bool {
    let f = f.cast::<TermInFrame>();
    ptr::write_bytes(f, 0, 1);
    let f = &mut *f;
    let Some(parsed) = frame::parse_term_frame(input(json, len), &mut f.ty) else { return false };
    if let Some(d) = parsed.data {
        f.data = if d.is_empty() {
            // An empty value still points into the message, past its opening quote.
            json.add(empty_offset(input(json, len), d))
        } else {
            d.as_ptr().cast()
        };
        f.data_len = d.len();
    }
    f.rows = parsed.rows;
    f.cols = parsed.cols;
    true
}

fn empty_offset(whole: &[u8], d: &[u8]) -> usize {
    (d.as_ptr() as usize).saturating_sub(whole.as_ptr() as usize)
}

#[no_mangle]
pub unsafe extern "C" fn hi_term_payload_parse(json: *const c_char, sid: *mut c_char, sid_max: usize, prog: *mut c_char, prog_max: usize, tok: *mut c_char, tok_max: usize) -> bool {
    let Some(j) = text(json) else { return false };
    if sid.is_null() || prog.is_null() || tok.is_null() || sid_max == 0 || prog_max == 0 || tok_max == 0 {
        return false;
    }
    frame::parse_term_payload(j, out(sid, sid_max), out(prog, prog_max), out(tok, tok_max))
}

#[no_mangle]
pub unsafe extern "C" fn hi_term_b64_decode(input_p: *const c_char, len: usize, o: *mut u8, max: usize) -> usize {
    b64::term_decode(input(input_p, len), out(o.cast(), max))
}

#[no_mangle]
pub unsafe extern "C" fn hi_screen_payload(
    json: *const c_char,
    sid: *mut c_char,
    sid_max: usize,
    mode: *mut c_char,
    mode_max: usize,
    tok: *mut c_char,
    tok_max: usize,
    op: *mut c_char,
    op_max: usize,
    unattended: *mut bool,
    ask_first: *mut bool,
) -> bool {
    let Some(j) = text(json) else { return false };
    frame::parse_screen_payload(
        j,
        frame::ScreenOut {
            session_id: out(sid, sid_max),
            mode: out(mode, mode_max),
            connect_token: out(tok, tok_max),
            operator_raw: out(op, op_max),
            unattended: &mut *unattended,
            ask_first: &mut *ask_first,
        },
    )
}

/* ---- base64 and the certificate object ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_base64_decode(input_p: *const c_char, len: usize, o: *mut u8, cap: usize) -> usize {
    b64::strict_decode(input(input_p, len), out(o.cast(), cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_cert_field(json: *const c_char, key: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let (Some(j), Some(k)) = (text(json), text(key)) else { return false };
    if o.is_null() || cap < 2 {
        return false;
    }
    cert::field(j, k, out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_cert_decode_pem(b: *const c_char, begin: *const c_char, o: *mut c_char, cap: usize) -> usize {
    let (Some(j), Some(k)) = (text(b), text(begin)) else { return 0 };
    if o.is_null() || cap < 2 {
        return 0;
    }
    cert::decode_pem(j, k, out(o, cap))
}

/* ---- offers and grants ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_extract_grant_n(p: *mut *const c_char, n: usize, grant: *mut c_void) -> bool {
    let grant = grant.cast::<ResponseGrant>();
    ptr::write_bytes(grant, 0, 1);
    let start = *p;
    let (ok, pos) = offers::extract_grant(input(start, n), &mut *grant);
    *p = start.add(pos);
    ok
}

#[no_mangle]
pub unsafe extern "C" fn hi_extract_grant(p: *mut *const c_char, grant: *mut c_void) -> bool {
    match text(*p) {
        Some(s) => hi_extract_grant_n(p, s.len(), grant),
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_read_offer(s: *const c_char, len: usize, offer: *mut c_void) -> bool {
    let offer = offer.cast::<ResponseJobOffer>();
    ptr::write_bytes(offer, 0, 1);
    offers::read_offer(input(s, len), &mut *offer)
}

#[no_mangle]
pub unsafe extern "C" fn hi_parse_offers(json: *const c_char, o: *mut c_void, max: usize) -> c_int {
    let o = o.cast::<ResponseJobOffer>();
    let Some(j) = text(json) else { return 0 };
    if o.is_null() || max == 0 {
        return 0;
    }
    ptr::write_bytes(o, 0, max);
    offers::parse_offers(j, slice::from_raw_parts_mut(o, max)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn hi_forensics_payload(json: *const c_char, bundle: *mut c_char, bundle_cap: usize, profile: *mut c_char, profile_cap: usize, max_bytes: *mut i64, timeout: *mut c_int) -> bool {
    let Some(j) = text(json) else { return false };
    payload::forensics(j, out(bundle, bundle_cap), out(profile, profile_cap), &mut *max_bytes, &mut *timeout)
}

#[no_mangle]
pub unsafe extern "C" fn hi_screen_canonical(json: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let Some(j) = text(json) else { return false };
    !o.is_null() && payload::screen_canonical(j, out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_terminal_canonical(json: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let Some(j) = text(json) else { return false };
    payload::terminal_canonical(j, out(o, cap))
}

/* ---- script_exec ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_script_payload_parse(json: *const c_char, fields: *const c_void) -> bool {
    let Some(j) = text(json) else { return false };
    if fields.is_null() {
        return false;
    }
    let f = &*fields.cast::<ScriptPayloadFields>();
    let params: &mut [ScriptParam] = if f.params.is_null() || f.params_cap == 0 { &mut [] } else { slice::from_raw_parts_mut(f.params, f.params_cap) };
    script::parse(
        j,
        script::Fields {
            script_id: out(f.script_id.cast(), f.script_id_cap),
            script_version: &mut *f.script_version,
            script_digest: out(f.script_digest.cast(), f.script_digest_cap),
            interpreter: out(f.interpreter.cast(), f.interpreter_cap),
            source: out(f.source.cast(), f.source_cap),
            source_len: &mut *f.source_len,
            parameters_json: out(f.parameters_json.cast(), f.parameters_cap),
            parameters_len: &mut *f.parameters_len,
            params,
            param_count: &mut *f.param_count,
            timeout_seconds: &mut *f.timeout_seconds,
            timeout_max: f.timeout_max,
            max_output_bytes: &mut *f.max_output_bytes,
            max_output_min: f.max_output_min,
            max_output_max: f.max_output_max,
        },
    )
}

/* ---- the trust reader ---- */

unsafe fn advance(p: *const c_char, from_p: Option<usize>) -> *const c_char {
    match from_p {
        Some(n) => p.add(n),
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_skip_string(p: *const c_char, end: *const c_char) -> *const c_char {
    advance(p, tj::skip_string(span(p, end), 0))
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_skip_value(p: *const c_char, end: *const c_char, depth: c_int) -> *const c_char {
    advance(p, tj::skip_value(span(p, end), 0, depth))
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_member(obj: *const c_char, end: *const c_char, key: *const c_char, v: *mut *const c_char, ve: *mut *const c_char) -> c_int {
    let Some(k) = text(key) else { return -1 };
    match tj::member(span(obj, end), k) {
        Mem::Found(a, b) => {
            *v = obj.add(a);
            *ve = obj.add(b);
            1
        }
        Mem::Absent => 0,
        Mem::Bad => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_plain(v: *const c_char, ve: *const c_char, o: *mut c_char, cap: usize) -> bool {
    tj::plain(span(v, ve), out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_plain_array(v: *const c_char, ve: *const c_char, o: *mut c_void, cap: c_int) -> c_int {
    let items: &mut [[u8; 64]] = if o.is_null() || cap <= 0 { &mut [] } else { slice::from_raw_parts_mut(o.cast(), cap as usize) };
    match tj::plain_array(span(v, ve), items) {
        Some(n) => n as c_int,
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_tj_int(v: *const c_char, ve: *const c_char, o: *mut i64) -> bool {
    match tj::int(span(v, ve)) {
        Some(x) => {
            *o = x;
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_parse_manifest(v: *const c_char, ve: *const c_char, m: *mut c_void) -> bool {
    let m = m.cast::<TrustManifest>();
    ptr::write_bytes(m, 0, 1);
    trust::parse_manifest(span(v, ve), &mut *m)
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_parse_rules(v: *const c_char, ve: *const c_char, o: *mut c_void, cap: c_int) -> c_int {
    let items: &mut [TrustRule] = if o.is_null() || cap <= 0 { &mut [] } else { slice::from_raw_parts_mut(o.cast(), cap as usize) };
    match trust::parse_rules(span(v, ve), items) {
        Some(n) => n as c_int,
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_rule_valid(r: *const c_void) -> bool {
    trust::rule_valid(&*r.cast::<TrustRule>())
}

fn reason(r: Option<&'static CStr>) -> *const c_char {
    r.map_or(ptr::null(), CStr::as_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_parse_baselines(payload_p: *const c_char, end: *const c_char, own: *const c_char, a: *mut c_void) -> *const c_char {
    let own = text(own).unwrap_or(&[]);
    reason(trust::parse_baselines(span(payload_p, end), own, &mut *a.cast::<TrustAction>()))
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_parse_action(payload_p: *const c_char, len: usize, kind: *const c_char, grant_endpoint: *const c_char, own: *const c_char, a: *mut c_void) -> *const c_char {
    let a = a.cast::<TrustAction>();
    ptr::write_bytes(a, 0, 1);
    let kind = text(kind).unwrap_or(&[]);
    let ge = text(grant_endpoint).unwrap_or(&[]);
    let own = text(own).unwrap_or(&[]);
    reason(trust::parse_action(input(payload_p, len), kind, ge, own, &mut *a))
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_read_grant_object(v: *const c_char, ve: *const c_char, g: *mut c_void, payload_p: *mut u8, plen: *mut usize) -> bool {
    let g = g.cast::<ResponseGrant>();
    ptr::write_bytes(g, 0, 1);
    match trust::read_grant_object(span(v, ve), &mut *g, out(payload_p.cast(), TRUST_MAX_PAYLOAD)) {
        Some(n) => {
            *plen = n;
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_is_ip_literal(s: *const c_char) -> bool {
    text(s).is_some_and(trust::is_ip_literal)
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_is_allow_entry(s: *const c_char) -> bool {
    text(s).is_some_and(trust::is_allow_entry)
}

#[no_mangle]
pub unsafe extern "C" fn hi_trust_public_address(s: *const c_char) -> bool {
    text(s).is_some_and(trust::public_address)
}

/* ---- field scrapes ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_scrape_string_flat(json: *const c_char, key: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let (Some(j), Some(k)) = (text(json), text(key)) else { return false };
    scrape::string_flat(j, k, out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_scrape_string_spaced(json: *const c_char, key: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let (Some(j), Some(k)) = (text(json), text(key)) else { return false };
    scrape::string_spaced(j, k, out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_scrape_device_credential(json: *const c_char, o: *mut c_char, cap: usize) -> bool {
    let Some(j) = text(json) else { return false };
    scrape::device_credential(j, out(o, cap))
}

#[no_mangle]
pub unsafe extern "C" fn hi_scrape_address_list(json: *const c_char, key: *const c_char, take: extern "C" fn(*const c_char, *mut c_void), ctx: *mut c_void) {
    let (Some(j), Some(k)) = (text(json), text(key)) else { return };
    scrape::address_list(j, k, |ip| take(ip.as_ptr().cast(), ctx));
}

/* ---- digests and signatures ---- */

#[no_mangle]
pub unsafe extern "C" fn hi_sha256_init(c: *mut c_void) {
    let c = c.cast::<Sha256Ctx>();
    ptr::write_bytes(c, 0, 1);
    crypto::sha256_init(&mut *c);
}

#[no_mangle]
pub unsafe extern "C" fn hi_sha256_update(c: *mut c_void, data: *const u8, len: usize) {
    crypto::sha256_update(&mut *c.cast::<Sha256Ctx>(), input(data.cast(), len));
}

#[no_mangle]
pub unsafe extern "C" fn hi_sha256_final(c: *mut c_void, hash: *mut u8) {
    crypto::sha256_final(&mut *c.cast::<Sha256Ctx>(), &mut *hash.cast::<[u8; 32]>());
}

#[no_mangle]
pub unsafe extern "C" fn hi_sha256_sum(data: *const u8, len: usize, hash: *mut u8) {
    crypto::sha256_sum(input(data.cast(), len), &mut *hash.cast::<[u8; 32]>());
}

#[no_mangle]
pub unsafe extern "C" fn hi_hex_to_bytes(hex: *const c_char, o: *mut u8, len: usize) -> bool {
    let Some(h) = text(hex) else { return false };
    crypto::hex_to_bytes(h, out(o.cast(), len))
}

#[no_mangle]
pub unsafe extern "C" fn hi_ed25519_verify(sig: *const u8, msg: *const u8, len: usize, public: *const u8) -> bool {
    crypto::ed25519_verify(&*sig.cast::<[u8; 64]>(), input(msg.cast(), len), &*public.cast::<[u8; 32]>())
}

#[no_mangle]
pub unsafe extern "C" fn hi_p256_verify_xy(xy: *const u8, msg: *const c_char, len: usize, der: *const u8, der_len: usize) -> bool {
    if xy.is_null() || msg.is_null() || der.is_null() || der_len == 0 {
        return false;
    }
    crypto::p256_verify_xy(&*xy.cast::<[u8; 64]>(), input(msg, len), input(der.cast(), der_len))
}

#[no_mangle]
pub unsafe extern "C" fn hi_p256_verify_hash(xy: *const u8, hash: *const u8, der: *const u8, der_len: usize) -> bool {
    if xy.is_null() || hash.is_null() || der.is_null() || der_len == 0 {
        return false;
    }
    crypto::p256_verify_hash(&*xy.cast::<[u8; 64]>(), &*hash.cast::<[u8; 32]>(), input(der.cast(), der_len))
}

#[no_mangle]
pub unsafe extern "C" fn hi_p256_verify_pem(pem: *const c_char, msg: *const c_char, len: usize, der: *const u8, der_len: usize) -> bool {
    let Some(p) = text(pem) else { return false };
    if msg.is_null() || der.is_null() || der_len == 0 {
        return false;
    }
    crypto::p256_verify_pem(p, input(msg, len), input(der.cast(), der_len))
}

