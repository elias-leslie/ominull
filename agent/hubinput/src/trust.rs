//! What the hub asks this endpoint to do to itself (C: Trust_Parse* and the
//! address rules in agent_trust.h). Every refusal reason matches the C text,
//! which reaches the hub in the agent's report.

use crate::abi::{ResponseGrant, TrustAction, TrustManifest, TrustRule, TRUST_MAX_ALLOW, TRUST_MAX_CAPS, TRUST_MAX_PAYLOAD, TRUST_MAX_RULES};
use crate::b64::strict_decode;
use crate::json::{cstr, hex_val};
use crate::offers::extract_grant;
use crate::tj::{int, member, member_plain, plain, plain_array, skip_value, value, ws, Mem};
use core::ffi::{c_int, CStr};

pub fn is_ip_literal(s: &[u8]) -> bool {
    if s.is_empty() || s.len() >= 64 {
        return false;
    }
    if !s.iter().all(|&c| c.is_ascii_hexdigit() || c == b'.' || c == b':') {
        return false;
    }
    if !s.contains(&b':') {
        let mut parts = 0;
        for part in s.split(|&c| c == b'.') {
            if part.is_empty() || part.len() > 3 || !part.iter().all(u8::is_ascii_digit) {
                return false;
            }
            let val = part.iter().fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
            if val > 255 {
                return false;
            }
            parts += 1;
        }
        return parts == 4;
    }
    let (mut colons, mut group, mut doubles) = (0, 0, 0);
    for (i, &c) in s.iter().enumerate() {
        if c == b':' {
            colons += 1;
            group = 0;
            if s.get(i + 1) == Some(&b':') {
                doubles += 1;
                if doubles > 1 || s.get(i + 2) == Some(&b':') {
                    return false;
                }
            }
        } else {
            group += 1;
            if c == b'.' || group > 4 {
                return false;
            }
        }
    }
    (2..=7).contains(&colons) && (doubles == 1 || colons == 7)
}

fn hex_prefix(s: &[u8]) -> u32 {
    let mut v = 0u32;
    for &c in s {
        let Some(d) = hex_val(c) else { break };
        v = v.saturating_mul(16).saturating_add(u32::from(d));
    }
    v
}

pub fn is_allow_entry(s: &[u8]) -> bool {
    if s.is_empty() || s.len() >= 64 {
        return false;
    }
    let Some(slash) = s.iter().position(|&c| c == b'/') else { return is_ip_literal(s) };
    if slash == 0 {
        return false;
    }
    let (Some(addr), Some(suffix)) = (s.get(..slash), s.get(slash + 1..)) else { return false };
    if !is_ip_literal(addr) {
        return false;
    }
    let (mut len, mut digits) = (0i32, 0);
    for &c in suffix {
        if !c.is_ascii_digit() {
            return false;
        }
        digits += 1;
        if digits > 3 {
            return false;
        }
        len = len * 10 + i32::from(c - b'0');
    }
    if digits == 0 || (digits > 1 && suffix.first() == Some(&b'0')) {
        return false;
    }
    if !addr.contains(&b':') {
        return (8..=32).contains(&len);
    }
    if !(32..=128).contains(&len) {
        return false;
    }
    let (mut g0, mut g1) = (0u32, 0u32);
    if addr.first() != Some(&b':') {
        g0 = hex_prefix(addr);
        if let Some(c) = addr.iter().position(|&x| x == b':') {
            if addr.get(c + 1) != Some(&b':') {
                g1 = hex_prefix(addr.get(c + 1..).unwrap_or(&[]));
            }
        }
    }
    let global = (g0 & 0xe000) == 0x2000;
    let ula = (g0 & 0xfe00) == 0xfc00;
    if !global && !ula {
        return false;
    }
    !(g0 == 0x2002 || (g0 == 0x2001 && g1 == 0))
}

pub fn public_address(s: &[u8]) -> bool {
    if !is_ip_literal(s) {
        return false;
    }
    if !s.contains(&b':') {
        let mut o = [0u32; 4];
        for (slot, part) in o.iter_mut().zip(s.split(|&c| c == b'.')) {
            *slot = part.iter().fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
        }
        let [a, b, c, _] = o;
        return !(a == 0
            || a == 10
            || a == 127
            || a >= 224
            || (a == 100 && (b & 0xc0) == 64)
            || (a == 169 && b == 254)
            || (a == 172 && (b & 0xf0) == 16)
            || (a == 192 && b == 168)
            || (a == 192 && b == 0 && (c == 0 || c == 2))
            || (a == 198 && (b & 0xfe) == 18)
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113));
    }
    if s.first() == Some(&b':') {
        return false;
    }
    let g = hex_prefix(s);
    let mut g2 = 0;
    if let Some(c) = s.iter().position(|&x| x == b':') {
        if s.get(c + 1) != Some(&b':') {
            g2 = hex_prefix(s.get(c + 1..).unwrap_or(&[]));
        }
    }
    if (g & 0xe000) != 0x2000 {
        return false;
    }
    !(g == 0x2001 && g2 == 0x0db8)
}

pub fn rule_valid(r: &TrustRule) -> bool {
    let service = cstr(&r.service);
    if service.is_empty() || !service.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_') {
        return false;
    }
    if !is_ip_literal(cstr(&r.destination)) {
        return false;
    }
    let proto = cstr(&r.protocol);
    if proto != b"udp" && proto != b"tcp" {
        return false;
    }
    (1..=65535).contains(&r.port)
}

/// Whole list or nothing; the count, or None.
pub fn parse_rules(v: &[u8], out: &mut [TrustRule]) -> Option<usize> {
    let mut p = ws(v, 0);
    if v.get(p) != Some(&b'[') {
        return None;
    }
    p = ws(v, p + 1);
    if v.get(p) == Some(&b']') {
        return Some(0);
    }
    let mut n = 0usize;
    loop {
        let e = skip_value(v, p, 1)?;
        let slot = out.get_mut(n)?;
        let el = v.get(p..e)?;
        let mut r = TrustRule::ZERO;
        if !member_plain(el, b"service", &mut r.service) || !member_plain(el, b"destination", &mut r.destination) || !member_plain(el, b"protocol", &mut r.protocol) {
            return None;
        }
        let port = int(value(el, b"port")?)?;
        if !(1..=65535).contains(&port) {
            return None;
        }
        r.port = port as c_int;
        if !rule_valid(&r) {
            return None;
        }
        *slot = r;
        n += 1;
        p = ws(v, e);
        match v.get(p) {
            Some(b',') => p = ws(v, p + 1),
            Some(b']') => return Some(n),
            _ => return None,
        }
    }
}

pub fn parse_manifest(v: &[u8], m: &mut TrustManifest) -> bool {
    m.have = 0;
    m.tenant_id.fill(0);
    m.endpoint_id.fill(0);
    m.profile.fill(0);
    m.caps = [[0; 24]; TRUST_MAX_CAPS];
    m.cap_count = 0;
    m.seq = 0;
    m.issued_at = 0;
    m.signer_key_id.fill(0);
    m.signature.fill(0);
    if value(v, b"v").and_then(int) != Some(1) {
        return false;
    }
    if !member_plain(v, b"tenant_id", &mut m.tenant_id)
        || !member_plain(v, b"endpoint_id", &mut m.endpoint_id)
        || !member_plain(v, b"profile", &mut m.profile)
        || !member_plain(v, b"signer_key_id", &mut m.signer_key_id)
        || !member_plain(v, b"signature", &mut m.signature)
    {
        return false;
    }
    let Some(seq) = value(v, b"seq").and_then(int) else { return false };
    m.seq = seq;
    let Some(issued) = value(v, b"issued_at").and_then(int) else { return false };
    m.issued_at = issued;
    let Some(cv) = value(v, b"caps") else { return false };
    let mut caps = [[0u8; 64]; TRUST_MAX_CAPS];
    let Some(n) = plain_array(cv, &mut caps) else { return false };
    for (src, dst) in caps.iter().zip(m.caps.iter_mut()).take(n) {
        let text = cstr(src);
        if text.len() >= dst.len() {
            return false;
        }
        let Some(d) = dst.get_mut(..text.len()) else { return false };
        d.copy_from_slice(text);
    }
    m.cap_count = n as c_int;
    m.have = 1;
    true
}

pub fn parse_baselines(payload: &[u8], own: &[u8], a: &mut TrustAction) -> Option<&'static CStr> {
    let v = match member(payload, b"baselines") {
        Mem::Bad => return Some(c"payload unreadable"),
        Mem::Absent => return None,
        Mem::Found(s, e) => payload.get(s..e).unwrap_or(&[]),
    };
    const UNREADABLE: &CStr = c"isolation exceptions unreadable";
    let mut p = ws(v, 0);
    if v.get(p) != Some(&b'[') {
        return Some(UNREADABLE);
    }
    p = ws(v, p + 1);
    if v.get(p) == Some(&b']') {
        return None;
    }
    let mut found = false;
    let mut eps = [[0u8; 64]; 64];
    let mut rules = [TrustRule::ZERO; TRUST_MAX_RULES];
    loop {
        let Some(e) = skip_value(v, p, 1) else { return Some(UNREADABLE) };
        let el = v.get(p..e).unwrap_or(&[]);
        let (Some(ev), Some(rv)) = (value(el, b"endpoints"), value(el, b"rules")) else { return Some(UNREADABLE) };
        let Some(ne) = plain_array(ev, &mut eps) else { return Some(UNREADABLE) };
        let Some(nr) = parse_rules(rv, &mut rules) else { return Some(c"isolation exceptions unreadable or too many") };
        for ep in eps.iter().take(ne) {
            if cstr(ep) != own {
                continue;
            }
            if found {
                return Some(c"isolation exceptions name this host twice");
            }
            found = true;
            if let (Some(dst), Some(src)) = (a.rules.get_mut(..nr), rules.get(..nr)) {
                dst.copy_from_slice(src);
            }
            a.rule_count = nr as c_int;
        }
        p = ws(v, e);
        match v.get(p) {
            Some(b',') => p = ws(v, p + 1),
            Some(b']') => return None,
            _ => return Some(UNREADABLE),
        }
    }
}

pub const OP_ISOLATE: c_int = 1;
pub const OP_RELEASE: c_int = 2;
pub const OP_AUTO_ISOLATE: c_int = 3;
pub const OP_MESH_ON: c_int = 4;
pub const OP_MESH_OFF: c_int = 5;
pub const OP_UPDATE: c_int = 6;

pub fn parse_action(payload: &[u8], kind: &[u8], grant_endpoint: &[u8], own: &[u8], a: &mut TrustAction) -> Option<&'static CStr> {
    a.op = 0;
    a.allow = [[0; 64]; TRUST_MAX_ALLOW];
    a.allow_count = 0;
    a.rules = [TrustRule::ZERO; TRUST_MAX_RULES];
    a.rule_count = 0;
    a.ip.fill(0);
    a.version.fill(0);
    let mut route_buf = [0u8; 64];
    if !member_plain(payload, b"route", &mut route_buf) {
        return Some(c"payload has no readable route");
    }
    let route = cstr(&route_buf);
    let Some(body) = value(payload, b"body") else { return Some(c"payload has no body") };
    let Some(tv) = value(payload, b"targets") else { return Some(c"payload has no targets") };
    let mut targets = [[0u8; 64]; 64];
    let nt = match plain_array(tv, &mut targets) {
        Some(n) if n > 0 => n,
        _ => return Some(c"payload targets unreadable"),
    };
    if member(body, b"\x01") == Mem::Bad {
        return Some(c"payload body unreadable");
    }
    if kind == b"mesh_quarantine" {
        a.op = match route {
            b"/api/v1/mesh/quarantine" => OP_MESH_ON,
            b"/api/v1/mesh/unquarantine" => OP_MESH_OFF,
            _ => return Some(c"mesh grant over a non-mesh route"),
        };
        if !member_plain(body, b"target_ip", &mut a.ip) || !is_ip_literal(cstr(&a.ip)) {
            return Some(c"mesh body has no address");
        }
        let ip = cstr(&a.ip);
        let is_want = |t: &[u8]| t.strip_prefix(b"mesh:") == Some(ip);
        if nt != 1 || !is_want(cstr(&targets[0])) || !is_want(grant_endpoint) {
            return Some(c"mesh grant and body disagree on the address");
        }
        return None;
    }
    let listed = targets.iter().take(nt).any(|t| cstr(t) == own);
    if !listed || grant_endpoint != own {
        return Some(c"grant is for another endpoint");
    }
    let names_self = |ep: &mut [u8; 64]| member_plain(body, b"endpoint_id", ep) && cstr(ep) == own;
    let mut ep = [0u8; 64];
    if kind == b"auto_isolate" {
        if route != b"auto-isolate" {
            return Some(c"auto-isolation key used for something other than isolating");
        }
        if !names_self(&mut ep) || nt != 1 {
            return Some(c"auto-isolation body names another endpoint");
        }
        a.op = OP_AUTO_ISOLATE;
        return parse_baselines(payload, own, a);
    }
    if kind == b"agent_update" {
        if route != b"/api/v1/agents/update" {
            return Some(c"update grant over a non-update route");
        }
        if !member_plain(body, b"version", &mut a.version) {
            return Some(c"update body names no version");
        }
        a.op = OP_UPDATE;
        return None;
    }
    if kind != b"isolation_change" {
        return Some(c"unsupported grant kind");
    }
    let single;
    match route {
        b"/api/v1/endpoints/isolate" => {
            a.op = OP_ISOLATE;
            single = true;
        }
        b"/api/v1/endpoints/isolate-bulk" => {
            a.op = OP_ISOLATE;
            single = false;
        }
        b"/api/v1/endpoints/unisolate" => {
            a.op = OP_RELEASE;
            single = true;
        }
        b"/api/v1/endpoints/unisolate-bulk" => {
            a.op = OP_RELEASE;
            single = false;
        }
        _ => return Some(c"isolation grant over an unknown route"),
    }
    if single && (nt != 1 || !names_self(&mut ep)) {
        return Some(c"isolation body names another endpoint");
    }
    if a.op == OP_ISOLATE {
        match member(body, b"allow_ips") {
            Mem::Bad => return Some(c"isolation body unreadable"),
            Mem::Absent => {}
            Mem::Found(s, e) => {
                let Some(n) = plain_array(body.get(s..e).unwrap_or(&[]), &mut a.allow) else {
                    a.allow_count = -1;
                    return Some(c"isolation allow list unreadable or too long");
                };
                a.allow_count = n as c_int;
                if !a.allow.iter().take(n).all(|e| is_allow_entry(cstr(e))) {
                    return Some(c"isolation allow list holds a non-address or too wide a range");
                }
            }
        }
        return parse_baselines(payload, own, a);
    }
    None
}

/// {"grant":{...},"payload_b64":"..."}.
pub fn read_grant_object(v: &[u8], g: &mut ResponseGrant, payload: &mut [u8]) -> Option<usize> {
    let gv = value(v, b"grant")?;
    let mut b64 = [0u8; (TRUST_MAX_PAYLOAD / 3 + 2) * 4 + 4];
    if !value(v, b"payload_b64").is_some_and(|x| plain(x, &mut b64)) {
        return None;
    }
    if gv.len() >= 2048 {
        return None;
    }
    // The C copy stops reading at a NUL inside an escape.
    let (ok, _) = extract_grant(cstr(gv), g);
    if !ok {
        return None;
    }
    let cap = TRUST_MAX_PAYLOAD.min(payload.len());
    let n = strict_decode(cstr(&b64), payload.get_mut(..cap)?);
    if n == 0 || n >= TRUST_MAX_PAYLOAD {
        return None;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_rules() {
        assert!(is_ip_literal(b"10.0.0.1"));
        assert!(!is_ip_literal(b"256.0.0.1"));
        assert!(!is_ip_literal(b"1.2.3"));
        assert!(is_ip_literal(b"fe80::1"));
        assert!(!is_ip_literal(b"1:::2"));
        assert!(is_allow_entry(b"10.0.0.0/8"));
        assert!(!is_allow_entry(b"10.0.0.0/7"));
        assert!(!is_allow_entry(b"10.0.0.0/08"));
        assert!(is_allow_entry(b"2600::/32"));
        assert!(!is_allow_entry(b"2002::/32"));
        assert!(!is_allow_entry(b"64:ff9b::/96"));
        assert!(public_address(b"8.8.8.8"));
        assert!(!public_address(b"192.168.1.1"));
        assert!(public_address(b"2606:4700::1"));
        assert!(!public_address(b"2001:db8::1"));
    }

}
