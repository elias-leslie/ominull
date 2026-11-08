//! Response offers and grants in the heartbeat reply (C: ExtractGrantObjectN,
//! Response_ReadOffer, ParseResponseOffers). Top-level members only, each known
//! member once, strings fully decoded, never truncated.

use crate::abi::{ResponseGrant, ResponseJobOffer, MAX_PAYLOAD_JSON_LEN};
use crate::json::{classify, decode_string, Known, Reader, Step, VType, REPLY_MAX_DEPTH};

/// Response_JsonSpan: the extent of the JSON value at the start of s.
pub fn json_span(s: &[u8]) -> Option<usize> {
    let mut j = Reader::at(s, 0, REPLY_MAX_DEPTH);
    if !j.skip_value(0) {
        return None;
    }
    Some(j.i)
}

/// ParseInt64Field over a scalar: optional minus, digits, nothing else, within i64.
pub fn int64(vt: VType, v: &[u8]) -> Option<i64> {
    if vt != VType::Scalar || v.is_empty() || v.len() >= 24 {
        return None;
    }
    let (neg, digits) = match v.first() {
        Some(b'-') => (true, v.get(1..)?),
        _ => (false, v),
    };
    if digits.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        let d = u64::from(c - b'0');
        if val > (i64::MAX as u64 - d) / 10 {
            return None;
        }
        val = val * 10 + d;
    }
    let x = val as i64;
    Some(if neg { -x } else { x })
}

fn decode_member(vt: VType, v: &[u8], out: &mut [u8]) -> bool {
    vt == VType::Str && decode_string(v, Some(&mut *out)).is_some() && out.first().copied().unwrap_or(0) != 0
}

fn decode_any(vt: VType, v: &[u8], out: &mut [u8]) -> bool {
    vt == VType::Str && decode_string(v, Some(out)).is_some()
}

impl ResponseGrant {
    fn clear(&mut self) {
        self.version = 0;
        self.grant_id.fill(0);
        self.tenant_id.fill(0);
        self.endpoint_id.fill(0);
        self.action_kind.fill(0);
        self.action_digest.fill(0);
        self.operator_id.fill(0);
        self.response_session_id.fill(0);
        self.issued_at = 0;
        self.expires_at = 0;
        self.nonce.fill(0);
        self.job_id.fill(0);
        self.signer_key_id.fill(0);
        self.signature.fill(0);
    }
}

const GRANT_NAMES: &[&[u8]] = &[
    b"version",
    b"grant_id",
    b"tenant_id",
    b"endpoint_id",
    b"action_kind",
    b"action_digest",
    b"operator_id",
    b"response_session_id",
    b"issued_at",
    b"expires_at",
    b"nonce",
    b"job_id",
    b"signer_key_id",
    b"signature",
];

/// ExtractGrantObjectN. Returns whether the grant is good and where the cursor
/// ended: past leading whitespace, and past the object once its members read.
pub fn extract_grant(s: &[u8], grant: &mut ResponseGrant) -> (bool, usize) {
    grant.clear();
    let mut pos = 0usize;
    while matches!(s.get(pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        pos += 1;
    }
    let Some(rest) = s.get(pos..) else { return (false, pos) };
    if rest.first() != Some(&b'{') {
        return (false, pos);
    }
    let Some(span) = json_span(rest) else { return (false, pos) };
    let Some(obj) = rest.get(..span) else { return (false, pos) };
    let Some(mut j) = Reader::begin(obj) else { return (false, pos) };
    let mut seen = [false; 14];
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return (false, pos),
            Step::Member(m) => m,
        };
        let idx = match classify(m.key, GRANT_NAMES) {
            Known::Twin => return (false, pos),
            Known::Unknown => continue,
            Known::At(i) => i,
        };
        let Some(slot) = seen.get_mut(idx) else { return (false, pos) };
        if *slot {
            return (false, pos);
        }
        *slot = true;
        let (vt, v) = (m.vtype, m.val);
        let ok = match idx {
            0 => match int64(vt, v) {
                Some(x) if (0..=0xFFFF_FFFF).contains(&x) => {
                    grant.version = x as u32;
                    true
                }
                _ => false,
            },
            1 => decode_member(vt, v, &mut grant.grant_id),
            2 => decode_any(vt, v, &mut grant.tenant_id),
            3 => decode_member(vt, v, &mut grant.endpoint_id),
            4 => decode_member(vt, v, &mut grant.action_kind),
            5 => decode_member(vt, v, &mut grant.action_digest),
            6 => decode_any(vt, v, &mut grant.operator_id),
            7 => decode_any(vt, v, &mut grant.response_session_id),
            8 => match int64(vt, v) {
                Some(x) => {
                    grant.issued_at = x;
                    true
                }
                None => false,
            },
            9 => match int64(vt, v) {
                Some(x) => {
                    grant.expires_at = x;
                    true
                }
                None => false,
            },
            10 => decode_any(vt, v, &mut grant.nonce),
            11 => decode_any(vt, v, &mut grant.job_id),
            12 => decode_any(vt, v, &mut grant.signer_key_id),
            _ => decode_member(vt, v, &mut grant.signature),
        };
        if !ok {
            return (false, pos);
        }
    }
    pos += span;
    // V2, or V3 which binds the hub job id (an empty one is no V3 grant).
    let good = (grant.version == 2 || grant.version == 3)
        && !(grant.version == 3 && grant.job_id[0] == 0)
        && grant.grant_id[0] != 0
        && grant.endpoint_id[0] != 0
        && grant.action_kind[0] != 0
        && grant.action_digest[0] != 0
        && grant.signature[0] != 0;
    (good, pos)
}

impl ResponseJobOffer {
    fn clear(&mut self) {
        self.job_id.fill(0);
        self.lease_id.fill(0);
        self.kind.fill(0);
        self.grant.clear();
        self.payload_json.fill(0);
        self.payload_len = 0;
    }
}

/// Response_ReadOffer.
pub fn read_offer(s: &[u8], offer: &mut ResponseJobOffer) -> bool {
    offer.clear();
    let Some(mut j) = Reader::begin(s) else { return false };
    let (mut has_job, mut has_lease, mut has_kind, mut has_grant, mut has_payload) = (false, false, false, false, false);
    const KNOWN: &[&[u8]] = &[b"job_id", b"lease_id", b"kind", b"grant", b"payload_json"];
    loop {
        let m = match j.next_member() {
            Step::End => break,
            Step::Bad => return false,
            Step::Member(m) => m,
        };
        match classify(m.key, KNOWN) {
            Known::Twin => return false,
            Known::Unknown => {}
            Known::At(0) => {
                if has_job || !decode_member(m.vtype, m.val, &mut offer.job_id) {
                    return false;
                }
                has_job = true;
            }
            Known::At(1) => {
                if has_lease || !decode_member(m.vtype, m.val, &mut offer.lease_id) {
                    return false;
                }
                has_lease = true;
            }
            Known::At(2) => {
                if has_kind || !decode_member(m.vtype, m.val, &mut offer.kind) {
                    return false;
                }
                has_kind = true;
            }
            Known::At(3) => {
                if has_grant || m.vtype != VType::Composite {
                    return false;
                }
                let (ok, end) = extract_grant(m.val, &mut offer.grant);
                if !ok || end != m.val.len() {
                    return false;
                }
                has_grant = true;
            }
            Known::At(_) => {
                if has_payload {
                    return false;
                }
                has_payload = true;
                if m.vtype == VType::Str {
                    match decode_string(m.val, Some(&mut offer.payload_json)) {
                        Some(n) => offer.payload_len = n,
                        None => return false,
                    }
                } else if m.vtype == VType::Composite && m.val.first() == Some(&b'{') {
                    if m.val.len() >= MAX_PAYLOAD_JSON_LEN {
                        return false;
                    }
                    let Some(dst) = offer.payload_json.get_mut(..m.val.len()) else { return false };
                    dst.copy_from_slice(m.val);
                    if let Some(nul) = offer.payload_json.get_mut(m.val.len()) {
                        *nul = 0;
                    }
                    offer.payload_len = m.val.len();
                } else {
                    return false;
                }
            }
        }
    }
    has_job && has_lease && has_kind && has_grant
}

/// ParseResponseOffers: the reply's top-level response_offers array. A malformed
/// offer is dropped and the rest still read; a malformed reply yields none.
pub fn parse_offers(json: &[u8], out: &mut [ResponseJobOffer]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let Some(mut top) = Reader::begin(json) else { return 0 };
    top.max_depth = REPLY_MAX_DEPTH;
    let mut arr: Option<&[u8]> = None;
    const TOP: &[&[u8]] = &[b"response_offers"];
    loop {
        let m = match top.next_member() {
            Step::End => break,
            Step::Bad => return 0,
            Step::Member(m) => m,
        };
        match classify(m.key, TOP) {
            Known::Twin => return 0,
            Known::Unknown => continue,
            Known::At(_) => {
                if arr.is_some() || m.vtype != VType::Composite || m.val.first() != Some(&b'[') {
                    return 0;
                }
                arr = Some(m.val);
            }
        }
    }
    let Some(arr) = arr else { return 0 };
    let mut a = Reader::at(arr, 1, REPLY_MAX_DEPTH);
    let mut count = 0usize;
    a.skip_ws();
    if a.peek() == Some(b']') {
        return 0;
    }
    while a.i < arr.len() && count < out.len() {
        a.skip_ws();
        let start = a.i;
        if !a.skip_value(1) {
            break;
        }
        if arr.get(start) == Some(&b'{') {
            let (Some(item), Some(slot)) = (arr.get(start..a.i), out.get_mut(count)) else { break };
            if read_offer(item, slot) {
                count += 1;
            }
        }
        a.skip_ws();
        if a.peek() != Some(b',') {
            break;
        }
        a.i += 1;
    }
    count
}
