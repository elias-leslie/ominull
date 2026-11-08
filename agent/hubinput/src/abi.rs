//! The C structs the agent shares with this library, field for field. The sizes
//! are asserted on both sides: here against the literal C layout, and through
//! hi_abi_size in the differential tests and the header's wrappers.

use core::ffi::{c_char, c_int, c_long};

pub const MAX_PAYLOAD_JSON_LEN: usize = 65536;
pub const TRUST_MAX_ALLOW: usize = 32;
pub const TRUST_MAX_RULES: usize = 64;
pub const TRUST_MAX_CAPS: usize = 12;
pub const TRUST_MAX_ROUTINE_KEYS: usize = 4;
pub const TRUST_MAX_PAYLOAD: usize = 8192;
pub const SCRIPT_PARAM_NAME_MAX: usize = 65;
pub const SCRIPT_PARAM_VALUE_MAX: usize = 2048;

#[repr(C)]
pub struct TermInFrame {
    pub ty: [u8; 16],
    pub data: *const c_char,
    pub data_len: usize,
    pub rows: c_long,
    pub cols: c_long,
}

#[repr(C)]
pub struct ResponseGrant {
    pub version: u32,
    pub grant_id: [u8; 64],
    pub tenant_id: [u8; 64],
    pub endpoint_id: [u8; 64],
    pub action_kind: [u8; 64],
    pub action_digest: [u8; 65],
    pub operator_id: [u8; 64],
    pub response_session_id: [u8; 64],
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: [u8; 65],
    pub job_id: [u8; 64],
    pub signer_key_id: [u8; 65],
    pub signature: [u8; 130],
}

#[repr(C)]
pub struct ResponseJobOffer {
    pub job_id: [u8; 64],
    pub lease_id: [u8; 64],
    pub kind: [u8; 64],
    pub grant: ResponseGrant,
    pub payload_json: [u8; MAX_PAYLOAD_JSON_LEN],
    pub payload_len: usize,
}

#[repr(C)]
pub struct ScriptParam {
    pub name: [u8; SCRIPT_PARAM_NAME_MAX],
    pub value: [u8; SCRIPT_PARAM_VALUE_MAX],
    pub env_skip: u8,
}

#[repr(C)]
pub struct ScriptPayloadFields {
    pub script_id: *mut u8,
    pub script_id_cap: usize,
    pub script_version: *mut c_int,
    pub script_digest: *mut u8,
    pub script_digest_cap: usize,
    pub interpreter: *mut u8,
    pub interpreter_cap: usize,
    pub source: *mut u8,
    pub source_cap: usize,
    pub source_len: *mut usize,
    pub parameters_json: *mut u8,
    pub parameters_cap: usize,
    pub parameters_len: *mut usize,
    pub params: *mut ScriptParam,
    pub params_cap: usize,
    pub param_count: *mut usize,
    pub timeout_seconds: *mut c_int,
    pub timeout_max: c_int,
    pub max_output_bytes: *mut usize,
    pub max_output_min: usize,
    pub max_output_max: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrustRule {
    pub service: [u8; 16],
    pub destination: [u8; 64],
    pub protocol: [u8; 8],
    pub port: c_int,
}

impl TrustRule {
    pub const ZERO: TrustRule = TrustRule { service: [0; 16], destination: [0; 64], protocol: [0; 8], port: 0 };
}

#[repr(C)]
pub struct TrustManifest {
    pub have: u8,
    pub tenant_id: [u8; 64],
    pub endpoint_id: [u8; 64],
    pub profile: [u8; 24],
    pub caps: [[u8; 24]; TRUST_MAX_CAPS],
    pub cap_count: c_int,
    pub seq: i64,
    pub issued_at: i64,
    pub signer_key_id: [u8; 65],
    pub signature: [u8; 129],
}

#[repr(C)]
pub struct TrustRoutineKey {
    pub id: [u8; 17],
    pub xy: [u8; 64],
}

#[repr(C)]
pub struct TrustAction {
    pub op: c_int,
    pub allow: [[u8; 64]; TRUST_MAX_ALLOW],
    pub allow_count: c_int,
    pub rules: [TrustRule; TRUST_MAX_RULES],
    pub rule_count: c_int,
    pub ip: [u8; 64],
    pub version: [u8; 64],
}

#[repr(C)]
pub struct Sha256Ctx {
    pub state: [u32; 8],
    pub count: u64,
    pub buffer: [u8; 64],
}

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<ResponseGrant>() == 800);
    assert!(size_of::<ResponseJobOffer>() == 192 + 800 + MAX_PAYLOAD_JSON_LEN + 8);
    assert!(size_of::<ScriptParam>() == 65 + 2048 + 1);
    assert!(size_of::<TrustRule>() == 92);
    assert!(size_of::<TrustRoutineKey>() == 81);
    assert!(size_of::<Sha256Ctx>() == 104);
};

#[cfg(test)]
mod tests {
    #[test]
    fn manifest_size_is_the_c_layout() {
        // have + 64+64+24 + 12*24 = 441, padded to 444; cap_count 448; two
        // int64 464; 65+129 = 658, padded to 8.
        assert_eq!(core::mem::size_of::<super::TrustManifest>(), 664);
        assert_eq!(core::mem::offset_of!(super::TrustManifest, seq), 448);
    }
}
