//! Digests and signature checks. Audited crates do the mathematics; this file
//! only adapts them to the agent's context struct and inputs.
//!
//! Deliberately stricter than the C it replaces, in ways no genuine signer or
//! hub produces: an Ed25519 S at or above the group order is refused (Go refuses
//! it too), hex is hex digits only (sscanf took a sign, a space or "0x"), and
//! DER must be exact: Windows' reader was laxer, and the openssl command ignored
//! anything past a key's largest signature (72 bytes) in the file.

#![allow(deprecated)] // sha2 0.10's block type is generic-array 0.14

use crate::abi::Sha256Ctx;
use crate::b64::strict_decode;
use crate::cert::find;
use crate::json::hex_val;
use ed25519_dalek::Verifier as _;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::digest::generic_array::GenericArray;

const H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

fn block(state: &mut [u32; 8], b: &[u8]) {
    if b.len() == 64 {
        sha2::compress256(state, core::slice::from_ref(GenericArray::from_slice(b)));
    }
}

pub fn sha256_init(c: &mut Sha256Ctx) {
    c.state = H0;
    c.count = 0;
    c.buffer = [0; 64];
}

pub fn sha256_update(c: &mut Sha256Ctx, mut data: &[u8]) {
    let mut idx = (c.count & 0x3f) as usize;
    c.count = c.count.wrapping_add(data.len() as u64);
    if idx > 0 && idx + data.len() >= 64 {
        let (fill, rest) = data.split_at(64 - idx);
        if let Some(dst) = c.buffer.get_mut(idx..) {
            dst.copy_from_slice(fill);
        }
        let b = c.buffer;
        block(&mut c.state, &b);
        data = rest;
        idx = 0;
    }
    let mut chunks = data.chunks_exact(64);
    for ch in chunks.by_ref() {
        block(&mut c.state, ch);
    }
    let rem = chunks.remainder();
    if let Some(dst) = c.buffer.get_mut(idx..idx + rem.len()) {
        dst.copy_from_slice(rem);
    }
}

pub fn sha256_final(c: &mut Sha256Ctx, out: &mut [u8; 32]) {
    let bits = c.count.wrapping_mul(8);
    let mut idx = (c.count & 0x3f) as usize;
    if let Some(s) = c.buffer.get_mut(idx) {
        *s = 0x80;
    }
    idx += 1;
    if idx > 56 {
        if let Some(t) = c.buffer.get_mut(idx..) {
            t.fill(0);
        }
        let b = c.buffer;
        block(&mut c.state, &b);
        idx = 0;
    }
    if let Some(t) = c.buffer.get_mut(idx..56) {
        t.fill(0);
    }
    if let Some(t) = c.buffer.get_mut(56..) {
        t.copy_from_slice(&bits.to_be_bytes());
    }
    let b = c.buffer;
    block(&mut c.state, &b);
    for (o, s) in out.chunks_exact_mut(4).zip(c.state.iter()) {
        o.copy_from_slice(&s.to_be_bytes());
    }
}

pub fn sha256_sum(data: &[u8], out: &mut [u8; 32]) {
    let mut c = Sha256Ctx { state: H0, count: 0, buffer: [0; 64] };
    sha256_update(&mut c, data);
    sha256_final(&mut c, out);
}

/// Exactly 2 * out.len() hex digits are read; what follows is not looked at.
pub fn hex_to_bytes(hex: &[u8], out: &mut [u8]) -> bool {
    if hex.len() < out.len() * 2 {
        return false;
    }
    for (o, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        let (Some(&a), Some(&b)) = (pair.first(), pair.get(1)) else { return false };
        let (Some(h), Some(l)) = (hex_val(a), hex_val(b)) else { return false };
        *o = (h << 4) | l;
    }
    true
}

pub fn ed25519_verify(sig: &[u8; 64], msg: &[u8], public: &[u8; 32]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public) else { return false };
    key.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}

fn p256_key(xy: &[u8; 64]) -> Option<p256::ecdsa::VerifyingKey> {
    let mut sec1 = [4u8; 65];
    sec1.get_mut(1..)?.copy_from_slice(xy);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// A DER ECDSA-P256/SHA-256 signature over msg with the raw point xy.
pub fn p256_verify_xy(xy: &[u8; 64], msg: &[u8], der: &[u8]) -> bool {
    let (Some(key), Ok(sig)) = (p256_key(xy), p256::ecdsa::Signature::from_der(der)) else { return false };
    key.verify(msg, &sig).is_ok()
}

/// The same, over a digest the caller already holds (a package too big to keep in memory).
pub fn p256_verify_hash(xy: &[u8; 64], hash: &[u8; 32], der: &[u8]) -> bool {
    let (Some(key), Ok(sig)) = (p256_key(xy), p256::ecdsa::Signature::from_der(der)) else { return false };
    key.verify_prehash(hash, &sig).is_ok()
}

const SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// The raw point in a P-256 SubjectPublicKeyInfo PEM (the release key's form).
pub fn p256_pem_point(pem: &[u8], xy: &mut [u8; 64]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN PUBLIC KEY-----";
    let Some(b) = find(pem, BEGIN) else { return false };
    let Some(body) = pem.get(b + BEGIN.len()..) else { return false };
    let Some(e) = find(body, b"-----END") else { return false };
    let Some(b64) = body.get(..e) else { return false };
    let mut der = [0u8; 92];
    if strict_decode(b64, &mut der) != 91 {
        return false;
    }
    let (head, tail) = der.split_at(27);
    if head != SPKI_PREFIX {
        return false;
    }
    match tail.get(..64) {
        Some(p) => {
            xy.copy_from_slice(p);
            true
        }
        None => false,
    }
}

pub fn p256_verify_pem(pem: &[u8], msg: &[u8], der: &[u8]) -> bool {
    let mut xy = [0u8; 64];
    p256_pem_point(pem, &mut xy) && p256_verify_xy(&xy, msg, der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha256_known_answers_and_streaming() {
        let mut o = [0u8; 32];
        sha256_sum(b"abc", &mut o);
        assert_eq!(hex(&o), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        sha256_sum(b"", &mut o);
        assert_eq!(hex(&o), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut whole = [0u8; 32];
        sha256_sum(&data, &mut whole);
        for split in [1usize, 55, 56, 63, 64, 65, 128, 999] {
            let mut c = Sha256Ctx { state: H0, count: 0, buffer: [0; 64] };
            sha256_update(&mut c, &data[..split]);
            sha256_update(&mut c, &data[split..]);
            sha256_final(&mut c, &mut o);
            assert_eq!(o, whole, "split {split}");
        }
    }

    #[test]
    fn ed25519_rfc8032_test_1() {
        let public = hex_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let mut sig = [0u8; 64];
        assert!(hex_to_bytes(b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", &mut sig));
        assert!(ed25519_verify(&sig, b"", &public));
        assert!(!ed25519_verify(&sig, b"x", &public));
        sig[0] ^= 1;
        assert!(!ed25519_verify(&sig, b"", &public));
    }

    fn hex_32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        assert!(hex_to_bytes(s.as_bytes(), &mut o));
        o
    }

    #[test]
    fn hex_is_digits_only() {
        let mut o = [0u8; 2];
        assert!(hex_to_bytes(b"0aFf", &mut o));
        assert_eq!(o, [0x0a, 0xff]);
        assert!(!hex_to_bytes(b"+a00", &mut o));
        assert!(!hex_to_bytes(b" a00", &mut o));
        assert!(!hex_to_bytes(b"0x00", &mut o));
        assert!(!hex_to_bytes(b"0a0", &mut o));
    }

    #[test]
    fn pem_refuses_other_shapes() {
        let mut xy = [0u8; 64];
        assert!(!p256_pem_point(b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", &mut xy));
    }
}
