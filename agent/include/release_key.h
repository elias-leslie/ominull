#ifndef OMINULL_RELEASE_KEY_H
#define OMINULL_RELEASE_KEY_H

/*
 * The Ominull release signing key, pinned into every agent at build time.
 *
 * Trust deliberately does not route through the hub. An agent verifies a
 * package against this key, so a hub that has been compromised - or an
 * attacker on the plain-HTTP LAN path between agent and hub - can serve any
 * bytes it likes and no agent will install them. That is the whole point of
 * pinning it here rather than fetching it: a digest served by the same party
 * that serves the package proves only that the file arrived intact.
 *
 * Public key material, safe to publish. The private half lives in the
 * operations vault and never touches this repo, the hub, or CI.
 *
 * Scheme: ECDSA P-256 over SHA-256, DER-encoded detached signature.
 * Chosen because every platform can verify it with what it already ships -
 * the openssl CLI on Linux and BCrypt CNG on Windows - so signature
 * verification adds no runtime dependency to any agent.
 *
 * Rotation: ship the replacement key in a release signed by the outgoing key,
 * let the fleet converge, then retire the old one.
 */

/* SubjectPublicKeyInfo, PEM. Used by the portable release verifier. */
#define OMINULL_RELEASE_PUBKEY_PEM \
    "-----BEGIN PUBLIC KEY-----\n" \
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUczKMOE8yfDzAWxOC6WPJiSTz/Oo\n" \
    "j/YnhRtusQqVxGVFFgcfxN1KqkCaLO2ZoYokeanZyJXzmJPzbq8woDaXfg==\n" \
    "-----END PUBLIC KEY-----\n"

/*
 * The same key as the raw curve point, X then Y, 32 bytes each. This is the
 * form BCryptImportKeyPair wants inside a BCRYPT_ECCKEY_BLOB; the leading
 * 0x04 uncompressed-point marker is not part of that blob and is omitted.
 */
/*
 * Only the agent that verifies with BCrypt needs the raw form, and an unused
 * static const is a warning under -Wall -Wextra, which the build treats as a
 * defect. Define OMINULL_NEED_PUBKEY_XY before including this to pull it in.
 */
#ifdef OMINULL_NEED_PUBKEY_XY
#define OMINULL_RELEASE_PUBKEY_XY_LEN 64
static const unsigned char OMINULL_RELEASE_PUBKEY_XY[OMINULL_RELEASE_PUBKEY_XY_LEN] = {
    0x51, 0xcc, 0xca, 0x30, 0xe1, 0x3c, 0xc9, 0xf0,
    0xf3, 0x01, 0x6c, 0x4e, 0x0b, 0xa5, 0x8f, 0x26,
    0x24, 0x93, 0xcf, 0xf3, 0xa8, 0x8f, 0xf6, 0x27,
    0x85, 0x1b, 0x6e, 0xb1, 0x0a, 0x95, 0xc4, 0x65,
    0x45, 0x16, 0x07, 0x1f, 0xc4, 0xdd, 0x4a, 0xaa,
    0x40, 0x9a, 0x2c, 0xed, 0x99, 0xa1, 0x8a, 0x24,
    0x79, 0xa9, 0xd9, 0xc8, 0x95, 0xf3, 0x98, 0x93,
    0xf3, 0x6e, 0xaf, 0x30, 0xa0, 0x36, 0x97, 0x7e,
};
#endif /* OMINULL_NEED_PUBKEY_XY */

#endif /* OMINULL_RELEASE_KEY_H */
