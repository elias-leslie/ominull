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
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE71CpMPEGtyUpx3ZSuvcf+YMiwM1F\n" \
    "0e6k7D05y7jLxXQblk3d7ZirBH3MNJlo7aUbtmlQ2izz/u5wTG2ztJ9TBw==\n" \
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
    0xef, 0x50, 0xa9, 0x30, 0xf1, 0x06, 0xb7, 0x25,
    0x29, 0xc7, 0x76, 0x52, 0xba, 0xf7, 0x1f, 0xf9,
    0x83, 0x22, 0xc0, 0xcd, 0x45, 0xd1, 0xee, 0xa4,
    0xec, 0x3d, 0x39, 0xcb, 0xb8, 0xcb, 0xc5, 0x74,
    0x1b, 0x96, 0x4d, 0xdd, 0xed, 0x98, 0xab, 0x04,
    0x7d, 0xcc, 0x34, 0x99, 0x68, 0xed, 0xa5, 0x1b,
    0xb6, 0x69, 0x50, 0xda, 0x2c, 0xf3, 0xfe, 0xee,
    0x70, 0x4c, 0x6d, 0xb3, 0xb4, 0x9f, 0x53, 0x07,
};
#endif /* OMINULL_NEED_PUBKEY_XY */

#endif /* OMINULL_RELEASE_KEY_H */
