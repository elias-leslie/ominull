#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
CERT_DIR="$ROOT_DIR/certs"

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/ominull_testcert.pfx" ]]; then
    echo "[*] Generating self-signed Authenticode test certificate for Ominull..."
    openssl req -x509 -newkey rsa:2048 \
      -keyout "$CERT_DIR/ominull_testcert.key" \
      -out "$CERT_DIR/ominull_testcert.cer" \
      -days 3650 -nodes \
      -subj "/CN=OminullTest" \
      -addext "extendedKeyUsage = codeSigning"
    
    openssl pkcs12 -export \
      -out "$CERT_DIR/ominull_testcert.pfx" \
      -inkey "$CERT_DIR/ominull_testcert.key" \
      -in "$CERT_DIR/ominull_testcert.cer" \
      -passout pass:ominull

    cp -f "$CERT_DIR/ominull_testcert.cer" "$CERT_DIR/testcert.cer"
fi

PFX_FILE="$CERT_DIR/ominull_testcert.pfx"
PFX_PASS="ominull"

echo "[*] Test-signing ominull.sys with osslsigncode..."
rm -f "$BUILD_DIR/ominull_signed.sys"
osslsigncode sign \
  -pkcs12 "$PFX_FILE" \
  -pass "$PFX_PASS" \
  -n "Ominull Kernel Security Driver" \
  -in "$BUILD_DIR/ominull.sys" \
  -out "$BUILD_DIR/ominull_signed.sys"

echo "[+] Verifying digital signature..."
osslsigncode verify "$BUILD_DIR/ominull_signed.sys" || true
echo "[+] Successfully signed: $BUILD_DIR/ominull_signed.sys"
