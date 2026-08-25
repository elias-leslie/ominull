#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
CERT_DIR="$ROOT_DIR/certs"

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/testcert.pfx" ]]; then
    echo "[*] Generating self-signed Authenticode test certificate..."
    openssl req -x509 -newkey rsa:2048 \
      -keyout "$CERT_DIR/testcert.key" \
      -out "$CERT_DIR/testcert.cer" \
      -days 3650 -nodes \
      -subj "/CN=WfpSentinelTest" \
      -addext "extendedKeyUsage = codeSigning"
    
    openssl pkcs12 -export \
      -out "$CERT_DIR/testcert.pfx" \
      -inkey "$CERT_DIR/testcert.key" \
      -in "$CERT_DIR/testcert.cer" \
      -passout pass:wfpsentinel
fi

echo "[*] Test-signing wfpsentinel.sys with osslsigncode..."
rm -f "$BUILD_DIR/wfpsentinel_signed.sys"
osslsigncode sign \
  -pkcs12 "$CERT_DIR/testcert.pfx" \
  -pass wfpsentinel \
  -n "wfpsentinel" \
  -in "$BUILD_DIR/wfpsentinel.sys" \
  -out "$BUILD_DIR/wfpsentinel_signed.sys"

echo "[+] Verifying digital signature..."
osslsigncode verify "$BUILD_DIR/wfpsentinel_signed.sys" || true
echo "[+] Successfully signed: $BUILD_DIR/wfpsentinel_signed.sys"
