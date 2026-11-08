#!/usr/bin/env bash
# Native signing with throwaway keys: nothing happens unless configured, a good
# signer's result verifies, and a bad signer or a tampered file is caught.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${ROOT_DIR}/scripts/lib/native-sign.sh"
# A release that signs nothing natively does not need these tools.
for tool in osslsigncode gpg wixl msiextract; do
    if ! command -v "${tool}" >/dev/null; then
        if [ -n "${OMINULL_AUTHENTICODE_COMMAND:-}${OMINULL_AUTHENTICODE_PFX:-}${OMINULL_DEB_GPG_KEY:-}" ]; then
            echo "[-] Native signing is configured but ${tool} is missing." >&2
            exit 1
        fi
        echo "  [=] Native signing test skipped: ${tool} is not installed and no signer is configured."
        exit 0
    fi
done
work="$(mktemp -d)"
trap 'gpgconf --homedir "${work}/gpg" --kill all 2>/dev/null || true; rm -rf "${work}"' EXIT
cd "${work}"
# The real release's settings must not reach the throwaway one below.
unset OMINULL_AUTHENTICODE_COMMAND OMINULL_AUTHENTICODE_PFX OMINULL_AUTHENTICODE_PASSFILE OMINULL_AUTHENTICODE_TIMESTAMP_URL \
    OMINULL_AUTHENTICODE_CAFILE OMINULL_DEB_GPG_KEY OMINULL_SIGNING_BACKEND OMINULL_SIGNING_KEY OMINULL_SIGNING_COMMAND \
    OMINULL_SIGNING_PASSFILE OMINULL_SIGNING_ROTATE_FROM OMINULL_SIGNING_SESSION OMINULL_DIST_DIR OMINULL_RELEASE_VERSION

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
same() { [ "$(sha256sum <"$1")" = "$2" ]; }

# Real formats: a small PE and a small MSI.
echo 'int main(void){return 0;}' >a.c
x86_64-w64-mingw32-gcc a.c -o a.exe
echo payload >payload.txt
cat >a.wxs <<'XML'
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
 <Product Id="*" Name="t" Language="1033" Version="1.0.0" Manufacturer="t" UpgradeCode="11111111-2222-3333-4444-555555555555">
  <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
  <Media Id="1" Cabinet="a.cab" EmbedCab="yes"/>
  <Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFiles64Folder"><Directory Id="D" Name="t">
   <Component Id="C" Guid="11111111-2222-3333-4444-666666666666" Win64="yes"><File Id="P" Name="payload.txt" Source="payload.txt" KeyPath="yes"/></Component>
  </Directory></Directory></Directory>
  <Feature Id="F" Level="1"><ComponentRef Id="C"/></Feature>
 </Product>
</Wix>
XML
wixl --arch x64 -o a.msi a.wxs
mkdir -p d/DEBIAN d/opt
printf 'Package: t\nVersion: 1.0\nArchitecture: amd64\nMaintainer: t <t@example.invalid>\nDescription: t\n' >d/DEBIAN/control
echo payload >d/opt/payload
dpkg-deb --root-owner-group --build d a.deb >/dev/null

# Not configured: untouched.
for f in a.exe a.msi; do
    before="$(sha256sum <"${f}")"
    native_sign_windows "${f}" | grep -q 'left as built' || fail "${f}: no message when unconfigured"
    same "${f}" "${before}" || fail "${f} changed with no signer"
done
before="$(sha256sum <a.deb)"
native_sign_deb a.deb | grep -q 'left as built' || fail "deb: no message when unconfigured"
same a.deb "${before}" || fail "deb changed with no key"

# A throwaway root and code-signing certificate.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=test-root \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout s.key -out s.csr -subj /CN=test-signer 2>/dev/null
printf 'extendedKeyUsage=codeSigning\nkeyUsage=digitalSignature\n' >ext
openssl x509 -req -in s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out s.crt 2>/dev/null
echo 'throwaway-pass' >pass
openssl pkcs12 -export -inkey s.key -in s.crt -certfile ca.crt -passout file:pass -out s.pfx 2>/dev/null
export OMINULL_AUTHENTICODE_CAFILE="${work}/ca.crt"

# The PFX backend signs both formats, and the result verifies.
export OMINULL_AUTHENTICODE_PFX="${work}/s.pfx" OMINULL_AUTHENTICODE_PASSFILE="${work}/pass"
for f in a.exe a.msi; do
    native_sign_windows "${f}" >/dev/null || fail "${f}: signing failed"
    native_authenticode_verify "${f}" || fail "${f}: does not verify"
done
cp a.msi tampered.msi
printf 'x' | dd of=tampered.msi bs=1 seek=4096 conv=notrunc 2>/dev/null
native_authenticode_verify tampered.msi && fail "a tampered MSI verified"
# The wrong root is refused and the file is left alone.
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 2 -subj /CN=other-root 2>/dev/null
x86_64-w64-mingw32-gcc a.c -o b.exe
before="$(sha256sum <b.exe)"
if (OMINULL_AUTHENTICODE_CAFILE="${work}/other.crt" native_sign_windows b.exe) >/dev/null 2>&1; then fail "a signature from an untrusted root was accepted"; fi
same b.exe "${before}" || fail "a failed signing replaced the file"
# A missing passphrase file stops the release.
if (OMINULL_AUTHENTICODE_PASSFILE="${work}/none" native_sign_windows b.exe) >/dev/null 2>&1; then fail "signing went on without a passphrase file"; fi
unset OMINULL_AUTHENTICODE_PFX OMINULL_AUTHENTICODE_PASSFILE

# The command backend: a working signer, one that fails, one that returns junk.
cat >good.sh <<SH
#!/bin/sh
[ "\$1" = sign ] && exec osslsigncode sign -certs "${work}/s.crt" -key "${work}/s.key" -h sha256 -in "\$2" -out "\$3" >/dev/null
SH
printf '#!/bin/sh\nexit 3\n' >bad.sh
printf '#!/bin/sh\ncp "$2" "$3"\n' >junk.sh
chmod +x good.sh bad.sh junk.sh
x86_64-w64-mingw32-gcc a.c -o c.exe
OMINULL_AUTHENTICODE_COMMAND="${work}/good.sh" native_sign_windows c.exe >/dev/null || fail "command backend failed"
native_authenticode_verify c.exe || fail "command backend result does not verify"
for s in bad junk; do
    if (OMINULL_AUTHENTICODE_COMMAND="${work}/${s}.sh" native_sign_windows b.exe) >/dev/null 2>&1; then fail "${s} signer accepted"; fi
    same b.exe "${before}" || fail "${s} signer replaced the file"
done

# Debian: a throwaway gpg key; dpkg still reads the package.
export GNUPGHOME="${work}/gpg"
mkdir -m 0700 "${GNUPGHOME}"
gpg --batch --quiet --passphrase '' --quick-generate-key 'test <t@example.invalid>' ed25519 sign 1d 2>/dev/null
export OMINULL_DEB_GPG_KEY='t@example.invalid'
native_sign_deb a.deb >/dev/null || fail "deb signing failed"
ar t a.deb | grep -qx _gpgorigin || fail "deb has no origin member"
native_deb_verify a.deb || fail "deb does not verify"
dpkg-deb --info a.deb >/dev/null || fail "dpkg cannot read the signed deb"
dpkg-deb --raw-extract a.deb extracted || fail "dpkg cannot extract the signed deb"
[ "$(cat extracted/opt/payload)" = payload ] || fail "the signed deb lost its contents"
native_sign_deb a.deb >/dev/null || fail "deb re-signing failed"
[ "$(ar t a.deb | grep -c _gpgorigin)" = 1 ] || fail "re-signing stacked origin members"
# Changed contents no longer verify.
mkdir -p t && (cd t && ar x ../a.deb)
echo evil >>t/debian-binary
(cd t && rm -f ../evil.deb && ar q ../evil.deb debian-binary control.tar.* data.tar.* _gpgorigin 2>/dev/null)
native_deb_verify evil.deb && fail "a changed deb verified"
# A deb with no signature does not verify.
dpkg-deb --root-owner-group --build d plain.deb >/dev/null
native_deb_verify plain.deb && fail "an unsigned deb verified"

# The release flow: sign-release.sh in a throwaway tree that pins a throwaway
# release key. Native signatures must be inside what the release key signs.
tree="${work}/tree"
mkdir -p "${tree}/scripts/lib" "${tree}/agent/include" "${tree}/hub/pkg/response" "${tree}/dist"
cp "${ROOT_DIR}/scripts/sign-release.sh" "${tree}/scripts/"
cp "${ROOT_DIR}/scripts/lib/signing-backend.sh" "${ROOT_DIR}/scripts/lib/native-sign.sh" "${tree}/scripts/lib/"
openssl ecparam -name prime256v1 -genkey -noout -out release.key 2>/dev/null
chmod 600 release.key
openssl ec -in release.key -pubout -out release.pub 2>/dev/null
{
    echo '#define OMINULL_RELEASE_PUBKEY_PEM \'
    sed -e 's/^/    "/' -e 's/$/\\n" \\/' release.pub
    echo
    echo 'static const unsigned char OMINULL_RELEASE_PUBKEY_XY[64] = {'
    openssl pkey -pubin -in release.pub -outform DER | tail -c 64 | od -An -v -tx1 | sed -E 's/ ([0-9a-f]{2})/0x\1,/g'
    echo '};'
} >"${tree}/agent/include/release_key.h"
{ printf 'const ReleasePublicKeyPEM = `'; cat release.pub; echo '`'; } >"${tree}/hub/pkg/response/trust.go"
dpkg-deb --root-owner-group --build d "${tree}/dist/ominull-agent_9.9.9_amd64.deb" >/dev/null
dpkg-deb --root-owner-group --build d "${tree}/dist/ominull-hub_9.9.9_amd64.deb" >/dev/null
# An MSI holding a program, built twice: the program signed, then not.
make_program_msi() { # EXE OUT
    sed -e 's|Name="payload.txt" Source="payload.txt"|Name="app.exe" Source="'"$1"'"|' a.wxs >prog.wxs
    wixl --arch x64 -o "$2" prog.wxs
}
x86_64-w64-mingw32-gcc a.c -o unsigned.exe
cp unsigned.exe signed.exe
OMINULL_AUTHENTICODE_COMMAND="${work}/good.sh" native_sign_windows signed.exe >/dev/null
make_program_msi signed.exe "${tree}/dist/ominull-agent-windows-9.9.9.msi"
release_env=(OMINULL_RELEASE_VERSION=9.9.9 OMINULL_SIGNING_KEY="${work}/release.key" OMINULL_AUTHENTICODE_COMMAND="${work}/good.sh")
env "${release_env[@]}" bash "${tree}/scripts/sign-release.sh" >release.log 2>&1 || { cat release.log >&2; fail "sign-release.sh failed with native signing on"; }
for pkg in ominull-agent_9.9.9_amd64.deb ominull-hub_9.9.9_amd64.deb ominull-agent-windows-9.9.9.msi; do
    f="${tree}/dist/${pkg}"
    openssl dgst -sha256 -verify release.pub -signature "${f}.sig" "${f}" >/dev/null 2>&1 || fail "${pkg}: the release signature does not cover the final bytes"
    case "${pkg}" in
        *.deb) native_deb_verify "${f}" || fail "${pkg}: no valid origin signature in the release" ;;
        *.msi) native_authenticode_verify "${f}" || fail "${pkg}: no valid Authenticode signature in the release" ;;
    esac
done
# The endpoint packages bundled in the hub package are the signed ones.
dpkg-deb --raw-extract "${tree}/dist/ominull-hub_9.9.9_amd64.deb" bundled
for pkg in ominull-agent_9.9.9_amd64.deb ominull-agent-windows-9.9.9.msi; do
    cmp -s "bundled/usr/share/ominull/packages/${pkg}" "${tree}/dist/${pkg}" || fail "${pkg}: the hub bundles different bytes"
done
# An unsigned program inside the MSI stops the release.
make_program_msi unsigned.exe "${tree}/dist/ominull-agent-windows-9.9.9.msi"
if env "${release_env[@]}" bash "${tree}/scripts/sign-release.sh" >release.log 2>&1; then fail "a signed MSI with an unsigned program inside passed"; fi
grep -q 'inside ominull-agent-windows' release.log || fail "the refusal does not name the program inside the MSI"
# A half-made setup is refused, not treated as unconfigured.
if (OMINULL_AUTHENTICODE_PASSFILE=pass native_sign_windows b.exe) >/dev/null 2>&1; then fail "a passphrase with no PFX passed"; fi
if (OMINULL_AUTHENTICODE_COMMAND="${work}/good.sh" OMINULL_AUTHENTICODE_TIMESTAMP_URL=http://ts.invalid native_sign_windows b.exe) >/dev/null 2>&1; then
    fail "a command signer with a timestamp URL passed"
fi
# The agent pins the helper's digest, so it must be signed before it is hashed.
sign_line="$(grep -n 'native_sign_windows "${BUILD_DIR}/ominull-screen-helper.exe"' "${ROOT_DIR}/scripts/build-packages.sh" | cut -d: -f1)"
hash_line="$(grep -n 'SCREEN_HELPER_SHA256="$(sha256sum' "${ROOT_DIR}/scripts/build-packages.sh" | cut -d: -f1)"
[ -n "${sign_line}" ] && [ -n "${hash_line}" ] && [ "${sign_line}" -lt "${hash_line}" ] || fail "the screen helper is hashed before it is signed"
# A signer failing stops the release before the release key signs anything.
rm -f "${tree}"/dist/*.sig
env OMINULL_RELEASE_VERSION=9.9.9 OMINULL_SIGNING_KEY="${work}/release.key" OMINULL_AUTHENTICODE_COMMAND="${work}/bad.sh" \
    bash "${tree}/scripts/sign-release.sh" >release.log 2>&1 && fail "sign-release.sh passed with a failing signer"
ls "${tree}"/dist/*.sig >/dev/null 2>&1 && fail "the release key signed after the native signer failed"

[ "${failures}" -eq 0 ] || { echo "${failures} native signing check(s) failed." >&2; exit 1; }
echo "[+] Native signing: unconfigured no-op, Authenticode (PFX, command, bad signers) and Debian origin signatures checked."
