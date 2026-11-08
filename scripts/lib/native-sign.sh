# shellcheck shell=bash
# Platform-native signing, sourced by build-packages.sh and sign-release.sh.
# It sits under the portable release signature, which stays what agents check:
# native_sign_* runs first, so the portable signature covers the final bytes.
# Each step does nothing and says so unless configured; once configured, any
# failure stops the release, and a file is only replaced after it verifies.
#
# Windows (Authenticode; .exe and .msi). One of:
#   OMINULL_AUTHENTICODE_COMMAND     "CMD sign IN OUT" for a token, HSM or cloud
#                                    signing service; the key never leaves it.
#   OMINULL_AUTHENTICODE_PFX         a PKCS#12 file, with its passphrase in
#   OMINULL_AUTHENTICODE_PASSFILE    a file, read by osslsigncode, never in argv.
# With the PFX: OMINULL_AUTHENTICODE_TIMESTAMP_URL (the CA's RFC 3161 server; keeps
# a signature valid after the certificate expires). A command signer timestamps
# for itself, so naming both is refused.
# Optional: OMINULL_AUTHENTICODE_CAFILE (the roots a result is verified against;
# default the system's, which may hold only TLS roots).
#
# Debian packages: OMINULL_DEB_GPG_KEY names a key in the signer's gpg keyring.
# The signature is the debsigs "origin" member, _gpgorigin, which dpkg ignores
# and gpg can check over the three members (native_deb_verify does).

NATIVE_SIGN_CAFILE_DEFAULT=/etc/ssl/certs/ca-certificates.crt

native_authenticode_verify() { # FILE
    # A timestamped signature chains to the TSA's roots as well as the signer's.
    osslsigncode verify -in "$1" -CAfile "${OMINULL_AUTHENTICODE_CAFILE:-${NATIVE_SIGN_CAFILE_DEFAULT}}" \
        -TSA-CAfile "${OMINULL_AUTHENTICODE_CAFILE:-${NATIVE_SIGN_CAFILE_DEFAULT}}" >/dev/null 2>&1
}

# True when a signer is set up; a partial setup stops the release rather than
# shipping unsigned files that look intended.
native_authenticode_configured() {
    if [ -n "${OMINULL_AUTHENTICODE_COMMAND:-}" ] && [ -n "${OMINULL_AUTHENTICODE_TIMESTAMP_URL:-}" ]; then
        echo "[-] OMINULL_AUTHENTICODE_TIMESTAMP_URL is for the PFX; a command signer timestamps for itself." >&2
        exit 1
    fi
    if [ -n "${OMINULL_AUTHENTICODE_COMMAND:-}" ] || [ -n "${OMINULL_AUTHENTICODE_PFX:-}" ]; then
        return 0
    fi
    if [ -n "${OMINULL_AUTHENTICODE_PASSFILE:-}" ] || [ -n "${OMINULL_AUTHENTICODE_TIMESTAMP_URL:-}" ]; then
        echo "[-] Authenticode is half set up: OMINULL_AUTHENTICODE_PFX is empty." >&2
        exit 1
    fi
    return 1
}

# An MSI's signature says nothing about the programs inside it, and the two are
# signed in separate steps. Refuse a signed MSI holding an unsigned program.
native_check_msi_contents() { # MSI
    local msi="$1" work exe
    native_authenticode_configured || return 0
    work="$(mktemp -d)"
    if ! msiextract -C "${work}" "${msi}" >/dev/null; then
        rm -rf "${work}"
        echo "[-] Could not read $(basename "${msi}") to check the programs inside it." >&2
        exit 1
    fi
    while IFS= read -r exe; do
        if ! native_authenticode_verify "${exe}"; then
            rm -rf "${work}"
            echo "[-] $(basename "${exe}") inside $(basename "${msi}") has no valid signature; set the signer for build-packages.sh too." >&2
            exit 1
        fi
    done < <(find "${work}" -type f -iname '*.exe')
    rm -rf "${work}"
}

native_sign_windows() { # FILE
    local file="$1" out ts=()
    if ! native_authenticode_configured; then
        echo "  [=] $(basename "${file}"): no Authenticode signer configured, left as built."
        return 0
    fi
    out="$(mktemp "${file}.native.XXXXXX")"
    rm -f "${out}" # osslsigncode refuses an existing output
    if [ -n "${OMINULL_AUTHENTICODE_COMMAND:-}" ]; then
        if ! "${OMINULL_AUTHENTICODE_COMMAND}" sign "${file}" "${out}"; then
            rm -f "${out}"
            echo "[-] The Authenticode signer failed on $(basename "${file}")." >&2
            exit 1
        fi
    else
        if [ ! -r "${OMINULL_AUTHENTICODE_PASSFILE:-}" ]; then
            echo "[-] OMINULL_AUTHENTICODE_PFX needs OMINULL_AUTHENTICODE_PASSFILE." >&2
            exit 1
        fi
        [ -z "${OMINULL_AUTHENTICODE_TIMESTAMP_URL:-}" ] || ts=(-ts "${OMINULL_AUTHENTICODE_TIMESTAMP_URL}")
        if ! osslsigncode sign -pkcs12 "${OMINULL_AUTHENTICODE_PFX}" -readpass "${OMINULL_AUTHENTICODE_PASSFILE}" \
            -h sha256 "${ts[@]}" -in "${file}" -out "${out}" >/dev/null; then
            rm -f "${out}"
            echo "[-] osslsigncode could not sign $(basename "${file}")." >&2
            exit 1
        fi
    fi
    if [ ! -s "${out}" ] || ! native_authenticode_verify "${out}"; then
        echo "[-] The Authenticode signature on $(basename "${file}") did not verify:" >&2
        osslsigncode verify -in "${out}" -CAfile "${OMINULL_AUTHENTICODE_CAFILE:-${NATIVE_SIGN_CAFILE_DEFAULT}}" 2>&1 | tail -5 >&2 || true
        rm -f "${out}"
        exit 1
    fi
    chmod --reference="${file}" "${out}"
    mv "${out}" "${file}"
    echo "  [+] $(basename "${file}"): Authenticode signed and verified."
}

# The bytes a debsigs origin signature covers: these three members, in order.
native_deb_signed_bytes() { # DEB
    local member
    for member in $(ar t "$1"); do
        case "${member}" in debian-binary|control.tar*|data.tar*) ar p "$1" "${member}" ;; esac
    done
}

native_deb_verify() { # DEB; gpg's own verdict, not its exit code alone
    local sig status rc=0
    sig="$(mktemp)"
    ar p "$1" _gpgorigin >"${sig}" 2>/dev/null || rc=1
    if [ "${rc}" -eq 0 ]; then
        status="$(native_deb_signed_bytes "$1" | gpg --batch --status-fd 1 --verify "${sig}" - 2>/dev/null)" || rc=1
        grep -q '^\[GNUPG:\] VALIDSIG ' <<<"${status}" || rc=1
    fi
    rm -f "${sig}"
    return "${rc}"
}

native_sign_deb() { # DEB
    local deb="$1" work
    if [ -z "${OMINULL_DEB_GPG_KEY:-}" ]; then
        echo "  [=] $(basename "${deb}"): no Debian signing key configured, left as built."
        return 0
    fi
    work="$(mktemp -d)"
    cp -p "${deb}" "${work}/pkg.deb"
    ar d "${work}/pkg.deb" _gpgorigin 2>/dev/null || true
    if ! native_deb_signed_bytes "${work}/pkg.deb" \
        | gpg --batch --yes --armor --local-user "${OMINULL_DEB_GPG_KEY}" --detach-sign --output "${work}/_gpgorigin" - ; then
        rm -rf "${work}"
        echo "[-] gpg could not sign $(basename "${deb}")." >&2
        exit 1
    fi
    (cd "${work}" && ar q pkg.deb _gpgorigin 2>/dev/null)
    if ! native_deb_verify "${work}/pkg.deb" || ! dpkg-deb --info "${work}/pkg.deb" >/dev/null; then
        rm -rf "${work}"
        echo "[-] The Debian signature on $(basename "${deb}") did not verify." >&2
        exit 1
    fi
    mv "${work}/pkg.deb" "${deb}"
    rm -rf "${work}"
    echo "  [+] $(basename "${deb}"): Debian origin signature added and verified."
}
