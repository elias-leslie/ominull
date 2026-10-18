#!/usr/bin/env bash
# Installs the OmniNull screen viewer for the current user (no sudo):
#   ~/.local/bin/ominull-screen, an ominull-screen:// link handler, and
#   ~/.config/ominull/screen.json listing the hub(s) the viewer trusts.
#
#   install-screen-viewer.sh [--binary PATH] [--hub https://HUB[:PORT] --ca CA.pem]
#   install-screen-viewer.sh --uninstall
#
# Without --binary it builds screen/viewer (release, offline, vendored crates).
# Running it again is safe; --hub/--ca adds or replaces that hub's entry.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"
CONF_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/ominull"
DESKTOP="ominull-screen.desktop"

binary="" hub="" ca="" uninstall=0
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) binary="${2:?--binary needs a path}"; shift 2 ;;
        --hub) hub="${2:?--hub needs an origin}"; shift 2 ;;
        --ca) ca="${2:?--ca needs a PEM file}"; shift 2 ;;
        --uninstall) uninstall=1; shift ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

refresh_handlers() {
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "${APP_DIR}" >/dev/null 2>&1 || true
    fi
}

if [ "${uninstall}" = 1 ]; then
    rm -f "${BIN_DIR}/ominull-screen" "${APP_DIR}/${DESKTOP}"
    # Drop our default from mimeapps.list; leave everything else alone.
    mimeapps="${XDG_CONFIG_HOME:-${HOME}/.config}/mimeapps.list"
    if [ -f "${mimeapps}" ]; then
        sed -i '/^x-scheme-handler\/ominull-screen=/d' "${mimeapps}"
    fi
    refresh_handlers
    echo "Removed the viewer and its link handler. Hub settings stay in ${CONF_DIR}/screen.json (delete it to forget them)."
    exit 0
fi

if [ -n "${hub}" ] || [ -n "${ca}" ]; then
    [ -n "${hub}" ] && [ -n "${ca}" ] || { echo "--hub and --ca go together" >&2; exit 2; }
    case "${hub}" in https://*) ;; *) echo "--hub must be an https:// origin" >&2; exit 2 ;; esac
    grep -q -- "-----BEGIN CERTIFICATE-----" "${ca}" || { echo "${ca} is not a PEM certificate" >&2; exit 2; }
    command -v python3 >/dev/null 2>&1 || { echo "python3 is needed to write ${CONF_DIR}/screen.json" >&2; exit 1; }
fi

# 1. The binary.
if [ -z "${binary}" ]; then
    (cd "${ROOT_DIR}/screen/viewer" && cargo build --release --offline --locked)
    binary="${ROOT_DIR}/screen/viewer/target/release/ominull-screen"
fi
[ -x "${binary}" ] || { echo "no viewer binary at ${binary}" >&2; exit 1; }
mkdir -p "${BIN_DIR}"
install -m 755 "${binary}" "${BIN_DIR}/ominull-screen.new"
mv -f "${BIN_DIR}/ominull-screen.new" "${BIN_DIR}/ominull-screen"

# 2. The link handler.
mkdir -p "${APP_DIR}"
cat > "${APP_DIR}/${DESKTOP}" <<EOF
[Desktop Entry]
Type=Application
Name=OmniNull screen
Comment=Opens OmniNull remote screen sessions from the console
Exec=${BIN_DIR}/ominull-screen %u
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/ominull-screen;
EOF
if command -v xdg-mime >/dev/null 2>&1; then
    xdg-mime default "${DESKTOP}" x-scheme-handler/ominull-screen
else
    echo "xdg-mime not found: links may not open the viewer until your desktop picks up ${APP_DIR}/${DESKTOP}" >&2
fi
refresh_handlers

# 3. Trusted hubs.
if [ -n "${hub}" ]; then
    mkdir -p "${CONF_DIR}"
    chmod 700 "${CONF_DIR}"
    umask 077
    python3 - "${CONF_DIR}/screen.json" "${hub%/}" "${ca}" <<'PY'
import json, os, sys
path, origin, ca_path = sys.argv[1:]
try:
    with open(path) as f:
        cfg = json.load(f)
    hubs = [h for h in cfg.get("hubs", []) if isinstance(h, dict) and h.get("origin", "").rstrip("/").lower() != origin.lower()]
except FileNotFoundError:
    hubs = []
with open(ca_path) as f:
    hubs.append({"origin": origin, "ca_pem": f.read()})
tmp = path + ".tmp"
with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
    json.dump({"hubs": hubs}, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
    echo "The viewer trusts ${hub%/} (${CONF_DIR}/screen.json)."
fi

echo "Installed ${BIN_DIR}/ominull-screen; ominull-screen:// links open it."
case ":${PATH}:" in *":${BIN_DIR}:"*) ;; *) echo "Note: ${BIN_DIR} is not on your PATH." ;; esac
