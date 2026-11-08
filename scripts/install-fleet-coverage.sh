#!/bin/bash
# Install the fleet coverage row (scripts/fleet_coverage.py) for this user on the machine whose
# Aico should show it: a copy in ~/.local/lib/ominull and an Aico routine that runs it every
# 15 minutes (and once now). It replaces the old ominull-fleet-coverage user timer, which this
# removes if it is still there. Re-run after changing the script.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${HOME}/.local/lib/ominull"
UNITS="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
command -v aico >/dev/null || { echo "install aico first (the routine is registered with it)" >&2; exit 1; }
mkdir -p "${LIB}"
install -m 0644 "${ROOT_DIR}/scripts/fleet_coverage.py" "${LIB}/fleet_coverage.py"
if [[ -f "${UNITS}/ominull-fleet-coverage.timer" ]]; then
  systemctl --user disable --now ominull-fleet-coverage.timer || true
  rm -f "${UNITS}/ominull-fleet-coverage.timer" "${UNITS}/ominull-fleet-coverage.service"
  systemctl --user daemon-reload
fi
if ! aico routines list | grep -q '^ominull-fleet-coverage '; then
  aico routines add --project ominull --kind ominull-fleet-coverage \
    --what "Fleet coverage row (machines without an agent)" --every 15 \
    --command /usr/bin/python3 -I "${LIB}/fleet_coverage.py"
fi
aico routines run ominull-fleet-coverage || echo "run it later with: aico routines run ominull-fleet-coverage"
