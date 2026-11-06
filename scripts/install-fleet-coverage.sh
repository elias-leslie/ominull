#!/bin/bash
# Install the fleet coverage row (scripts/fleet_coverage.py) for this user on the
# machine whose Aico should show it: a copy in ~/.local/lib/ominull and a user
# timer that runs it every 15 minutes (and once now). Re-run after changing it.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${HOME}/.local/lib/ominull"
UNITS="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
mkdir -p "${LIB}" "${UNITS}"
install -m 0644 "${ROOT_DIR}/scripts/fleet_coverage.py" "${LIB}/fleet_coverage.py"
cat > "${UNITS}/ominull-fleet-coverage.service" <<EOF
[Unit]
Description=OmniNull fleet coverage row for Aico Status (fleet machines without an agent)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${LIB}/fleet_coverage.py
EOF
cat > "${UNITS}/ominull-fleet-coverage.timer" <<'EOF'
[Unit]
Description=OmniNull fleet coverage row every 15 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now ominull-fleet-coverage.timer
systemctl --user start ominull-fleet-coverage.service
systemctl --user --no-pager status ominull-fleet-coverage.service | sed -n '1,3p;/fleet machines/p'
