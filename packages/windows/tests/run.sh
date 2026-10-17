#!/usr/bin/env bash
# Parse, PowerShell 5.1-compatibility, safety and unit checks for packages/windows.
# Uses pwsh from PATH, or the binary named by OMINULL_PWSH.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pwsh_bin="${OMINULL_PWSH:-$(command -v pwsh || true)}"
if [ -z "${pwsh_bin}" ] || [ ! -x "${pwsh_bin}" ]; then
    echo "pwsh not found, skipped the Windows package checks (install PowerShell 7 or set OMINULL_PWSH)."
    exit 0
fi
exec "${pwsh_bin}" -NoProfile -NonInteractive -File "${here}/test-packages.ps1"
