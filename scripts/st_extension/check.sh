#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root}"
python3 -m unittest discover -s scripts/st_extension -p 'test_*.py' -v
