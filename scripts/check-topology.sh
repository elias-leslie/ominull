#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
npm --prefix "$ROOT_DIR/web-build" ci --ignore-scripts
node "$ROOT_DIR/web-build/build.cjs" --check
for file in app topology topology-model; do
  node --check "$ROOT_DIR/hub/pkg/server/web/$file.js"
done
node --test "$ROOT_DIR"/hub/pkg/server/web_tests/*.test.cjs
node --test "$ROOT_DIR"/web-build/*.test.cjs
