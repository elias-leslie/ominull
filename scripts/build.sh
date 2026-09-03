#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"

mkdir -p "$BUILD_DIR"

echo "[*] Compiling Windows user-mode agent and WFP recovery tool..."
x86_64-w64-mingw32-gcc \
  -Wall -Wextra -Wformat=2 -O2 -DOMINULL_WFP_EMBEDDED \
  -I"$ROOT_DIR/agent/include" \
  "$ROOT_DIR/agent/src/main.c" \
  "$ROOT_DIR/agent/src/hub_client.c" \
  "$ROOT_DIR/agent/src/hub_tls.c" \
  "$ROOT_DIR/agent/src/service.c" \
  "$ROOT_DIR/agent/src/updater.c" \
  "$ROOT_DIR/agent/src/provenance_windows.c" \
  "$ROOT_DIR/agent/src/response_windows.c" \
  "$ROOT_DIR/agent/windows/wfp_user.c" \
  -o "$BUILD_DIR/ominulld.exe" \
  -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt \
  -lfwpuclnt -lole32
file "$BUILD_DIR/ominulld.exe"

x86_64-w64-mingw32-gcc \
  -Wall -Wextra -Wformat=2 -O2 \
  -I"$ROOT_DIR/agent/include" \
  "$ROOT_DIR/agent/windows/wfp_user.c" \
  -o "$BUILD_DIR/ominull_wfp_user.exe" \
  -lws2_32 -ladvapi32 -lfwpuclnt -lole32
file "$BUILD_DIR/ominull_wfp_user.exe"

echo "[*] Compiling Linux socket-collection agent..."
gcc -Wall -Wextra -Wformat=2 -O2 \
  -I"$ROOT_DIR/agent/include" \
  "$ROOT_DIR/agent/linux/main.c" -lcurl -o "$BUILD_DIR/ominulld"
file "$BUILD_DIR/ominulld"

echo "[*] Compiling Linux hub, control CLI, and response authority..."
(cd "$ROOT_DIR/hub" && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/ominull-hub" ./cmd)
(cd "$ROOT_DIR/hub" && CGO_ENABLED=0 go build -trimpath -o "$BUILD_DIR/ominullctl" ./cmd/ominullctl)
(cd "$ROOT_DIR/hub" && CGO_ENABLED=0 go build -trimpath -o "$BUILD_DIR/ominull-response-authority" ./cmd/ominull-response-authority)
file "$BUILD_DIR/ominull-hub"
file "$BUILD_DIR/ominullctl"
file "$BUILD_DIR/ominull-response-authority"

echo "[+] Retained binaries built for version $VERSION."
