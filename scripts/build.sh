#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
SRC_DIR="$ROOT_DIR/driver/src"
INC_DIR="$ROOT_DIR/driver/include"
CLI_DIR="$ROOT_DIR/cli"

mkdir -p "$BUILD_DIR"

echo "[*] Generating fwpkclnt import library (libfwpkclnt.a)..."
x86_64-w64-mingw32-dlltool \
  -d "$SRC_DIR/fwpkclnt.def" \
  -l "$BUILD_DIR/libfwpkclnt.a" \
  -m i386:x86-64 \
  -D fwpkclnt.sys

echo "[*] Compiling ominull.sys (x86_64 Windows Native Subsystem)..."

x86_64-w64-mingw32-gcc \
  -shared \
  -Wall -Wextra \
  -Wl,--subsystem,native \
  -Wl,--image-base,0x140000000 \
  -Wl,--file-alignment,0x1000 \
  -Wl,--section-alignment,0x1000 \
  -Wl,--entry,DriverEntry \
  -Wl,--dynamicbase \
  -Wl,--nxcompat \
  -nostartfiles -nodefaultlibs -nostdlib \
  -I"$INC_DIR" \
  -I/usr/x86_64-w64-mingw32/include/ddk \
  -L"$BUILD_DIR" \
  -o "$BUILD_DIR/ominull.sys" \
  "$SRC_DIR/driver.c" \
  -lntoskrnl -lhal -lfwpkclnt -lndis

echo "[+] Built: $BUILD_DIR/ominull.sys"
file "$BUILD_DIR/ominull.sys"

echo "[*] Compiling user-mode control CLI (ominullctl.exe)..."
x86_64-w64-mingw32-gcc \
  -Wall -Wextra -O2 \
  -I"$INC_DIR" \
  -o "$BUILD_DIR/ominullctl.exe" \
  "$CLI_DIR/ominullctl.c" \
  -lws2_32

cp -f "$BUILD_DIR/ominullctl.exe" "$BUILD_DIR/ominull_ctl.exe"

echo "[+] Built: $BUILD_DIR/ominullctl.exe"
file "$BUILD_DIR/ominullctl.exe"

echo "[*] Compiling endpoint service agent (ominulld.exe)..."
x86_64-w64-mingw32-gcc \
  -Wall -O2 -DOMINULL_WFP_EMBEDDED \
  -I"$INC_DIR" \
  "$ROOT_DIR/agent/src/main.c" \
  "$ROOT_DIR/agent/src/driver_client.c" \
  "$ROOT_DIR/agent/src/hub_client.c" \
  "$ROOT_DIR/agent/src/hub_tls.c" \
  "$ROOT_DIR/agent/src/service.c" \
  "$ROOT_DIR/agent/src/updater.c" \
  "$ROOT_DIR/agent/windows/wfp_user.c" \
  -o "$BUILD_DIR/ominulld.exe" \
  -lwinhttp -lws2_32 -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lfwpuclnt -lole32

echo "[+] Built: $BUILD_DIR/ominulld.exe"
file "$BUILD_DIR/ominulld.exe"

echo "[*] Compiling central management hub (ominull-hub Linux & Windows)..."
(cd "$ROOT_DIR/hub" && CGO_ENABLED=0 go build -o "$BUILD_DIR/ominull-hub" cmd/main.go)
(cd "$ROOT_DIR/hub" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/ominull-hub.exe" cmd/main.go)

echo "[+] Built: $BUILD_DIR/ominull-hub"
file "$BUILD_DIR/ominull-hub"
echo "[+] Built: $BUILD_DIR/ominull-hub.exe"
file "$BUILD_DIR/ominull-hub.exe"

echo "[*] Compiling Linux eBPF kernel program (ominull_filter.bpf.o)..."
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c "$ROOT_DIR/ebpf/ominull_filter.bpf.c" -o "$BUILD_DIR/ominull_filter.bpf.o"
echo "[+] Built: $BUILD_DIR/ominull_filter.bpf.o"
file "$BUILD_DIR/ominull_filter.bpf.o"

echo "[*] Compiling Linux endpoint daemon (ominulld)..."
gcc -Wall -O2 "$ROOT_DIR/agent/linux/main.c" -o "$BUILD_DIR/ominulld"
echo "[+] Built: $BUILD_DIR/ominulld"
file "$BUILD_DIR/ominulld"


