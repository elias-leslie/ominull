#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
SRC_DIR="$ROOT_DIR/driver/src"
INC_DIR="$ROOT_DIR/driver/include"

mkdir -p "$BUILD_DIR"

echo "[*] Compiling wfpsentinel.sys (x86_64 Windows Native Subsystem)..."

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
  -o "$BUILD_DIR/wfpsentinel.sys" \
  "$SRC_DIR/driver.c" \
  -lntoskrnl -lhal

echo "[+] Built: $BUILD_DIR/wfpsentinel.sys"
file "$BUILD_DIR/wfpsentinel.sys"
