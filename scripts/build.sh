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
  -L"$BUILD_DIR" \
  -o "$BUILD_DIR/wfpsentinel.sys" \
  "$SRC_DIR/driver.c" \
  -lntoskrnl -lhal -lfwpkclnt -lndis

echo "[+] Built: $BUILD_DIR/wfpsentinel.sys"
file "$BUILD_DIR/wfpsentinel.sys"

echo "[*] Compiling user-mode control CLI (wfpsentinel_ctl.exe / wfpctl.exe)..."
x86_64-w64-mingw32-gcc \
  -Wall -Wextra -O2 \
  -I"$INC_DIR" \
  -o "$BUILD_DIR/wfpsentinel_ctl.exe" \
  "$CLI_DIR/wfpsentinel_ctl.c" \
  -lws2_32

cp -f "$BUILD_DIR/wfpsentinel_ctl.exe" "$BUILD_DIR/wfpctl.exe"

echo "[+] Built: $BUILD_DIR/wfpsentinel_ctl.exe & $BUILD_DIR/wfpctl.exe"
file "$BUILD_DIR/wfpsentinel_ctl.exe"

