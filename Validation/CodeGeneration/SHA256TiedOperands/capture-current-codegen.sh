#!/bin/sh

set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLCHAIN_IDENTIFIER=${SWIFT_SSL_TOOLCHAIN:-org.swift.64202607231a}
TEMPORARY_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/swift-ssl-sha256-codegen.XXXXXX")

cleanup() {
  rm -rf "$TEMPORARY_DIRECTORY"
}
trap cleanup EXIT HUP INT TERM

SDK_PATH=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)

TOOLCHAINS="$TOOLCHAIN_IDENTIFIER" /usr/bin/xcrun swiftc \
  -O \
  -parse-as-library \
  -target arm64-apple-macosx15.0 \
  -sdk "$SDK_PATH" \
  -emit-assembly \
  "$SCRIPT_DIRECTORY/SHA256IntrinsicProbe.swift" \
  -o "$TEMPORARY_DIRECTORY/swift.s"

TOOLCHAINS="$TOOLCHAIN_IDENTIFIER" /usr/bin/xcrun clang \
  -O3 \
  -march=armv8.2-a+sha2 \
  -target arm64-apple-macosx15.0 \
  -isysroot "$SDK_PATH" \
  -S \
  "$SCRIPT_DIRECTORY/SHA256IntrinsicProbe.c" \
  -o "$TEMPORARY_DIRECTORY/c.s"

for assembly_path in "$TEMPORARY_DIRECTORY/swift.s" "$TEMPORARY_DIRECTORY/c.s"; do
  /usr/bin/grep -Eq 'mov\.16b[[:space:]]+v[0-9]+, v[0-9]+' "$assembly_path"
  /usr/bin/grep -Eq 'sha256h\.4s' "$assembly_path"
  /usr/bin/grep -Eq 'sha256h2\.4s' "$assembly_path"
done

echo "Swift intrinsic sequence:"
/usr/bin/grep -E 'mov\.16b|sha256h2?\.4s' "$TEMPORARY_DIRECTORY/swift.s"
echo "Clang intrinsic sequence:"
/usr/bin/grep -E 'mov\.16b|sha256h2?\.4s' "$TEMPORARY_DIRECTORY/c.s"
echo "Observed the current tied-operand copy shape in both frontends."
