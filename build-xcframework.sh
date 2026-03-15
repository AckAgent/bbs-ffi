#!/usr/bin/env bash
#
# build-xcframework.sh
#
# Builds the bbs-ffi Rust crate for iOS targets,
# generates Swift bindings via UniFFI, and packages everything into an
# XCFramework (output location configurable via BBS_FFI_XCFRAMEWORK_BUILD_OUTPUT).
#
# Usage:
#   ./build-xcframework.sh          # Build release XCFramework
#   ./build-xcframework.sh --debug  # Build debug XCFramework (faster, larger)
#
# Prerequisites:
#   - Rust toolchain with targets: aarch64-apple-ios, aarch64-apple-ios-sim
#     Install via:
#       rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   - Xcode command line tools (xcodebuild)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$SCRIPT_DIR"
TARGET_DIR="${BBS_FFI_TARGET_DIR:-$CRATE_DIR/target}"
GENERATED_DIR="${BBS_FFI_GENERATED_DIR:-$CRATE_DIR/generated}"
HEADERS_DIR="${BBS_FFI_HEADERS_DIR:-$CRATE_DIR/headers}"
XCFRAMEWORK_BUILD_OUTPUT="${BBS_FFI_XCFRAMEWORK_BUILD_OUTPUT:-$CRATE_DIR/AckAgentBBSBindings.xcframework}"
SKIP_RUSTUP_TARGET_INSTALL="${BBS_FFI_SKIP_RUSTUP_TARGET_INSTALL:-0}"

# Parse arguments
PROFILE="release"
CARGO_FLAG="--release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
    CARGO_FLAG=""
fi

echo "=== Building bbs-ffi for iOS targets (profile: $PROFILE) ==="

# Ensure required Rust targets are installed.
if [[ "$SKIP_RUSTUP_TARGET_INSTALL" != "1" ]]; then
    rustup target add \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        >/dev/null
fi

# Step 1 & 2: Build for iOS device and simulator in parallel
echo ""
echo "--- Building for aarch64-apple-ios and aarch64-apple-ios-sim (parallel) ---"
cd "$CRATE_DIR"

cargo build --target-dir "$TARGET_DIR" --target aarch64-apple-ios $CARGO_FLAG &
PID_DEVICE=$!
cargo build --target-dir "$TARGET_DIR" --target aarch64-apple-ios-sim $CARGO_FLAG &
PID_SIM=$!

FAIL=0
wait $PID_DEVICE || FAIL=1
wait $PID_SIM || FAIL=1
if [[ $FAIL -ne 0 ]]; then
    echo "ERROR: One or both iOS builds failed"
    exit 1
fi

# Step 3: Generate Swift bindings
echo ""
echo "--- Generating Swift bindings ---"
mkdir -p "$GENERATED_DIR"
cargo run --target-dir "$TARGET_DIR" --bin uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-apple-ios/$PROFILE/libbbs_ffi.a" \
    --language swift \
    --out-dir "$GENERATED_DIR/"

echo "Generated files:"
ls -la "$GENERATED_DIR/"

# Step 4: Prepare headers for XCFramework
echo ""
echo "--- Preparing headers ---"
mkdir -p "$HEADERS_DIR"
cp "$GENERATED_DIR/bbs_ffiFFI.h" "$HEADERS_DIR/"
cp "$GENERATED_DIR/bbs_ffiFFI.modulemap" "$HEADERS_DIR/module.modulemap"

# Step 5: Create XCFramework
echo ""
echo "--- Creating XCFramework ---"
mkdir -p "$(dirname "$XCFRAMEWORK_BUILD_OUTPUT")"
rm -rf "$XCFRAMEWORK_BUILD_OUTPUT"
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/$PROFILE/libbbs_ffi.a" \
        -headers "$HEADERS_DIR/" \
    -library "$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/libbbs_ffi.a" \
        -headers "$HEADERS_DIR/" \
    -output "$XCFRAMEWORK_BUILD_OUTPUT"

echo ""
echo "=== XCFramework built successfully ==="
echo ""
echo "  XCFramework:    $XCFRAMEWORK_BUILD_OUTPUT"
echo "  Swift bindings: $GENERATED_DIR/bbs_ffi.swift"
echo ""
echo "  Library sizes:"
echo "    iOS device:    $(du -h "$TARGET_DIR/aarch64-apple-ios/$PROFILE/libbbs_ffi.a" | cut -f1)"
echo "    iOS simulator: $(du -h "$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/libbbs_ffi.a" | cut -f1)"
echo "    simulator archs: $(lipo -archs "$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/libbbs_ffi.a")"
