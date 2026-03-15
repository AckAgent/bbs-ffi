.PHONY: build build-generate-issuer-keypair test static-lib static-lib-check static-lib-linux-arm64 wasm-web android-libs xcframework clean lint format release

# ── VERSION resolution ─────────────────────────────────────
# Supports: make release VERSION=1.2.3 | VERSION=patch | VERSION=minor | VERSION=major
ifdef VERSION
  ifneq ($(filter v%,$(VERSION)),)
    $(error VERSION must not start with 'v' — the prefix is added automatically. Usage: make release VERSION=1.2.3)
  endif
  ifneq ($(filter patch minor major,$(VERSION)),)
    _LATEST_TAG := $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)
    _LATEST_VER := $(patsubst v%,%,$(_LATEST_TAG))
    _VER_PARTS  := $(subst ., ,$(_LATEST_VER))
    _CUR_MAJOR  := $(or $(word 1,$(_VER_PARTS)),0)
    _CUR_MINOR  := $(or $(word 2,$(_VER_PARTS)),0)
    _CUR_PATCH  := $(or $(word 3,$(_VER_PARTS)),0)
    ifeq ($(VERSION),patch)
      override VERSION := $(_CUR_MAJOR).$(_CUR_MINOR).$(shell echo $$(($(_CUR_PATCH) + 1)))
    else ifeq ($(VERSION),minor)
      override VERSION := $(_CUR_MAJOR).$(shell echo $$(($(_CUR_MINOR) + 1))).0
    else ifeq ($(VERSION),major)
      override VERSION := $(shell echo $$(($(_CUR_MAJOR) + 1))).0.0
    endif
  endif
  ifeq ($(shell echo '$(VERSION)' | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+$$'),0)
    $(error Invalid VERSION '$(VERSION)'. Must be semver X.Y.Z (e.g. 1.2.3) or bump keyword (patch|minor|major))
  endif
endif
# ────────────────────────────────────────────────────────────

# Default target: build for host (used for development/testing)
build:
	cargo build --release

# Build the generate-issuer-keypair CLI tool
build-generate-issuer-keypair:
	cargo build --release --example generate_issuer_keypair

# Build static library for CGo linking (used by credential-issuer service)
static-lib:
	cargo build --release

# Cross-compile static library for Linux arm64.
# Output is placed in target/release/ so CGo LDFLAGS work unchanged.
static-lib-linux-arm64:
	rustup target add aarch64-unknown-linux-gnu
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
		cargo build --target aarch64-unknown-linux-gnu --release
	cp target/aarch64-unknown-linux-gnu/release/libbbs_ffi.a target/release/libbbs_ffi.a

# Verify the static library exists (CI gate)
static-lib-check:
	test -f target/release/libbbs_ffi.a

# Build wasm32 artifact and generate JS/TS bindings for Web SDK pseudonym verification
wasm-web:
	rustup target add wasm32-unknown-unknown
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen target/wasm32-unknown-unknown/release/bbs_ffi.wasm --target web --out-dir ../web-sdk/src/generated/bbs_ffi_wasm
	wasm-opt -Oz --enable-bulk-memory --enable-sign-ext \
		../web-sdk/src/generated/bbs_ffi_wasm/bbs_ffi_bg.wasm \
		-o ../web-sdk/src/generated/bbs_ffi_wasm/bbs_ffi_bg.wasm

# Build Android .so libraries for JNI usage in the Android app.
# Requires cargo-ndk (install with: cargo install cargo-ndk).
android-libs:
	@cargo ndk --version >/dev/null 2>&1 || (echo "cargo-ndk is required. Install with: cargo install cargo-ndk" && exit 1)
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
	cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../android/ackagent/app/src/main/jniLibs build --release

# Run unit tests on the host platform
test:
	cargo test

# Build the XCFramework for iOS (device + simulator) and install it
xcframework:
	./build-xcframework.sh

# Build a debug XCFramework (faster compilation, larger binary)
xcframework-debug:
	./build-xcframework.sh --debug

# Clean all build artifacts
clean:
	cargo clean
	rm -rf generated/ headers/
	rm -rf AckAgentBBSBindings.xcframework

# Lint (cargo clippy)
lint:
	cargo clippy -- -D warnings

# Release: build XCFramework, update Package.swift checksum, tag, and push.
# CI builds the same XCFramework and creates the GitHub Release with the zip.
# Usage: make release VERSION=0.2.0
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.2.3 (or patch|minor|major))
endif
	@echo "Releasing v$(VERSION)$(if $(_LATEST_VER), (was v$(_LATEST_VER)),)"
	./build-xcframework.sh
	cd "$(CURDIR)" && zip -r AckAgentBBSBindings.xcframework.zip AckAgentBBSBindings.xcframework
	$(eval CHECKSUM := $(shell swift package compute-checksum AckAgentBBSBindings.xcframework.zip))
	sed -i '' 's|releases/download/v[^/]*/|releases/download/v$(VERSION)/|' Package.swift
	sed -i '' 's|checksum: "[^"]*"|checksum: "$(CHECKSUM)"|' Package.swift
	rm -f AckAgentBBSBindings.xcframework.zip
	git add Package.swift
	git commit -m "chore: update Package.swift for v$(VERSION)"
	git tag v$(VERSION)
	git push origin main v$(VERSION)

# Format code
format:
	cargo fmt
