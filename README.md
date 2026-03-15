# BBS+ FFI

Rust crate implementing BBS+ signature operations, built as platform-specific artifacts for the AckAgent ecosystem.

## Artifacts

Published as GitHub Release assets on each tagged release:

| Artifact | Platform |
|----------|----------|
| `libbbs_ffi-macos-arm64.a` | macOS ARM64 static lib |
| `libbbs_ffi-linux-amd64.a` | Linux x86_64 static lib |
| `libbbs_ffi-linux-arm64.a` | Linux ARM64 static lib |
| `bbs_ffi.wasm` + `bbs_ffi.js` | WebAssembly |
| `BbsFfi.xcframework.zip` | iOS XCFramework |
| `bbs_ffi.h` | C header |

## Build

```sh
cargo build --release
```

## Consumers

- [ackagent/cli](https://github.com/AckAgent/ackagent) — static lib (CGo)
- [ackagent/web-sdk](https://github.com/AckAgent/web-sdk) — WASM
- [ackagent/ios-sdk](https://github.com/AckAgent/ios-sdk) — XCFramework
- [ackagent/platform](https://github.com/AckAgent/platform) — static lib (CGo)
