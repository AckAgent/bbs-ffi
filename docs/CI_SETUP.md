# CI Setup

## Secrets

No secrets are required for CI builds. All builds use public Rust crates and standard toolchains.

## Workflow: release.yml

Triggered on tag push (`v*`). Builds the following artifacts and attaches them to a GitHub Release:

| Artifact | Platform | Format |
|----------|----------|--------|
| `libbbs_ffi-macos-arm64.a` | macOS arm64 | Static library |
| `libbbs_ffi-linux-amd64.a` | Linux amd64 | Static library |
| `libbbs_ffi-linux-arm64.a` | Linux arm64 | Static library |
| `wasm-out/` | WASM | `.wasm` + `.js` bindings |
| `AckAgentBBSBindings.xcframework.zip` | iOS device + simulator | XCFramework |
| `bbs_ffiFFI.h` | All C-compatible platforms | C header |

## Creating a Release

```bash
git tag v1.0.0
git push origin v1.0.0
```
