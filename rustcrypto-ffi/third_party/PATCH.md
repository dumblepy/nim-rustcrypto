# Vendored patch: halo2-axiom 0.5.3

## Why

`snark-verifier` 0.2.7 → `halo2-base` 0.5.5 → `halo2-axiom` 0.5.3. Upstream
`halo2-axiom` enables the `multicore` feature by default. On `wasm32` without
the `atomics` target feature that combination is a hard `compile_error!`:

```text
The multicore feature flag is not supported on wasm32 architectures without atomics
```

The verifier does not need parallel execution. `halo2-axiom` already provides a
sequential `#[cfg(not(feature = "multicore"))]` path, and `rayon` 1.12+ has a
single-threaded fallback for wasm targets. Removing `multicore` from the default
feature list therefore lets the exact same verifier code build for
`wasm32-unknown-unknown` and `wasm32-wasip1` without changing cryptography,
transcripts, or serialization.

Native builds keep the parallel path because `rustcrypto-ffi/Cargo.toml`
enables `halo2-axiom`'s `multicore` feature for
`cfg(not(target_arch = "wasm32"))`.

## Provenance

| Item | Value |
|---|---|
| Crate | `halo2-axiom` |
| Version | `0.5.3` |
| Registry checksum | `18316396f9bc7dcd6ac1602443ea4f83f2c93fa5abe448a28db3abceb9c7aab3` |
| Upstream repository | https://github.com/axiom-crypto/halo2 |
| Published from commit | `5e4f0e524956f23b50d51b3a2f7bb07834948598` (`halo2_proofs/`) |
| License | MIT OR Apache-2.0 |
| Local path | `rustcrypto-ffi/third_party/halo2-axiom-0.5.3` |

Source files are otherwise byte-for-byte the crates.io 0.5.3 package (copied
from the Cargo registry cache). Only the two feature-list lines below differ.

## Diff

```diff
--- upstream Cargo.toml (normalized)
+++ vendored Cargo.toml
@@
 default = [
     "batch",
-    "multicore",
     "circuit-params",
 ]

--- upstream Cargo.toml.orig
+++ vendored Cargo.toml.orig
@@
-default = ["batch", "multicore", "circuit-params"]
+default = ["batch", "circuit-params"]
```

No `.rs` file is modified. `multicore` remains an opt-in feature.

## Update procedure

1. Change the `snark-verifier` / `halo2-base` versions only after reviewing the
   fixed v1 profile in `docs/halo2.md`.
2. Copy the new `halo2-axiom-<version>` package from the Cargo registry into
   `rustcrypto-ffi/third_party/`.
3. Apply the same `default` feature edit (remove `multicore`) and update this
   document with the new checksum and commit.
4. Keep `halo2-axiom = { features = ["multicore"] }` in the native
   `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` section.
5. Run `cargo build --locked --lib` for native, `wasm32-unknown-unknown`, and
   `wasm32-wasip1`, then `ci/test_halo2_wasm.sh`.

## Upstream contribution

The change is a candidate for an upstream issue: "provide a wasm-safe default
feature set or document `default-features = false` for halo2-axiom". Upstream
already has the sequential code path; only the default feature choice blocks
transitive consumers such as `halo2-base` (which depends on `halo2-axiom` with
default features enabled).
