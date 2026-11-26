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

The package was copied from the Cargo registry cache. The default-feature
change below is required for wasm; the warning cleanups keep native and both
wasm targets at zero warnings. Run
`git diff -- rustcrypto-ffi/third_party/halo2-axiom-0.5.3` for the exact diff.

## Diff: wasm-safe defaults

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

`multicore` remains an opt-in feature. Native builds select it explicitly.

## Diff: warning cleanup

`cargo fix --lib -p halo2-axiom` applied the lifetime/import/unused-attribute
fixes; the cross-target and non-machine-applicable warnings were fixed manually.

| File | Change |
|---|---|
| `Cargo.toml` / `Cargo.toml.orig` | Declare the already-referenced `thread-safe-region` feature (upstream had it commented out) |
| `src/multicore.rs` | Drop the unused `Scope` re-export; cfg-gate `ParallelIterator` / `IntoParallelRefMutIterator` |
| `src/plonk/evaluation.rs`, `src/plonk/keygen.rs`, `src/plonk/prover.rs`, `src/plonk/witness.rs` | cfg-gate `ParallelIterator` imports to `multicore` |
| `src/plonk/vanishing/verifier.rs`, `src/poly/ipa/commitment.rs` | Explicit elided lifetimes |
| `src/poly/ipa/strategy.rs` | Remove no-op `#[must_use]` on trait impl methods |
| `src/transcript.rs` | Replace deprecated `GenericArray::as_slice()` with slice indexing |
| `src/plonk/circuit.rs` | Remove unused `PointIndex`; allow the intentionally retained `queried_selectors` debug field |

Warning policy:

- Local: `ci/fix_halo2_axiom_warnings.sh` applies `cargo fix` and immediately
  runs the warning check.
- CI: `ci/check_halo2_axiom_warnings.sh` runs
  `cargo rustc -p halo2-axiom --lib -- -D warnings` for native and both wasm
  targets. It is wired into the `ZKP integration` job.
- CI does not run `cargo fix` (it would mutate the tree). Apply fixes locally,
  review, and commit.

## Update procedure

1. Change the `snark-verifier` / `halo2-base` versions only after reviewing the
   fixed v1 profile in `docs/halo2.md`.
2. Copy the new `halo2-axiom-<version>` package from the Cargo registry into
   `rustcrypto-ffi/third_party/`.
3. Apply the `default` feature edit (remove `multicore`) and declare
   `thread-safe-region = []` as above.
4. Run `ci/fix_halo2_axiom_warnings.sh`, review the diff, and update this
   document with the new checksum/commit.
5. Keep `halo2-axiom = { features = ["multicore"] }` in the native
   `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` section.
6. Run `ci/check_halo2_axiom_warnings.sh`, then `ci/test_halo2_wasm.sh`.

## Upstream contribution

The default-feature change and warning fixes are candidates for upstream
issues/PRs: "provide a wasm-safe default feature set", "declare
thread-safe-region", and "clean up Rust 2024/new-lint warnings". Upstream
already has the sequential code path; only the default feature choice blocks
transitive consumers such as `halo2-base`.
