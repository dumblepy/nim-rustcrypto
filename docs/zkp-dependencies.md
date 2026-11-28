# ZKP verifier dependencies and licenses

This repository adds four independent proof-verification backends. They do not share
proof formats. The versions below are pinned in `rustcrypto-ffi/Cargo.lock`.

Branch 85 additionally defines a transparent IPA profile and a Poseidon2 hash
API. Both are implemented and exercised by native unit/Nim tests and by runtime
WASM smokes for `wasm32-unknown-unknown` and `wasm32-wasip1`. They are new
profiles/APIs, not replacements for the existing KZG/Groth16 verifiers.

| Crate | Version | License | Used for | Targets |
|---|---|---|---|---|
| `ark-bn254` | 0.5.0 | MIT OR Apache-2.0 | BN254 Fr/Fq/G1/G2 | all |
| `ark-ff` / `ark-ec` / `ark-serialize` | 0.5.0 | MIT OR Apache-2.0 | field/curve/serialization primitives | all |
| `ark-groth16` | 0.5.0 | MIT OR Apache-2.0 | Groth16 verifier | all |
| `light-poseidon` | 0.4.1 | Apache-2.0 | Poseidon/BN254 (bn254_x5) | all |
| `genshi-core` / `genshi-math` | 0.3.0 | MIT OR Apache-2.0 | fixed PLONKish/KZG/BN254 verifier | all |
| `qp-plonky2` (crate name `plonky2`) | 1.6.0 | MIT OR Apache-2.0 | Plonky2/Goldilocks verifier | all |
| `qp-plonky2-verifier` | 1.6.0 | MIT OR Apache-2.0 | Plonky2 verifier-side types/serializer | all |
| `snark-verifier` | 0.2.7 | MIT | Halo2/PSE-Axiom KZG verifier | all |
| `halo2-axiom` (via `halo2-base`) | 0.5.3 (vendored feature patch) | MIT OR Apache-2.0 | Halo2 proof system types | all |
| `bincode` | 1.3.3 | MIT | Halo2 protocol encoding | all |

Other transitive dependencies retain their own licenses. See the generated
`Cargo.lock` and each crate's repository for the authoritative list.

## Unaudited software warning

None of the verifier backends has been audited by this project. In particular:

- `genshi-core` is a young PLONKish implementation.
- `qp-plonky2` is a fork of Plonky2; Plonky2 itself is not a substitute for an audited
  proving system in every deployment.
- `snark-verifier` / `halo2-axiom` are PSE/Axiom ecosystem components.
- `arkworks` and `light-poseidon` are cryptographic building blocks, not audited
  products.

Do not infer application-level safety from a successful verification. Pin trusted
verifying keys/circuits, protect trusted-setup material (PLONK/Halo2 SRS), and perform
your own threat model.

## Target matrix

| Backend | Linux x86_64 | macOS arm64 | wasm32-unknown-unknown | wasm32-wasip1 |
|---|---|---|---|---|
| BN254 / Poseidon | build + test | build + test | build | build |
| Groth16/BN254 | build + test | build + test | build | build |
| PLONK/BN254 (genshi) | build + test | build + test | build | build |
| Plonky2 | build + test | build + test | build | build |
| Halo2 KZG/BN254 | build + test | build + test | build + test (Node `WebAssembly`) | build + test (Node WASI) |

"build" means the Rust staticlib compiles. For Halo2, the committed v1 fixture is also
verified through the C ABI on both wasm targets (`ci/test_halo2_wasm.sh`). Other wasm
runtimes and wasm performance were not measured; do not extend the claim beyond the
executed hosts listed in `docs/halo2.md`.

`halo2-axiom` 0.5.3 is vendored with a default-feature change (remove `multicore`)
so wasm can build without atomics, plus warning-only cleanups. See
`rustcrypto-ffi/third_party/PATCH.md` for provenance, the exact change list, and
update steps. `ci/check_halo2_axiom_warnings.sh` enforces `-D warnings` for native
and both wasm targets in the `ZKP integration` job.

## Branch 85: transparent IPA / Poseidon2 (2026-11-27)

Branch 85 adds no new proof-system crate or crate version. The transparent IPA
profile uses the existing vendored `halo2-axiom` 0.5.3 (the branch adds it as a
direct dependency edge; the crate/version was already present through the KZG
stack). The Poseidon2 implementation vendors constants only.

### Halo2 IPA / BN254 (implemented, verified natively and on both wasm targets)

The IPA profile uses the same `halo2-axiom` 0.5.3 copy as the KZG profile. The
local vendored patch is unchanged; see `rustcrypto-ffi/third_party/PATCH.md`.

| Crate / item | Version | License | Role in this branch | Notes |
|---|---|---|---|---|
| `halo2-axiom` (vendored) | 0.5.3 | MIT OR Apache-2.0 | IPA commitment, keygen, prove/verify; BN254 G1 / Fr; Blake2b transcript | Local patch removes `multicore` from the default feature list for wasm; native re-enables it. Registry checksum `18316396f9bc7dcd6ac1602443ea4f83f2c93fa5abe448a28db3abceb9c7aab3`; published from `5e4f0e524956f23b50d51b3a2f7bb07834948598` (`halo2_proofs/`). Warning-only cleanups are recorded in `PATCH.md`. |
| `snark-verifier` | 0.2.7 | MIT | **KZG profile only** (`src/halo2.rs`); not used by the IPA profile | crates.io metadata reports `rust_version = 1.91.1`; repository `axiom-crypto/snark-verifier`. Do not use it as an IPA verifier. |
| `bincode` | 1.3.3 | MIT | KZG protocol encoding | Unchanged. The IPA wire format is defined in `rustcrypto-ffi/src/halo2_ipa.rs` and does not use this KZG encoding. |
| IPA params / VK | — | — | Deterministic `ParamsIPA::new(k)`; approved circuit-id registry | No SRS ceremony and no caller-supplied generators. VK deserialization requires a concrete circuit type, so the crate accepts only built-in approved circuit ids. |

Status: the Rust API contract, v1 wire formats (`RCH2IPV1`, `RCH2IPP1`,
`RCH2IPF1`, `RCH2IPI1`), Nim type-first wrapper, and a committed fixture are in
this branch. Verified in the development container (2026-11-27):

- `cargo test --lib halo2_ipa`: 11 passed.
- `nimble test -y`: includes the 7 + 2 Nim tests for IPA.
- `ci/test_halo2_ipa_wasm.sh`: native, `wasm32-wasip1`, and
  `wasm32-unknown-unknown` verify the committed fixture. The unknown-target
  module has host imports from unrelated code paths, so the smoke replaces every
  function import with a throwing stub; verification still succeeds, confirming
  that it does not call `getrandom`/OS RNG. The verify path uses
  `SingleStrategy`; `AccumulatorStrategy` was rejected because it samples a
  random scalar during verification.
- The example circuit is a small built-in cubic demo, not a general R1CS
  frontend. A separate Poseidon2 custom-gate demo exists in
  `src/poseidon2_halo2.rs` (Rust-only; not registered as a C ABI circuit id).
- The verify-only feature `halo2-ipa-verify-only` excludes prover/keygen and the
  `prepare`/`prove` symbols. The ICP verifier canister builds with it and has
  only the five `ic0` imports (no `__wbindgen`/`getrandom`/Web Crypto imports).
  See `docs/ic-branch85.md` for the PocketIC measurements.
- Browser Web Worker proving and native benchmark reports are documented in
  `docs/halo2-ipa.md` and `docs/benchmarks-branch85.md`.

### Poseidon2 / BN254 constants

Poseidon2 is a hash API, not a verifier backend. It adds **no runtime
dependency**: the constants are vendored into
`rustcrypto-ffi/src/poseidon2.rs`, and `pso-poseidon` does not appear in
`rustcrypto-ffi/Cargo.lock`.

| Item | Version | License | Use | Notes |
|---|---|---|---|---|
| `pso-poseidon` | 0.5.0 | MIT | Provenance of the BN254 Poseidon2 round constants, internal diagonal, and linear layers | crates.io metadata: repository `psonet/pso-poseidon`, crate size 385,441 bytes. Constants only; no runtime dependency. |
| Noir `bn254_blackbox_solver` | `v1.0.0-beta.22` | Apache-2.0 | Upstream reference for the constants and the Noir/Barretenberg sponge | Constants are copied via `pso-poseidon` 0.5.0. Not linked at runtime. |
| `ark-bn254` | 0.5.0 | MIT OR Apache-2.0 | BN254 `Fr` arithmetic for the implementation | Existing dependency; no `ark` 0.6 duplicate is introduced for Poseidon2. |

Parameters recorded in the source: width `t = 4`, rate `3`, capacity `1`,
S-box `x^5`, `R_F = 8`, `R_P = 56`. Verified in the development container
(2026-11-27):

- `cargo test --lib poseidon2`: 12 passed, including the permutation KAT and
  the Noir sponge KAT for `n = 0..=7` plus the R1CS gadget KAT.
- `nimble test -y`: includes the Poseidon2 Nim tests and the unchanged
  Poseidon1 regression suite.
- `ci/test_poseidon2_wasm.sh`: native, `wasm32-wasip1`, and
  `wasm32-unknown-unknown` execute the KATs; the unknown-target cdylib has
  **zero imports** (no RNG/host services).

The framing is the Noir/Barretenberg sponge, not the psonet framing; the source
comment and tests are explicit about this distinction.

### Branch 85 target status

| Item | Native | `wasm32-unknown-unknown` | `wasm32-wasip1` | Nim | Status |
|---|---|---|---|---|---|
| Poseidon2 / BN254 | Rust KAT + Nim tests pass | Runtime smoke pass (0 imports) | Runtime smoke pass | Yes | Implemented |
| Poseidon2 Halo2 gate | MockProver KATs + IPA example pass | Not executed | Runtime prove/verify pass (Node WASI) | Yes (circuit id 2 + `0x100+n` 0..=12) | Implemented |
| Poseidon2 Halo2 browser/ICP | — | Chromium Web Worker prove id 2 | — | No | Implemented (browser prove, ICP verify) |
| Poseidon1 Halo2 gate | MockProver KAT + IPA comparison pass | Not executed | Not executed | No (comparison demo) | Implemented |
| Halo2 IPA / BN254 | Rust fixtures + Nim tests pass | Runtime smoke pass (host imports stubbed to throw) | Runtime smoke pass | Yes | Implemented (cubic + Poseidon2 hash3) |
| Halo2 IPA browser prove | — | Chromium Web Worker, `crossOriginIsolated=false` | — | No | Implemented (cubic circuit) |
| Halo2 IPA ICP verify | PocketIC update call | verify-only canister, `ic0`-only imports, params cache cold/warm | — | No | Implemented (not mainnet) |
| Poseidon2 IPA ICP verify | PocketIC update call (id 2 VK pinned) | verify-only canister, `ic0`-only imports, cold/warm | — | No | Implemented (not mainnet) |
| Poseidon2 ICP hash | PocketIC update call | canister, `ic0`-only imports | — | No | Implemented (not mainnet) |

The table is a status record. A successful compile alone is not treated as
success; the wasm entries are actual Node/WASI/Chromium executions and the ICP
entries are PocketIC update calls. Measurement references:
`docs/benchmarks-branch85.md`, `docs/ic-branch85.md`, `docs/halo2-ipa.md`,
`docs/poseidon2-halo2-gate.md`, `docs/poseidon2-halo2-wasm.md`,
`docs/poseidon1-halo2-gate.md`. Mainnet cycle quotes and a production `dfx`
deployment are not included.

## Native smoke benchmark (indicative only)

Measured once in the development container (Linux x86_64, release Rust archive,
Nim `-d:release`), verifying the committed fixtures with a warm process. These are
**not** guarantees and do not include wasm.

| Backend | Approx. verification time |
|---|---:|
| Groth16/BN254 | ~5.0 ms |
| PLONK/BN254 (genshi) | ~6.7 ms |
| Plonky2 | ~4.3 ms |
| Halo2 KZG/BN254 | ~10.0 ms |

Static archive sizes in this build after enabling Halo2 on wasm and protocol-shape
validation: Linux x86_64 49,496,168 bytes (~47.2 MiB), `wasm32-unknown-unknown`
33,142,524 bytes (~31.6 MiB), `wasm32-wasip1` 32,237,204 bytes (~30.7 MiB). These
are raw `.a` sizes, not compressed release assets. Memory usage, instruction counts,
and wasm runtime timings were not measured.
