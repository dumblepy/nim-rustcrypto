# ZKP verifier dependencies and licenses

This repository adds four independent proof-verification backends. They do not share
proof formats. The versions below are pinned in `rustcrypto-ffi/Cargo.lock`.

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
