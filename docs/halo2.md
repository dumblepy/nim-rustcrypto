# Halo2 verification (PSE/Axiom KZG / BN254 / SHPLONK / Blake2b)

Module: `rustcrypto/algorithm/halo2` (marker type `Halo2KzgBn254`)

> **Fixed Halo2 profile.** Halo2 is not a single proof format. This module accepts only
> the profile below. Zcash `halo2_proofs` IPA/Pasta proofs, PSE Poseidon-transcript
> proofs, EVM/Keccak-transcript proofs, and gnark PLONK proofs are different and are
> rejected.

## Profile (v1)

| Item | Value |
|---|---|
| Implementation | `snark-verifier` 0.2.7 over `halo2-axiom` 0.5.3 (PSE-halo2 derivative) |
| Curve / field | BN254, `Fr` |
| PCS | KZG with a universal SRS |
| Multi-open | **SHPLONK** (`snark_verifier::pcs::kzg::Bdfg21`) |
| Fiat-Shamir | halo2 `Blake2bRead` / `Blake2bWrite`, `b"Halo2-Transcript"`, 64-byte challenges |
| Protocol encoding | `bincode` 1.3.3, fixed-int, of `PlonkProtocol<G1Affine>` |
| Verifier | `PlonkVerifier<KzgAs<Bn254, Bdfg21>>` + `KzgDecidingKey<Bn254>` |

Why not Zcash IPA/Pasta: the Zcash `halo2_proofs` 0.3/0.4 API does not expose a
circuit-independent verifying-key deserializer, so a generic "verify with external
VK bytes" API cannot be built on it without reimplementing the verifier or pinning a
concrete circuit. The PSE/Axiom KZG profile exposes a data-only `PlonkProtocol` and is
therefore used here.

## API

```nim
import rustcrypto/algorithm/halo2

let params: seq[byte] = ...          # v1 SRS subset
let vk: seq[byte] = ...              # v1 protocol
let proof: seq[byte] = ...           # Blake2b SHPLONK proof bytes
let publicInstances: seq[byte] = ... # v1 instance columns

if Halo2KzgBn254.verify(params, vk, proof, publicInstances):
  echo "valid for this profile, SRS, and key"
```

Helpers: `validateParams`, `validateVerifyingKey`, `validatePublicInstances`.

`false` means structurally valid but not verifying. Malformed blobs, non-canonical
field values, mismatched instance columns, and trailing bytes raise `ValueError`.

## Wire format v1

### Params — SRS subset (exactly 328 bytes)

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2P1\0\0"` |
| 8 | 64 | `[1]_1` (G1) |
| 72 | 128 | `[1]_2` (G2) |
| 200 | 128 | `[tau]_2` (G2) |

Points use the canonical big-endian encoding from [bn254.md](bn254.md). Points must be
on-curve and in the prime-order subgroup; infinity is rejected.

### Verifying key

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2V1\0\0"` |
| 8 | 4 | `protocol_len` (`u32` BE, 1..=2 MiB) |
| 12 | `protocol_len` | `bincode(PlonkProtocol<G1Affine>)` |

Protocol deserialization is bounded to 2 MiB, rejects trailing bytes, bounds the
instance/witness column counts, and validates every protocol G1 commitment (preprocessed and instance-committing)
(on-curve + prime-order subgroup).

### Public instances

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2I1\0\0"` |
| 8 | 4 | `column_count` (`u32` BE, ≤ 64) |
| 12 | — | repeated columns |

Each column:

| Size | Field |
|---|---|
| 4 | `value_count` (`u32` BE) |
| `value_count * 32` | canonical big-endian `Fr` values |

The total number of values is bounded at `2^20`. There must be exactly one column per
protocol instance polynomial, with exactly the expected number of values in each.
Trailing bytes are rejected.

### Proof

Raw bytes written by halo2's `Blake2bWrite` transcript for the **SHPLONK** prover.
Proof length is bounded at 16 MiB. The verifier reads the proof with a counting reader
and rejects trailing bytes.

## Fixtures and tests

`rustcrypto-ffi/examples/halo2_fixture.rs` builds a small halo2-axiom circuit (an advice
cell constrained equal to one public instance), generates `ParamsKZG::setup(8, rng)` with
a **seeded, test-only SRS**, and writes the v1 params/VK/proof/instances. The fixture is
committed at `tests/fixtures/halo2_kzg_bn254_v1.hex`.

Tests cover successful verification plus modified instances, modified proofs, modified
params, truncated/trailing blobs, wrong column layouts, and non-canonical instance
values. A Rust unit test verifies the committed fixture directly.

## Target support

- Native Linux x86_64 and macOS arm64: supported.
- `wasm32-unknown-unknown` / `wasm32-wasip1`: **not supported**.
  `halo2-axiom` unconditionally uses Rayon parallel iterators that do not compile for
  these targets. The Rust module is compiled only for non-wasm targets; importing
  `rustcrypto/algorithm/halo2` on wasm produces a clear compile-time error.

The repository's wasm archives therefore do not export `rustcrypto_halo2_*` symbols.
Do not advertise Halo2 verification on wasm.

## Security notes

- The SRS and verifying key (circuit) are caller-supplied. Trusting them, and binding
  them to an approved circuit/version, is the application's responsibility.
- This profile requires a KZG trusted setup. The fixture SRS is deliberately insecure
  and must never be used for production.
- `snark-verifier` / `halo2-axiom` are not audited by this project.
- The API verifies the pairing equation and PLONK constraints; it does not prove that
  the circuit represents a meaningful application statement.
