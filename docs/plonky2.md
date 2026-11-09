# Plonky2 / Goldilocks / FRI verification

Module: `rustcrypto/algorithm/plonky2` (marker type `Plonky2Goldilocks`)

## Fixed profile

- **Implementation:** `qp-plonky2` 1.6.0 (Quantus fork of Polygon Zero Plonky2),
  imported under the crate name `plonky2`.
  - Upstream `plonky2` 1.1.0 requires nightly `specialization`; this project keeps the
    stable Rust toolchain by using the fork, which gates specialization behind a
    `nightly` cfg.
- **Field:** Goldilocks (64-bit).
- **Extension degree:** `D = 2`.
- **Hash/config:** `PoseidonGoldilocksConfig`.
- **Circuit config / FRI parameters:** taken from the supplied `CommonCircuitData`;
  this library does not impose a `CircuitConfig`.
- **Serialization:** Plonky2's own byte encodings.

A proof from a different Plonky2 commit, gate set, hash configuration, FRI
configuration, or `D` is not interchangeable.

## API

```nim
import rustcrypto/algorithm/plonky2

let proof: seq[byte] = ...            # ProofWithPublicInputs::to_bytes()
let verifierData: seq[byte] = ...     # VerifierOnlyCircuitData::to_bytes()
let commonData: seq[byte] = ...       # CommonCircuitData::to_bytes(DefaultGateSerializer)

if Plonky2Goldilocks.verify(proof, verifierData, commonData):
  echo "valid for this circuit"
```

Helpers: `validateVerifierCircuitData`, `validateCommonCircuitData`.

`false` means structurally valid but not verifying; malformed blobs raise `ValueError`.

## Wire format v1

This API accepts the three native plonky2 byte blobs directly:

| Argument | Producer |
|---|---|
| `proofWithPublicInputs` | `ProofWithPublicInputs::to_bytes()` |
| `verifierOnlyCircuitData` | `VerifierOnlyCircuitData::to_bytes()` |
| `commonCircuitData` | `CommonCircuitData::to_bytes(&DefaultGateSerializer)` |

Public inputs are committed **inside** `ProofWithPublicInputs`; there is no separate
public-input argument. The proof is parsed against the supplied common circuit data.
All three blobs are limited to 16 MiB. The common data is additionally bounded to
`degree_bits <= 28`, at most 4096 gates, and at most `2^20` public inputs.

Trailing bytes inside the Plonky2 encodings follow the upstream parser's rules; the
top-level blob length is bounded and invalid encodings fail closed.

## Fixtures and tests

`rustcrypto-ffi/examples/plonky2_fixture.rs` generates two deterministic circuits:

- `MUL`: `c = a * b`, public input `15`.
- `ADD`: `c = a + b`, public inputs `8` and `3` (different `num_public_inputs` so the
  common circuit data differs).

The fixtures are committed at `tests/fixtures/plonky2_v1.hex`. Tests verify both proofs
and reject mixture of proof/verifier/common data, tampered proofs, truncated blobs, and
empty inputs. A Rust unit test also regenerates a proof and checks tamper rejection.

## Target support

The verifier builds for native Linux x86_64, macOS arm64, `wasm32-unknown-unknown`, and
`wasm32-wasip1`. The Rust archive compilation succeeds for both wasm targets; execution
and performance in a wasm runtime have not been measured in this repository. Proof
**generation** is not part of the library and is not supported on wasm.

## Security notes

- Plonky2 proofs are configuration-specific. Pin the `verifierOnlyCircuitData` and
  `commonCircuitData` (including the circuit digest) to an approved circuit.
- Supplying an arbitrary circuit data blob is not a statement about application
  approval. The caller must maintain the trust policy.
- The fork and the underlying Plonky2 implementation are not audited by this project.
- FRI/Goldilocks verification is mathematically distinct from the BN254/Groth16,
  PLONK, and Halo2 verifiers in this repository. Proofs are not interchangeable.
