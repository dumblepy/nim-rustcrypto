# PLONK / BN254 verification (genshi-core profile)

Module: `rustcrypto/algorithm/plonk` (marker type `PlonkBn254`)

> **This is a fixed, non-gnark profile.** It does not accept generic "PLONK" proofs.
> The target implementation is **genshi-core 0.3.0**, a 4-wire PLONKish/KZG system over
> BN254 with its own Keccak Fiat-Shamir transcript. gnark, snarkjs, dusk-plonk, and
> PSE-halo2 proofs are different formats and are rejected.

## Why this profile

The design document asks for a PLONK/BN254 verifier with a precisely identified target
implementation, proof/VK format, KZG handling, and transcript. At the time of this
implementation there is no mature, audited Rust verifier that accepts gnark's PLONK
wire format directly. Instead of pretending byte compatibility, this module pins a
single data-only implementation and documents the incompatibility.

- **Curve/field:** BN254 (`ark-bn254` 0.5), scalar field `Fr`.
- **Arithmetization:** 4-wire PLONKish with selector commitments.
- **PCS:** KZG with a universal SRS.
- **Transcript:** genshi's Keccak-based transcript (`b"genshi_plonk"` domain separator).
- **Serialization:** genshi-core canonical big-endian encodings.
- **Dependency:** `genshi-core` / `genshi-math` 0.3.0, MIT OR Apache-2.0, pinned in `Cargo.lock`.

## API

```nim
import rustcrypto/algorithm/bn254
import rustcrypto/algorithm/plonk

let vk: seq[byte] = ...      # v1 verifying key
let proof: seq[byte] = ...   # genshi-core proof bytes
let publicInputs = @[fromHexFr("...")]

if PlonkBn254.verify(vk, proof, publicInputs):
  echo "valid for this profile and key"
```

Helpers: `PlonkBn254.validateVerifyingKey(vk)`, `PlonkBn254.validateProof(proof)`.

`false` means structurally valid but not verifying; malformed inputs raise `ValueError`.

## Wire format v1

### Verifying key (`1148` bytes)

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCPLK1\0\0"` |
| 8 | 128 | KZG SRS `[1]_2` (G2) |
| 136 | 128 | KZG SRS `[tau]_2` (G2) |
| 264 | 4 | `vk_len` (`u32`, must be 880) |
| 268 | 880 | genshi-core `vk_to_bytes` |

The blob includes the selector commitments, permutation commitments, domain size,
public-input count, domain generator `omega`, and wire-copy permutation parameters.
The KZG verifier assumes `[1]_1` is the BN254 G1 generator. The SRS G2 elements must
come from the same trusted setup that produced the commitments.

### Proof

`genshi-core::proving::serialization::proof_to_bytes`. The exact length is
`1028 + 64 * num_t_comms`, where `num_t_comms` is the little-endian `u32` at offset 320.
`num_t_comms` is bounded at 1024 and trailing bytes are rejected. The encoding contains:

```text
w_comms[4] || z_comm || num_t_comms (u32 LE) || t_comms[num_t]
|| w_evals[4] || sigma_evals[4] || z_eval || z_omega_eval
|| selector_evals[7] || t_eval || w_zeta || w_zeta_omega
```

### Public inputs

A flat array of canonical 32-byte big-endian `Fr` values, in the order expected by the
circuit. The count must equal the verifying key's `num_public_inputs`.

## Fixtures and tests

`rustcrypto-ffi/examples/plonk_fixture.rs` generates a proof with genshi's
**insecure test SRS** (`SRS::insecure_for_testing(128)`) for a small addition circuit.
The fixture is committed at `tests/fixtures/plonk_bn254_v1.hex`.

Nim tests cover valid verification, a modified public input, a modified proof point,
a modified VK point, truncated/oversized proofs, wrong input counts, and non-canonical
field elements. Rust tests cover malformed VK/proof structures and panic containment.

## Target support

The verifier path is pure Rust and builds on native Linux x86_64, macOS arm64, and both
wasm targets. The wasm build only proves compilation; execution/performance has not been
measured in this repository. The SRS/proof fixture is test-only and must not be used in
production.

## Security notes

- **No gnark compatibility is claimed.** Do not feed gnark/snarkjs PLONK artifacts to
  this API.
- genshi-core is a young implementation and is not audited by this project or, to our
  knowledge, by a third party. Treat it as experimental.
- The verifying key and SRS are caller-supplied. Approving a circuit/key and using a
  trustworthy SRS ceremony are the application's responsibility.
- The verifier only checks the PLONK constraints and KZG pairing equations. It does not
  establish that a circuit encodes a meaningful statement.
