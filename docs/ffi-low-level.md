# Low-level FFI (`algorithm/ffi`)

Module: `rustcrypto/algorithm/ffi`

This module binds the static Rust archive and exposes `importc` C ABI functions (`*Raw` suffix in many call sites inside the library). High-level Nim wrappers in `rustcrypto/algorithm/*` are preferred: they pack buffers, translate status codes into `ValueError`, and use fixed-size types.

## Platform

Supported targets are defined in `ffi.nim` (for example Linux x86_64, `wasm32-unknown-unknown`, and `wasm32-wasip1`); other combinations fail at compile time with an error from that module.

## BLS12-381 (`rustcrypto_bls12_381_*`)

Length constants are exported from `ffi.nim` as `Bls12381ScalarLen` (32), `Bls12381G1CompressedLen` (48), `Bls12381G2CompressedLen` (96), and the corresponding uncompressed sizes. Curve points use `BlsPointFormatCompressed` / `BlsPointFormatUncompressed` with the `*_g1_*` / `*_g2_*` functions. Signature helpers use the `rustcrypto_bls12_381_signature_*` prefix.

Minimal-pk-size (G1 public key, G2 signature/hash, NUL DST): `signature_hash`, `signature_sign`, `signature_verify`, `signature_verify_messages`, and related key helpers.

Minimal-signature-size + message augmentation (G2 public key, G1 signature/hash, AUG DST over `publicKey || message`):

- `rustcrypto_bls12_381_signature_hash_g1_aug`
- `rustcrypto_bls12_381_signature_verify_g1_aug_hash`
- `rustcrypto_bls12_381_signature_verify_g1_aug_message`

Prefer the high-level `rustcrypto/algorithm/bls` module when possible.

## Zero-knowledge proof verifier families

- **BN254 / Poseidon / Groth16:** `rustcrypto_bn254_*`, `rustcrypto_poseidon_bn254_*`,
  and `rustcrypto_groth16_bn254_*`. Verification helpers include
  `rustcrypto_groth16_bn254_verify`, `_vk_validate`, and `_proof_validate`.
- **PLONK (genshi-core profile):** `rustcrypto_plonk_bn254_verify`, `_vk_validate`,
  `_proof_validate`.
- **Plonky2:** `rustcrypto_plonky2_verify`, `rustcrypto_plonky2_verifier_validate`,
  `rustcrypto_plonky2_common_validate`.
- **Halo2 (PSE/Axiom KZG/BN254, SHPLONK, Blake2b):**
  `rustcrypto_halo2_kzg_bn254_verify`, `_params_validate`, `_vk_validate`, and
  `_instances_validate`. Native targets only; the wasm archives do not contain these
  symbols.

All verifier entry points return `RustCryptoOk` on success,
`RustCryptoErrVerificationFailed` for a well-formed but invalid proof, and a distinct
error code for malformed inputs. See the per-algorithm documents for wire formats and
compatibility profiles.

## Typical pattern

1. Allocate output buffers with correct lengths (see `*Len` constants in the same module).
2. Pass pointers via `bytesPtr` from `rustcrypto/algorithm/common` for `string` and `openArray[byte]`.
3. Check the returned `cint` status against `RustCryptoOk`.

```nim
import rustcrypto/algorithm/ffi
import rustcrypto/algorithm/common

var outDigest: array[SHA256DigestLen, byte]
let st = sha256Raw(
  bytesPtr("abc"),
  csize_t(3),
  cast[ptr uint8](addr outDigest[0]),
  csize_t(outDigest.len),
)
if st != RustCryptoOk:
  raise newException(ValueError, "sha256Raw failed: " & $st)
```

`common.raiseRustCryptoStatus` is a small helper that throws on non-zero status.

## Status codes (subset)

The following are used across primitives (see `ffi.nim` for the full list):

| Constant | Meaning |
|----------|---------|
| `RustCryptoOk` | Success |
| `RustCryptoErrNullOutput` | Required output pointer was nil |
| `RustCryptoErrOutputTooShort` | Output buffer too small |
| `RustCryptoErrNullInputWithData` | Nil pointer with non-zero length |
| `RustCryptoErrAuthenticationFailed` | AEAD tag verification failed |
| `RustCryptoErrVerificationFailed` | Signature or proof verification failed |
| `RustCryptoErrInvalidFieldElement` (20) | Non-canonical BN254 field element |
| `RustCryptoErrInvalidCurvePoint` (21) | Off-curve / wrong-subgroup point |
| `RustCryptoErrInvalidProofFormat` (22) | Malformed proof encoding |
| `RustCryptoErrInvalidVerifyingKey` (23) | Malformed verifying key |
| `RustCryptoErrInvalidPublicInputCount` (24) | Public-input count mismatch |
| `RustCryptoErrInvalidCircuitData` (25) | Malformed Plonky2 common circuit data |
| `RustCryptoErrPanic` | Rust side caught a panic at the FFI boundary |

Prefer the typed wrappers (`sha256`, `aes256gcmEncrypt`, …) unless you are extending the library.
