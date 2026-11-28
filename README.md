# rustcrypto — Cryptography for Nim

Nim bindings to RustCrypto through a small Rust FFI static library. High-level APIs cover common protocols; low-level modules expose one primitive per file under `rustcrypto/algorithm/`.

- **Upstream**: [RustCrypto](https://github.com/RustCrypto)
- **License**: Dual-licensed (MIT / Apache-2.0)

## Features (summary)

Hashing (SHA-256, SHA3-256, Keccak-256, BLAKE2, Poseidon1/BN254, **Poseidon2/BN254**), HMAC, HKDF, PBKDF2, scrypt, Argon2id, bcrypt, AEAD (ChaCha20-Poly1305, AES-256-GCM, AES-256-GCM-SIV), secp256k1 (ECDSA, Schnorr, recoverable ECDSA), Ed25519, NIST P-256 / P-384 ECDSA, **BLS12-381** (low-level curve/pairing via [`blst`](https://github.com/supranational/blst), `bls-signatures`-compatible minimal-pk-size signing, and minimal-signature-size G2-pk / G1-sig AUG hash-to-G1 verification), RSA (sign/verify, OAEP, PKCS#1 v1.5), X.509 minimal parsing, PKCS#8 / SPKI / PEM for supported keys, plus **Bitcoin**, **Lightning (BOLT-11 signing)**, **Ethereum**, **JWT** helpers, and **zero-knowledge proof verifiers** (Groth16/BN254, a fixed PLONK/BN254 profile, Plonky2/Goldilocks, a fixed Halo2 KZG/BN254 profile, and a **transparent Halo2 IPA/BN254 profile with no trusted setup**).

## Installation

```sh
nimble add "https://github.com/itsumura-h/nim-rustcrypto"
```

Or in your `.nimble` file:

```nim
requires "https://github.com/itsumura-h/nim-rustcrypto"
```

On Linux x86_64, `nimble add` / `nimble install` automatically downloads and unpacks the Rust FFI static archive from GitHub Release, so normal consumers do not need Rust installed. Use `nimble fetchRustFfi` or `nimble buildRustFfiLocal` only when you need to refresh the archive during development.

## Target support

Linux x86_64, macOS arm64, `wasm32-unknown-unknown`, and `wasm32-wasip1` ship Rust FFI
static archives. The Halo2 KZG/BN254 verifier is now available on both wasm targets:
the committed v1 fixture is verified through the C ABI under Node `WebAssembly`
(`wasm32-unknown-unknown`) and Node WASI (`wasm32-wasip1`), while native targets keep
the parallel verification path. See [Halo2 docs](docs/halo2.md) for the exact tested
runtimes, the vendored `halo2-axiom` feature patch, and security notes.

The **Halo2 IPA/BN254** profile (no trusted setup) and **Poseidon2/BN254** are also
verified on both wasm targets. Their wasm smokes execute the committed KATs/fixture
under Node. The Poseidon2 cdylib has zero host imports; the IPA verifier is executed
with every imported host function replaced by a throwing stub, proving the verify
path does not request RNG or OS services. Browser Web Worker proving (cubic id 1
and Poseidon2 hash3 id 2), verify-only ICP canisters with an IPA params cache
(PocketIC-measured, including circuit id 2 VK pinning but not in-canister
proving), a registered 3-input Poseidon2 hash circuit (id 2) with arbitrary
arity `0x100+n`, and a Poseidon2 Halo2 custom-gate `wasm32-wasip1` prove/verify
run are included.

> **Poseidon2 artifact revision (V2).** The P0 soundness fix zero-constrains every
> unused sponge absorb lane and the capacity addend, which changes the Poseidon2
> VK/PK. Poseidon2 keys now use the V2 envelopes `RCH2IPV2` / `RCH2IPP2`; cubic
> id 1 keeps V1 `RCH2IPV1` / `RCH2IPP1`, and proof/instances stay `RCH2IPF1` /
> `RCH2IPI1`. Old V1-magic Poseidon2 artifacts are rejected, so the committed
> Poseidon2 fixtures and the wasm/browser/ICP results recorded above (measured
> against the old V1 circuit) must be regenerated and re-run. Do not accept a
> pinned old VK/proof as the new circuit.

The same profile now exposes a reusable **`Poseidon2Chip`** (pass already-assigned
cells, copy-constrain them, publish only caller-selected cells) and a compile-time
**external-circuit adapter** (`rustcrypto-ffi/src/halo2_ipa_registry.rs`) with
`CircuitProfile` / `ApprovedCircuit`, generic prepare/prove/verify, VK/params
digest helpers, and the `halo2_ipa_export_circuit!` /
`halo2_ipa_export_circuit_verifier!` macros. A 17-public-value composite example
lives in `examples/halo2-ipa-external-circuit/`. Registration is compile-time only;
there is no runtime circuit descriptor or arbitrary code loading. Everything here
is still **un-audited**; see
[Halo2 IPA docs](docs/halo2-ipa.md) and [Poseidon2 docs](docs/poseidon2-bn254.md).

公開鍵による非対話暗号化: [RFC 9180 HPKE Base mode](docs/hpke.md) (`Hpke.generateSecretKey/publicKey/seal/open`)。

## Documentation

Per-primitive and per-protocol guides (English):

### Hashing and MAC

- [SHA-256](docs/sha256.md)
- [SHA3-256 and Keccak-256](docs/sha3-keccak.md)
- [BLAKE2b-512 / BLAKE2s-256](docs/blake2.md)
- [HMAC-SHA256](docs/hmac.md)

### Key derivation and passwords

- [HKDF-SHA256](docs/hkdf.md)
- [PBKDF2-HMAC-SHA256](docs/pbkdf2.md)
- [scrypt](docs/scrypt.md)
- [Argon2id](docs/argon2.md)
- [bcrypt](docs/bcrypt.md)
- [PHC string validate / canonicalize](docs/password-hash-phc.md)

### AEAD

- [ChaCha20-Poly1305](docs/chacha20-poly1305.md)
- [AES-256-GCM](docs/aes-256-gcm.md)
- [AES-256-GCM-SIV](docs/aes-256-gcm-siv.md)

### Elliptic-curve signatures and encodings

- [secp256k1 ECDSA](docs/secp256k1-ecdsa.md)
- [secp256k1 ECDSA (DER)](docs/secp256k1-ecdsa-der.md)
- [secp256k1 Schnorr (BIP340-style)](docs/secp256k1-schnorr.md)
- [Ed25519](docs/ed25519.md)
- [P-256 ECDSA](docs/p256-ecdsa.md)
- [P-384 ECDSA](docs/p384-ecdsa.md)
- [BLS12-381 (curve / pairing / minimal BLS)](docs/bls12-381.md)

### RSA and certificates

- [RSA signatures and encryption](docs/rsa-signatures-and-encryption.md)
- [X.509 (minimal)](docs/x509-certificates.md)
- [PKCS#8, SPKI, PEM (keys)](docs/key-encoding-pkcs8-pem.md)

### Zero-knowledge proof verifiers

- [BN254 fields and curve encodings](docs/bn254.md)
- [Poseidon / BN254](docs/poseidon-bn254.md)
- [Poseidon2 / BN254 (Noir/Barretenberg-compatible)](docs/poseidon2-bn254.md)
- [Poseidon2 / BN254 Halo2 custom gate / IPA circuits](docs/poseidon2-halo2-gate.md)
- [Poseidon2 / BN254 Halo2 gate on wasm32-wasip1](docs/poseidon2-halo2-wasm.md)
- [Poseidon2 Halo2 browser Worker / ICP verifier](docs/poseidon2-halo2-browser-icp.md)
- [Poseidon1 / BN254 Halo2 custom gate (comparison demo)](docs/poseidon1-halo2-gate.md)
- [Groth16 / BN254 verifier](docs/groth16-bn254.md)
- [PLONK / BN254 verifier (genshi-core profile)](docs/plonk-bn254.md)
- [Plonky2 / Goldilocks / FRI verifier](docs/plonky2.md)
- [Halo2 KZG / BN254 verifier (PSE/Axiom SHPLONK profile)](docs/halo2.md)
- [Halo2 IPA / BN254 (transparent, no trusted setup)](docs/halo2-ipa.md)
- [Branch 85 benchmarks (Poseidon1/Poseidon2, IPA 1k/20k)](docs/benchmarks-branch85.md)
- [ICP canisters (IPA verify / Poseidon2 hash)](docs/ic-branch85.md)
- [ZKP verifier dependencies, licenses, and target matrix](docs/zkp-dependencies.md)
- [Bulletproofs R1CS / Ristretto255 prover and verifier (opt-in PoC)](docs/bulletproofs-r1cs.md)

### High-level protocol helpers

- [Bitcoin](docs/bitcoin.md)
- [Lightning (invoice signing)](docs/lightning.md)
- [Ethereum](docs/ethereum.md)
- [JWT (JWS compact)](docs/jwt-json-web-tokens.md)

### FFI

- [Low-level `algorithm/ffi`](docs/ffi-low-level.md)

## Development

Build and test Rust from `rustcrypto-ffi`, Nim from the repository root (see project rules for exact commands). On GitHub, CI exercises the Nim test suite with the prebuilt static archive workflow.

## License

Use under **MIT** or **Apache-2.0**, at your option.

Groth16/BN254 の回路構築と proof 生成: [Groth16 prover](docs/groth16-prover.md)。
