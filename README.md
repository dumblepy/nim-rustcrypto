# rustcrypto — Cryptography for Nim

Nim bindings to RustCrypto through a small Rust FFI static library. High-level APIs cover common protocols; low-level modules expose one primitive per file under `rustcrypto/algorithm/`.

- **Upstream**: [RustCrypto](https://github.com/RustCrypto)
- **License**: Dual-licensed (MIT / Apache-2.0)

## Features (summary)

Hashing (SHA-256, SHA3-256, Keccak-256, BLAKE2), HMAC, HKDF, PBKDF2, scrypt, Argon2id, bcrypt, AEAD (ChaCha20-Poly1305, AES-256-GCM, AES-256-GCM-SIV), secp256k1 (ECDSA, Schnorr, recoverable ECDSA), Ed25519, NIST P-256 / P-384 ECDSA, **BLS12-381** (low-level curve/pairing via [`blst`](https://github.com/supranational/blst), `bls-signatures`-compatible minimal-pk-size signing, and minimal-signature-size G2-pk / G1-sig AUG hash-to-G1 verification), RSA (sign/verify, OAEP, PKCS#1 v1.5), X.509 minimal parsing, PKCS#8 / SPKI / PEM for supported keys, plus **Bitcoin**, **Lightning (BOLT-11 signing)**, **Ethereum**, and **JWT** helpers.

## Installation

```sh
nimble add "https://github.com/itsumura-h/nim-rustcrypto"
```

Or in your `.nimble` file:

```nim
requires "https://github.com/itsumura-h/nim-rustcrypto"
```

On Linux x86_64, `nimble add` / `nimble install` automatically downloads and unpacks the Rust FFI static archive from GitHub Release, so normal consumers do not need Rust installed. Use `nimble fetchRustFfi` or `nimble buildRustFfiLocal` only when you need to refresh the archive during development.

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
