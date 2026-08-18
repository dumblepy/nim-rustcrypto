import std/[os, strutils]

const rustCryptoResolveScript = currentSourcePath.parentDir.parentDir / "tools" / "resolve_rustcrypto_ffi.nim"

when defined(linux) and defined(amd64):
  const rustCryptoTargetArg = "linux-x86_64"
elif defined(wasi) or defined(rustcryptoWasi):
  const rustCryptoTargetArg = "wasm32-wasip1"
elif defined(wasm32):
  const rustCryptoTargetArg = "wasm32-unknown-unknown"
elif defined(macosx) and defined(arm64):
  const rustCryptoTargetArg = "macos-arm64"
elif defined(macosx):
  {.error: "rustcrypto FFI on macOS is supported only on Apple Silicon (arm64). macOS x86_64 is not supported.".}
else:
  {.error: "rustcrypto FFI static archive currently supports only Linux x86_64, macOS arm64, wasm32-unknown-unknown, and wasm32-wasip1.".}

const rustCryptoStaticLib* = staticExec(
  "nim r --hints:off --warnings:off " & rustCryptoResolveScript & " -- " & rustCryptoTargetArg
).strip

when rustCryptoStaticLib.len == 0:
  when defined(linux) and defined(amd64):
    {.error: "rustcrypto FFI static archive is not available for Linux x86_64. Run `nimble fetchRustFfi` or `nimble buildRustFfiLocal` from `/application`.".}
  elif defined(macosx) and defined(arm64):
    {.error: "rustcrypto FFI static archive is not available for macOS arm64. Run `nimble fetchRustFfi` or `nimble buildRustFfiLocal` from `/application`, or place the macos-arm64 vendor/cache archive before compiling.".}
  elif defined(wasi) or defined(rustcryptoWasi):
    {.error: "rustcrypto FFI static archive is not available for wasm32-wasip1. Run `nimble fetchRustFfi` from `/application`, or place the wasm32-wasip1 vendor/cache archive before compiling.".}
  elif defined(wasm32):
    {.error: "rustcrypto FFI static archive is not available for wasm32-unknown-unknown. Run `nimble fetchRustFfi` from `/application`, or place the vendor/cache archive before compiling.".}

{.passL: rustCryptoStaticLib.}

const
  SHA256DigestLen* = 32
  HmacSha256MacLen* = 32
  Sha3_256DigestLen* = 32
  Keccak256DigestLen* = 32
  Secp256k1SecretKeyLen* = 32
  Secp256k1PublicKeyCompressedLen* = 33
  Secp256k1PublicKeyUncompressedLen* = 65
  Secp256k1SignatureLen* = 64
  Secp256k1RecoverableSignatureLen* = 65
  Secp256k1SignatureDerMaxLen* = 72
  Secp256k1MessageDigestLen* = 32
  SchnorrPublicKeyLen* = 32
  SchnorrSignatureLen* = 64
  Ed25519PrivateKeyLen* = 32
  Ed25519PublicKeyLen* = 32
  Ed25519SignatureLen* = 64
  Ed25519PrivateKeyDerMaxLen* = 48
  Ed25519PublicKeyDerMaxLen* = 44
  Ed25519PrivateKeyPemMaxLen* = 119
  Ed25519PublicKeyPemMaxLen* = 113
  ChaCha20Poly1305KeyLen* = 32
  ChaCha20Poly1305NonceLen* = 12
  ChaCha20Poly1305TagLen* = 16
  Aes256GcmKeyLen* = 32
  Aes256GcmNonceLen* = 12
  Aes256GcmTagLen* = 16
  Aes256GcmSivKeyLen* = 32
  Aes256GcmSivNonceLen* = 12
  Aes256GcmSivTagLen* = 16
  Blake2b512DigestLen* = 64
  Blake2s256DigestLen* = 32
  RustCryptoOk* = 0.cint
  RustCryptoErrNullOutput* = 1.cint
  RustCryptoErrOutputTooShort* = 2.cint
  RustCryptoErrNullInputWithData* = 3.cint
  RustCryptoErrInvalidSecretKey* = 4.cint
  RustCryptoErrInvalidPublicKeyFormat* = 5.cint
  RustCryptoErrInvalidMessageDigest* = 6.cint
  RustCryptoErrInvalidSignature* = 7.cint
  RustCryptoErrVerificationFailed* = 8.cint
  RustCryptoErrInvalidLength* = 9.cint
  RustCryptoErrInvalidPrkLength* = 10.cint
  RustCryptoErrAuthenticationFailed* = 11.cint
  RustCryptoErrInvalidKeyLength* = 12.cint
  RustCryptoErrInvalidNonceLength* = 13.cint
  RustCryptoErrInvalidTagLength* = 14.cint
  RustCryptoErrInvalidParameter* = 15.cint
  RustCryptoErrInvalidPasswordHashFormat* = 16.cint
  RustCryptoErrInvalidCertificate* = 17.cint
  RustCryptoErrDecryptionFailed* = 18.cint
  RustCryptoErrRandomFailed* = 19.cint
  RustCryptoErrPanic* = -1.cint
  Secp256k1PublicKeyFormatUncompressed* = 0.cint
  Secp256k1PublicKeyFormatCompressed* = 1.cint
  HkdfSha256PrkLen* = 32
  HkdfSha256MaxOkmLen* = 32 * 255
  ScryptMaxOkmLen* = 137_438_953_440
  Argon2idMinHashLen* = 4
  Argon2idMaxHashLen* = 4_294_967_295
  BcryptHashLen* = 60
  BcryptMinCost* = 4
  BcryptMaxCost* = 31
  BcryptDefaultCost* = 12
  BcryptMaxPasswordLen* = 71
  Bls12381ScalarLen* = 32
  Bls12381G1CompressedLen* = 48
  Bls12381G1UncompressedLen* = 96
  Bls12381G2CompressedLen* = 96
  Bls12381G2UncompressedLen* = 192
  BlsPointFormatUncompressed* = 0.cint
  BlsPointFormatCompressed* = 1.cint

proc sha256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_sha256".}

proc blake2b512Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_blake2b_512".}

proc blake2s256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_blake2s_256".}

proc hmacSha256Raw*(
    key: ptr uint8,
    keyLen: csize_t,
    message: ptr uint8,
    messageLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hmac_sha256".}

proc pbkdf2HmacSha256Raw*(
    password: ptr uint8,
    passwordLen: csize_t,
    salt: ptr uint8,
    saltLen: csize_t,
    iterations: cuint,
    output: ptr uint8,
    outputLen: csize_t,
    derivedLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_pbkdf2_hmac_sha256".}

proc scryptRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    salt: ptr uint8,
    saltLen: csize_t,
    n: csize_t,
    r: csize_t,
    p: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    derivedLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_scrypt".}

proc argon2idDeriveRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    salt: ptr uint8,
    saltLen: csize_t,
    mCost: cuint,
    tCost: cuint,
    pCost: cuint,
    output: ptr uint8,
    outputLen: csize_t,
    derivedLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_argon2id_derive".}

proc argon2idHashPasswordRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    salt: ptr uint8,
    saltLen: csize_t,
    mCost: cuint,
    tCost: cuint,
    pCost: cuint,
    hashLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_argon2id_hash_password".}

proc argon2idVerifyPasswordRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    phc: ptr uint8,
    phcLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_argon2id_verify_password".}

proc passwordHashValidateRaw*(
    input: ptr uint8,
    inputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_password_hash_validate".}

proc passwordHashCanonicalizeRaw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_password_hash_canonicalize".}

proc bcryptHashPasswordRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    cost: cuint,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bcrypt_hash_password".}

proc bcryptVerifyPasswordRaw*(
    password: ptr uint8,
    passwordLen: csize_t,
    hash: ptr uint8,
    hashLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bcrypt_verify_password".}

proc bcryptValidateHashRaw*(
    hash: ptr uint8,
    hashLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bcrypt_validate_hash".}

proc bcryptCostRaw*(
    hash: ptr uint8,
    hashLen: csize_t,
    cost: ptr cuint,
  ): cint {.cdecl, importc: "rustcrypto_bcrypt_cost".}

proc hkdfSha256ExtractRaw*(
    salt: ptr uint8,
    saltLen: csize_t,
    ikm: ptr uint8,
    ikmLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_extract".}

proc hkdfSha256ExpandRaw*(
    prk: ptr uint8,
    prkLen: csize_t,
    info: ptr uint8,
    infoLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_expand".}

proc hkdfSha256DeriveRaw*(
    salt: ptr uint8,
    saltLen: csize_t,
    ikm: ptr uint8,
    ikmLen: csize_t,
    info: ptr uint8,
    infoLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_hkdf_sha256_derive".}

proc chacha20Poly1305EncryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_chacha20poly1305_encrypt".}

proc chacha20Poly1305DecryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_chacha20poly1305_decrypt".}

proc aes256GcmEncryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_aes256gcm_encrypt".}

proc aes256GcmDecryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_aes256gcm_decrypt".}

proc aes256GcmSivEncryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_aes256gcmsiv_encrypt".}

proc aes256GcmSivDecryptRaw*(
    key: ptr uint8,
    keyLen: csize_t,
    nonce: ptr uint8,
    nonceLen: csize_t,
    aad: ptr uint8,
    aadLen: csize_t,
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    tag: ptr uint8,
    tagLen: csize_t,
    plaintext: ptr uint8,
    plaintextLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_aes256gcmsiv_decrypt".}

proc sha3_256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_sha3_256".}

proc keccak256Raw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_keccak_256".}

proc secp256k1PublicKeyFromSecretKeyRaw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_public_key_from_secret_key".}

proc secp256k1EcdsaSignRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_prehash".}

proc secp256k1EcdsaSignSha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_sha256".}

proc secp256k1EcdsaSignSha3_256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_sha3_256".}

proc secp256k1EcdsaSignKeccak256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_keccak_256".}

proc secp256k1EcdsaSignRecoverablePrehashRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_sign_recoverable_prehash".}

proc secp256k1EcdsaVerifyRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_verify_prehash".}

proc secp256k1EcdsaVerifySha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_verify_sha256".}

proc secp256k1EcdsaVerifySha3_256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_verify_sha3_256".}

proc secp256k1EcdsaVerifyKeccak256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_verify_keccak_256".}

proc secp256k1EcdsaRecoverPublicKeyRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    recoverableSignature: ptr uint8,
    recoverableSignatureLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_recover_public_key".}

proc secp256k1EcdsaSignatureToDerRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_signature_to_der".}

proc secp256k1EcdsaSignatureFromDerRaw*(
    derSignature: ptr uint8,
    derSignatureLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_ecdsa_signature_from_der".}

proc schnorrPublicKeyFromSecretKeyRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_schnorr_public_key_from_secret_key".}

proc schnorrSignRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_schnorr_sign".}

proc schnorrVerifyRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_secp256k1_schnorr_verify".}

proc ed25519PrivateKeyToPkcs8DerRaw*(
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_to_pkcs8_der".}

proc ed25519PrivateKeyFromPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_from_pkcs8_der".}

proc ed25519PublicKeyToSpkiDerRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_to_spki_der".}

proc ed25519PublicKeyFromSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_spki_der".}

proc ed25519PublicKeyFromSecretKeyRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_secret_key".}

proc ed25519SignRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_sign".}

proc ed25519VerifyRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_verify".}

proc ed25519PrivateKeyToPkcs8PemRaw*(
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_to_pkcs8_pem".}

proc ed25519PrivateKeyFromPkcs8PemRaw*(
    pem: ptr uint8,
    pemLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_private_key_from_pkcs8_pem".}

proc ed25519PublicKeyToSpkiPemRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_to_spki_pem".}

proc ed25519PublicKeyFromSpkiPemRaw*(
    pem: ptr uint8,
    pemLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_ed25519_public_key_from_spki_pem".}

const
  P256SecretKeyLen* = 32
  P256PublicKeyCompressedLen* = 33
  P256PublicKeyUncompressedLen* = 65
  P256SignatureLen* = 64
  P256MessageDigestLen* = 32
  P256PrivateKeyDerMaxLen* = 256
  P256PublicKeyDerMaxLen* = 128
  P256PrivateKeyPemMaxLen* = 512
  P256PublicKeyPemMaxLen* = 256
  P384SecretKeyLen* = 48
  P384PublicKeyCompressedLen* = 49
  P384PublicKeyUncompressedLen* = 97
  P384SignatureLen* = 96
  P384MessageDigestLen* = 48
  P384PrivateKeyDerMaxLen* = 256
  P384PublicKeyDerMaxLen* = 160
  P384PrivateKeyPemMaxLen* = 512
  P384PublicKeyPemMaxLen* = 320
  X509CertDerMaxLen* = 8192
  X509CertPemMaxLen* = 11000
  RsaPrivateKeyDerMaxLen* = 4096
  RsaPublicKeyDerMaxLen* = 2048
  RsaPssSignatureMaxLen* = 4096
  RsaPkcs1v15SignatureMaxLen* = 4096
  P256PublicKeyFormatUncompressed* = 0.cint
  P256PublicKeyFormatCompressed* = 1.cint
  P384PublicKeyFormatUncompressed* = 0.cint
  P384PublicKeyFormatCompressed* = 1.cint

proc p256PublicKeyFromSecretKeyRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_p256_public_key_from_secret_key".}

proc p256EcdsaSignSha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_ecdsa_sign_sha256".}

proc p256EcdsaVerifySha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_ecdsa_verify_sha256".}

proc p256EcdsaSignPrehashRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_ecdsa_sign_prehash".}

proc p256EcdsaVerifyPrehashRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_ecdsa_verify_prehash".}

proc p256PrivateKeyToPkcs8DerRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_private_key_to_pkcs8_der".}

proc p256PrivateKeyFromPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_private_key_from_pkcs8_der".}

proc p256PublicKeyToSpkiDerRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p256_public_key_to_spki_der".}

proc p256PublicKeyFromSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    outputFormat: cint,
  ): cint {.cdecl, importc: "rustcrypto_p256_public_key_from_spki_der".}

proc p384PublicKeyFromSecretKeyRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_p384_public_key_from_secret_key".}

proc p384EcdsaSignSha384Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_ecdsa_sign_sha384".}

proc p384EcdsaVerifySha384Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_ecdsa_verify_sha384".}

proc p384EcdsaSignPrehashRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_ecdsa_sign_prehash".}

proc p384EcdsaVerifyPrehashRaw*(
    messageDigest: ptr uint8,
    messageDigestLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_ecdsa_verify_prehash".}

proc p384PrivateKeyToPkcs8DerRaw*(
    secretKey: ptr uint8,
    secretKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_private_key_to_pkcs8_der".}

proc p384PrivateKeyFromPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_private_key_from_pkcs8_der".}

proc p384PublicKeyToSpkiDerRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    publicKeyFormat: cint,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_p384_public_key_to_spki_der".}

proc p384PublicKeyFromSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    outputFormat: cint,
  ): cint {.cdecl, importc: "rustcrypto_p384_public_key_from_spki_der".}

proc x509CertValidateDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_validate_der".}

proc x509CertFromPemRaw*(
    pem: ptr uint8,
    pemLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_from_pem".}

proc x509CertToPemRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_to_pem".}

proc x509CertSubjectPublicKeyInfoDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_subject_public_key_info_der".}

proc x509CertSignatureAlgorithmOidRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_signature_algorithm_oid".}

proc x509CertSubjectDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_subject_der".}

proc x509CertIssuerDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_x509_cert_issuer_der".}

proc rsaPrivateKeyToPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_private_key_to_pkcs8_der".}

proc rsaPrivateKeyFromPkcs8DerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_private_key_from_pkcs8_der".}

proc rsaPublicKeyToSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_public_key_to_spki_der".}

proc rsaPublicKeyFromSpkiDerRaw*(
    der: ptr uint8,
    derLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_public_key_from_spki_der".}

proc rsaPssSignSha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    privateKeyDer: ptr uint8,
    privateKeyDerLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pss_sign_sha256".}

proc rsaPssVerifySha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKeyDer: ptr uint8,
    publicKeyDerLen: csize_t,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pss_verify_sha256".}

proc rsaPkcs1v15SignSha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    privateKeyDer: ptr uint8,
    privateKeyDerLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pkcs1v15_sign_sha256".}

proc rsaPkcs1v15VerifySha256Raw*(
    message: ptr uint8,
    messageLen: csize_t,
    publicKeyDer: ptr uint8,
    publicKeyDerLen: csize_t,
    signature: ptr uint8,
    signatureLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pkcs1v15_verify_sha256".}

proc rsaOaepSha256EncryptRaw*(
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    publicKeyDer: ptr uint8,
    publicKeyDerLen: csize_t,
    label: ptr uint8,
    labelLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_oaep_sha256_encrypt".}

proc rsaOaepSha256DecryptRaw*(
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    privateKeyDer: ptr uint8,
    privateKeyDerLen: csize_t,
    label: ptr uint8,
    labelLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_oaep_sha256_decrypt".}

proc rsaPkcs1v15EncryptRaw*(
    plaintext: ptr uint8,
    plaintextLen: csize_t,
    publicKeyDer: ptr uint8,
    publicKeyDerLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pkcs1v15_encrypt".}

proc rsaPkcs1v15DecryptRaw*(
    ciphertext: ptr uint8,
    ciphertextLen: csize_t,
    privateKeyDer: ptr uint8,
    privateKeyDerLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    writtenLen: ptr csize_t,
  ): cint {.cdecl, importc: "rustcrypto_rsa_pkcs1v15_decrypt".}

proc bls12_381ScalarValidateRaw*(
    scalar: ptr uint8,
    scalarLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_scalar_validate".}

proc bls12_381ScalarRandomRaw*(
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_scalar_random".}

proc bls12_381ScalarAddRaw*(
    lhs: ptr uint8,
    lhsLen: csize_t,
    rhs: ptr uint8,
    rhsLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_scalar_add".}

proc bls12_381ScalarMulRaw*(
    lhs: ptr uint8,
    lhsLen: csize_t,
    rhs: ptr uint8,
    rhsLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_scalar_mul".}

proc bls12_381ScalarInvertRaw*(
    scalar: ptr uint8,
    scalarLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_scalar_invert".}

proc bls12_381G1GeneratorRaw*(
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g1_generator".}

proc bls12_381G2GeneratorRaw*(
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g2_generator".}

proc bls12_381G1ValidateRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g1_validate".}

proc bls12_381G2ValidateRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g2_validate".}

proc bls12_381G1AddRaw*(
    lhs: ptr uint8,
    lhsLen: csize_t,
    rhs: ptr uint8,
    rhsLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g1_add".}

proc bls12_381G2AddRaw*(
    lhs: ptr uint8,
    lhsLen: csize_t,
    rhs: ptr uint8,
    rhsLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g2_add".}

proc bls12_381G1NegRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g1_neg".}

proc bls12_381G2NegRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g2_neg".}

proc bls12_381G1MulRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    scalar: ptr uint8,
    scalarLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g1_mul".}

proc bls12_381G2MulRaw*(
    point: ptr uint8,
    pointLen: csize_t,
    scalar: ptr uint8,
    scalarLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
    compressed: cint,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_g2_mul".}

proc bls12_381PairingEqRaw*(
    g1Lhs: ptr uint8,
    g1LhsLen: csize_t,
    g2Lhs: ptr uint8,
    g2LhsLen: csize_t,
    g1Rhs: ptr uint8,
    g1RhsLen: csize_t,
    g2Rhs: ptr uint8,
    g2RhsLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_pairing_eq".}

proc bls12_381PairingProductIsIdentityRaw*(
    g1Points: ptr uint8,
    g1PointsLen: csize_t,
    g2Points: ptr uint8,
    g2PointsLen: csize_t,
    pairCount: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_pairing_product_is_identity".}

proc bls12_381SignaturePrivateKeyFromSeedRaw*(
    seed: ptr uint8,
    seedLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_private_key_from_seed".}

proc bls12_381SignaturePrivateKeyGenerateRaw*(
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_private_key_generate".}

proc bls12_381SignaturePrivateKeyFromDecimalStringRaw*(
    input: ptr uint8,
    inputLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_private_key_from_decimal_string".}

proc bls12_381SignaturePublicKeyRaw*(
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_public_key".}

proc bls12_381SignatureHashRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_hash".}

proc bls12_381SignatureSignRaw*(
    message: ptr uint8,
    messageLen: csize_t,
    privateKey: ptr uint8,
    privateKeyLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_sign".}

proc bls12_381SignatureAggregateRaw*(
    signatures: ptr uint8,
    signaturesLen: csize_t,
    signatureCount: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_aggregate".}

proc bls12_381SignatureVerifyRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    hashes: ptr uint8,
    hashesLen: csize_t,
    publicKeys: ptr uint8,
    publicKeysLen: csize_t,
    pairCount: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_verify".}

proc bls12_381SignatureVerifyMessagesRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    messages: ptr ptr uint8,
    messageLens: ptr csize_t,
    messageCount: csize_t,
    publicKeys: ptr uint8,
    publicKeysLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_verify_messages".}

proc bls12_381SignatureHashG1AugRaw*(
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
    message: ptr uint8,
    messageLen: csize_t,
    output: ptr uint8,
    outputLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_hash_g1_aug".}

proc bls12_381SignatureVerifyG1AugHashRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    messageHash: ptr uint8,
    messageHashLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_verify_g1_aug_hash".}

proc bls12_381SignatureVerifyG1AugMessageRaw*(
    signature: ptr uint8,
    signatureLen: csize_t,
    message: ptr uint8,
    messageLen: csize_t,
    publicKey: ptr uint8,
    publicKeyLen: csize_t,
  ): cint {.cdecl, importc: "rustcrypto_bls12_381_signature_verify_g1_aug_message".}
