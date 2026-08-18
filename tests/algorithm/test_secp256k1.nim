import unittest

import ./utils
import ../../src/rustcrypto/algorithm/sha256
import ../../src/rustcrypto/algorithm/secp256k1

suite "secp256k1":
  test "raw compressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoOk
    check hexOf(output) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "raw uncompressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    var output: Secp256k1UncompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatUncompressed,
    )

    check status == RustCryptoOk
    check hexOf(output) == "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

  test "raw rejects null output":
    let secretKey = basePointSecretKey()

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      nil,
      csize_t(Secp256k1PublicKeyCompressedLen),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrNullOutput

  test "raw rejects short output buffer":
    let secretKey = basePointSecretKey()
    var output: array[Secp256k1PublicKeyCompressedLen - 1, byte]

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw rejects null input with data":
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      nil,
      csize_t(Secp256k1SecretKeyLen),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrNullInputWithData

  test "raw rejects invalid secret key":
    let secretKey = default(Secp256k1SecretKey)
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      Secp256k1PublicKeyFormatCompressed,
    )

    check status == RustCryptoErrInvalidSecretKey

  test "raw rejects invalid public key format":
    let secretKey = basePointSecretKey()
    var output: Secp256k1CompressedPublicKey

    let status = secp256k1PublicKeyFromSecretKeyRaw(
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      2,
    )

    check status == RustCryptoErrInvalidPublicKeyFormat

  test "high-level compressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyCompressed(secretKey)

    check hexOf(publicKey) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "high-level uncompressed public key derivation matches the known vector":
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyUncompressed(secretKey)

    check hexOf(publicKey) == "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    check $publicKey == hexOf(publicKey)

  test "random secret key can derive a public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = Secp256k1.publicKeyCompressed(secretKey)
    let signature = Secp256k1.sign("abc", secretKey)

    check secretKey.len == Secp256k1SecretKeyLen
    check publicKey.len == Secp256k1PublicKeyCompressedLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check Secp256k1.verify("abc", publicKey, signature)

  test "raw ECDSA sign produces the known deterministic signature":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    var signature: Secp256k1Signature

    let status = secp256k1EcdsaSignRaw(
      cast[ptr uint8](unsafeAddr messageDigest[0]),
      csize_t(messageDigest.len),
      cast[ptr uint8](unsafeAddr secretKey[0]),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk
    check hexOf(signature) == "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"

  test "high-level ECDSA sign and verify accept the known vector":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let compressedPublicKey = Secp256k1.publicKeyCompressed(secretKey)
    let uncompressedPublicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let signature = Secp256k1.sign(messageDigest, secretKey)

    check hexOf(signature) == "75601b1385909ea698e3fd6e26e5fa5105127bd2299d3ab0b9d9f93df5b8b99c28ae7cc8f969e6b6fb1feac477818a75a46e8c364e88dfdc9880e1a5175c4bd1"
    check $signature == hexOf(signature)
    check Secp256k1.verify(messageDigest, compressedPublicKey, signature)
    check Secp256k1.verify(messageDigest, uncompressedPublicKey, signature)

  test "recoverable signature stringifies as hex":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let signature = Secp256k1.signRecoverable(messageDigest, secretKey)

    check $signature == hexOf(signature)

  test "raw ECDSA verify rejects tampered signatures":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyCompressed(secretKey)
    var signature = Secp256k1.sign(messageDigest, secretKey)

    signature[0] = signature[0] xor 0x01

    let status = secp256k1EcdsaVerifyRaw(
      cast[ptr uint8](unsafeAddr messageDigest[0]),
      csize_t(messageDigest.len),
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
      Secp256k1PublicKeyFormatCompressed,
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoErrVerificationFailed

  test "high-level ECDSA verify returns false for tampered signatures":
    let messageDigest = sha256("abc")
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyCompressed(secretKey)
    var signature = Secp256k1.sign(messageDigest, secretKey)

    signature[0] = signature[0] xor 0x01

    check not Secp256k1.verify(messageDigest, publicKey, signature)

  test "high-level rejects invalid secret key":
    let secretKey = default(Secp256k1SecretKey)

    expect ValueError:
      discard Secp256k1.publicKeyCompressed(secretKey)

  test "marker type API accepts message and digest inputs":
    let secretKey = Secp256k1.generateSecretKey()
    let compressedPublicKey = Secp256k1.publicKeyCompressed(secretKey)
    let uncompressedPublicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let messageSignature = Secp256k1.sign("abc", secretKey)
    let digest = sha256("abc")
    let digestSignature = Secp256k1.sign(digest, secretKey)

    check Secp256k1.verify("abc", compressedPublicKey, messageSignature)
    check Secp256k1.verify("abc", uncompressedPublicKey, messageSignature)
    check Secp256k1.verify(digest, compressedPublicKey, digestSignature)
    check Secp256k1.verify(digest, uncompressedPublicKey, digestSignature)
