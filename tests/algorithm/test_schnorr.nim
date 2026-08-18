import unittest

import ./utils
import ../../src/rustcrypto/algorithm/schnorr

proc basePointSchnorrSecretKey(): SchnorrSecretKey =
  result = default(SchnorrSecretKey)
  result[Secp256k1SecretKeyLen - 1] = 1

suite "schnorr":
  test "public key derivation matches the expected x-only encoding":
    let secretKey = basePointSchnorrSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)

    check hexOf(publicKey) ==
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    check $publicKey == hexOf(publicKey)

  test "random secret key can derive public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)
    let signature = Schnorr.sign("abc", secretKey)

    check secretKey.len == Secp256k1SecretKeyLen
    check publicKey.len == SchnorrPublicKeyLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check Schnorr.verify("abc", publicKey, signature)

  test "sign and verify accept the message text":
    let secretKey = basePointSchnorrSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)
    let signature = Schnorr.sign("abc", secretKey)

    check Schnorr.verify("abc", publicKey, signature)
    check not Schnorr.verify("abd", publicKey, signature)

  test "raw signing accepts empty input via null pointer":
    let secretKey = basePointSchnorrSecretKey()
    var signature: SchnorrSignature

    let status = schnorrSignRaw(
      nil,
      0,
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    )

    check status == RustCryptoOk

  test "verify rejects a tampered signature":
    let secretKey = basePointSchnorrSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)
    var signature = Schnorr.sign("abc", secretKey)
    signature[0] = signature[0] xor 0x01

    check not Schnorr.verify("abc", publicKey, signature)

  test "raw sign rejects malformed inputs":
    let secretKey = basePointSchnorrSecretKey()
    var signature: SchnorrSignature

    check schnorrSignRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(secretKey),
      csize_t(secretKey.len - 1),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    ) == RustCryptoErrInvalidSecretKey

    check schnorrSignRaw(
      bytesPtr("abc"),
      csize_t(3),
      nil,
      csize_t(secretKey.len),
      cast[ptr uint8](addr signature[0]),
      csize_t(signature.len),
    ) == RustCryptoErrNullInputWithData

    check schnorrSignRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      nil,
      csize_t(signature.len),
    ) == RustCryptoErrNullOutput

    var shortOutput = newSeq[byte](SchnorrSignatureLen - 1)
    check schnorrSignRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(shortOutput),
      csize_t(shortOutput.len),
    ) == RustCryptoErrOutputTooShort

  test "raw verify rejects malformed inputs":
    let secretKey = basePointSchnorrSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)
    let signature = Schnorr.sign("abc", secretKey)

    check schnorrVerifyRaw(
      nil,
      1,
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(signature),
      csize_t(signature.len),
    ) == RustCryptoErrNullInputWithData

    check schnorrVerifyRaw(
      bytesPtr("abc"),
      csize_t(3),
      nil,
      csize_t(publicKey.len),
      bytesPtr(signature),
      csize_t(signature.len),
    ) == RustCryptoErrNullInputWithData

    var shortPublicKey = newSeq[byte](SchnorrPublicKeyLen - 1)
    check schnorrVerifyRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(shortPublicKey),
      csize_t(shortPublicKey.len),
      bytesPtr(signature),
      csize_t(signature.len),
    ) == RustCryptoErrInvalidPublicKeyFormat

    var malformedPublicKey: SchnorrPublicKey
    check schnorrVerifyRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(malformedPublicKey),
      csize_t(malformedPublicKey.len),
      bytesPtr(signature),
      csize_t(signature.len),
    ) == RustCryptoErrInvalidPublicKeyFormat

    var shortSignature = newSeq[byte](SchnorrSignatureLen - 1)
    check schnorrVerifyRaw(
      bytesPtr("abc"),
      csize_t(3),
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(shortSignature),
      csize_t(shortSignature.len),
    ) == RustCryptoErrInvalidSignature

  test "marker type API round-trips":
    let secretKey = Schnorr.generateSecretKey()
    let publicKey = Schnorr.publicKey(secretKey)
    let stringSignature = Schnorr.sign("abc", secretKey)
    let bytesSignature = Schnorr.sign(bytesFromString("abc"), secretKey)

    check Schnorr.verify("abc", publicKey, stringSignature)
    check Schnorr.verify(bytesFromString("abc"), publicKey, bytesSignature)
