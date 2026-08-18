import unittest

import ./utils
import ../../src/rustcrypto/algorithm/ed25519

suite "ed25519":
  test "public key derivation matches the RFC 8032 vector":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let publicKey = Ed25519.publicKey(secretKey)
    check hexOf(publicKey) ==
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    check $publicKey == hexOf(publicKey)

  test "random secret key can derive public key and sign":
    let secretKey = randomSecretKey()
    let publicKey = Ed25519.publicKey(secretKey)
    let signature = Ed25519.sign("abc", secretKey)

    check secretKey.len == Ed25519PrivateKeyLen
    check publicKey.len == Ed25519PublicKeyLen
    check $publicKey == hexOf(publicKey)
    check $signature == hexOf(signature)
    check Ed25519.verify("abc", publicKey, signature)

  test "signing matches the RFC 8032 vector":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let signature = Ed25519.sign("", secretKey)
    check hexOf(signature) ==
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

  test "verify accepts the RFC 8032 vector":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let publicKey = Ed25519.publicKey(secretKey)
    let signature = fromHexSignature(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    check Ed25519.verify("", publicKey, signature)

  test "high-level string scenario creates keys, signs, and verifies":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let publicKey = Ed25519.publicKey(secretKey)
    let message = "abc"
    let signature = Ed25519.sign(message, secretKey)

    check hexOf(publicKey) ==
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    check Ed25519.verify(message, publicKey, signature)
    check not Ed25519.verify("abd", publicKey, signature)

    var tamperedSignature = signature
    tamperedSignature[0] = tamperedSignature[0] xor 0x01
    check not Ed25519.verify(message, publicKey, tamperedSignature)

  test "verify rejects a tampered signature":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let publicKey = Ed25519.publicKey(secretKey)
    var signature = fromHexSignature(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    signature[0] = signature[0] xor 0x01
    check not Ed25519.verify("", publicKey, signature)

  test "raw public key derivation rejects short output buffers":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var output = newSeq[byte](Ed25519PublicKeyLen - 1)

    let status = ed25519PublicKeyFromSecretKeyRaw(
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw signing rejects short output buffers":
    let secretKey = fromHexSecretKey(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var output = newSeq[byte](Ed25519SignatureLen - 1)

    let status = ed25519SignRaw(
      bytesPtr(""),
      csize_t(0),
      bytesPtr(secretKey),
      csize_t(secretKey.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw verification rejects malformed public keys":
    let signature = fromHexSignature(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let publicKey = newSeq[byte](Ed25519PublicKeyLen - 1)

    let status = ed25519VerifyRaw(
      bytesPtr(""),
      csize_t(0),
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(signature),
      csize_t(signature.len),
    )

    check status == RustCryptoErrInvalidPublicKeyFormat

  test "marker type API round-trips":
    let secretKey = Ed25519.generateSecretKey()
    let publicKey = Ed25519.publicKey(secretKey)
    let signature = Ed25519.sign("abc", secretKey)

    check Ed25519.verify("abc", publicKey, signature)
    check not Ed25519.verify("abd", publicKey, signature)
