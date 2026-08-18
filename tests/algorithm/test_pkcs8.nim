import unittest

import ./utils
import ../../src/rustcrypto/algorithm/pkcs8

suite "pkcs8":
  test "raw private key encodes to the RFC 8410 example":
    let privateKey = fromHexPrivateKey(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    let der = ed25519PrivateKeyToPkcs8Der(privateKey)
    check hexOf(der) ==
      "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"

  test "raw private key decodes from the RFC 8410 example":
    let der = bytesFromHex(
      "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    let privateKey = ed25519PrivateKeyFromPkcs8Der(der)
    check hexOf(privateKey) ==
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"

  test "raw public key encodes to the RFC 8410 example":
    let publicKey = fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    let der = ed25519PublicKeyToSpkiDer(publicKey)
    check hexOf(der) ==
      "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    check $der == hexOf(der)

  test "raw public key decodes from the RFC 8410 example":
    let der = bytesFromHex(
      "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    let publicKey = ed25519PublicKeyFromSpkiDer(der)
    check hexOf(publicKey) ==
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"

  test "raw private key encoder rejects short output buffers":
    let privateKey = fromHexPrivateKey(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    var output = newSeq[byte](Ed25519PrivateKeyDerMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PrivateKeyToPkcs8DerRaw(
      bytesPtr(privateKey),
      csize_t(privateKey.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key encoder rejects short output buffers":
    let publicKey = fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    var output = newSeq[byte](Ed25519PublicKeyDerMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PublicKeyToSpkiDerRaw(
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw private key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: Ed25519PrivateKey

    let status = ed25519PrivateKeyFromPkcs8DerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter

  test "raw public key decoder rejects malformed DER":
    let der = bytesFromHex("3000")
    var output: Ed25519PublicKey

    let status = ed25519PublicKeyFromSpkiDerRaw(
      bytesPtr(der),
      csize_t(der.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter
