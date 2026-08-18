import unittest

import ./utils
import ../../src/rustcrypto/algorithm/pkcs8
import ../../src/rustcrypto/algorithm/pem

suite "pem-rfc7468":
  test "raw private key encodes to the RFC 7468 example":
    let privateKey = fromHexPrivateKey(
      "17ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85"
    )
    let pem = ed25519PrivateKeyToPkcs8Pem(privateKey)
    check pem == """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
-----END PRIVATE KEY-----
"""

  test "raw private key decodes from the RFC 7468 example":
    let pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
-----END PRIVATE KEY-----"""
    let privateKey = ed25519PrivateKeyFromPkcs8Pem(pem)
    check privateKey == fromHexPrivateKey(
      "17ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85"
    )

  test "raw public key encodes to the RFC 7468 example":
    let publicKey = fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )
    let pem = ed25519PublicKeyToSpkiPem(publicKey)
    check pem == """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
"""

  test "raw public key decodes from the RFC 7468 example":
    let pem = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""
    let publicKey = ed25519PublicKeyFromSpkiPem(pem)
    check publicKey == fromHexPublicKey(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
    )

  test "raw private key encoder rejects short output buffers":
    let privateKey = fromHexPrivateKey(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
    )
    var output = newString(Ed25519PrivateKeyPemMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PrivateKeyToPkcs8PemRaw(
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
    var output = newString(Ed25519PublicKeyPemMaxLen - 1)
    var writtenLen: csize_t

    let status = ed25519PublicKeyToSpkiPemRaw(
      bytesPtr(publicKey),
      csize_t(publicKey.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw private key decoder rejects wrong label":
    let pem = """-----BEGIN PUBLIC KEY-----
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
-----END PUBLIC KEY-----"""
    var output: Ed25519PrivateKey

    let status = ed25519PrivateKeyFromPkcs8PemRaw(
      bytesPtr(pem),
      csize_t(pem.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter

  test "raw public key decoder rejects invalid base64":
    let pem = """-----BEGIN PUBLIC KEY-----
!CowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""
    var output: Ed25519PublicKey

    let status = ed25519PublicKeyFromSpkiPemRaw(
      bytesPtr(pem),
      csize_t(pem.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter

  test "raw private key decoder rejects short output buffers":
    let pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
-----END PRIVATE KEY-----"""
    var output = newSeq[byte](Ed25519PrivateKeyLen - 1)

    let status = ed25519PrivateKeyFromPkcs8PemRaw(
      bytesPtr(pem),
      csize_t(pem.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw public key decoder rejects short output buffers":
    let pem = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""
    var output = newSeq[byte](Ed25519PublicKeyLen - 1)

    let status = ed25519PublicKeyFromSpkiPemRaw(
      bytesPtr(pem),
      csize_t(pem.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort
