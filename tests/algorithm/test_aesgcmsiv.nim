import unittest

import ./utils
import ../../src/rustcrypto/algorithm/aesgcmsiv

suite "aes-gcm-siv":
  test "raw encrypt matches the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let plaintext = bytesFromHex("0100000000000000")
    var ciphertext = newSeq[byte](plaintext.len)
    var tag: Aes256GcmSivTag

    let status = aes256GcmSivEncryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](addr tag[0]),
      csize_t(tag.len),
    )

    check status == RustCryptoOk
    check hexOf(ciphertext) == "c2ef328e5c71c83b"
    check hexOf(tag) == "843122130f7364b761e0b97427e3df28"

  test "raw decrypt matches the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let ciphertext = bytesFromHex("c2ef328e5c71c83b")
    let tag = aesgcmsiv.fromHexTag("843122130f7364b761e0b97427e3df28")
    var plaintext = newSeq[byte](ciphertext.len)

    let status = aes256GcmSivDecryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](unsafeAddr tag[0]),
      csize_t(tag.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
    )

    check status == RustCryptoOk
    check hexOf(plaintext) == "0100000000000000"

  test "raw decrypt rejects tampered tag":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let ciphertext = bytesFromHex("c2ef328e5c71c83b")
    var tag = aesgcmsiv.fromHexTag("843122130f7364b761e0b97427e3df28")
    var plaintext = newSeq[byte](ciphertext.len)
    tag[0] = tag[0] xor 0x01

    let status = aes256GcmSivDecryptRaw(
      bytesPtr(key),
      csize_t(key.len),
      bytesPtr(nonce),
      csize_t(nonce.len),
      bytesPtr(aad),
      csize_t(aad.len),
      bytesPtr(ciphertext),
      csize_t(ciphertext.len),
      cast[ptr uint8](addr tag[0]),
      csize_t(tag.len),
      bytesPtr(plaintext),
      csize_t(plaintext.len),
    )

    check status == RustCryptoErrAuthenticationFailed

  test "high-level encrypt and decrypt match the RFC 8452 vector":
    let key = aesgcmsiv.fromHexKey(
      "0100000000000000000000000000000000000000000000000000000000000000"
    )
    let nonce = aesgcmsiv.fromHexNonce("030000000000000000000000")
    let aad = bytesFromHex("")
    let plaintext = bytesFromHex("0100000000000000")

    let (ciphertext, tag) = aes256gcmsivEncrypt(key, nonce, plaintext, aad)
    check hexOf(ciphertext) == "c2ef328e5c71c83b"
    check hexOf(tag) == "843122130f7364b761e0b97427e3df28"
    check aes256gcmsivDecrypt(key, nonce, ciphertext, tag, aad) == plaintext
