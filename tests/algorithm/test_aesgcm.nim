import unittest

import ./utils
import ../../src/rustcrypto/algorithm/aesgcm

suite "aes-gcm":
  test "raw encrypt matches the NIST vector":
    let key = aesgcm.fromHexKey(
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    let nonce = aesgcm.fromHexNonce("cafebabefacedbaddecaf888")
    let aad = bytesFromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    let plaintext = bytesFromHex(
      "d9313225f88406e5a55909c5aff5269a" &
      "86a7a9531534f7da2e4c303d8a318a72" &
      "1c3c0c95956809532fcf0e2449a6b525" &
      "b16aedf5aa0de657ba637b39"
    )
    var ciphertext = newSeq[byte](plaintext.len)
    var tag: Aes256GcmTag

    let status = aes256GcmEncryptRaw(
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
    check hexOf(ciphertext) ==
      "522dc1f099567d07f47f37a32a84427d" &
      "643a8cdcbfe5c0c97598a2bd2555d1aa" &
      "8cb08e48590dbb3da7b08b1056828838" &
      "c5f61e6393ba7a0abcc9f662"
    check hexOf(tag) == "76fc6ece0f4e1768cddf8853bb2d551b"

  test "raw decrypt matches the NIST vector":
    let key = aesgcm.fromHexKey(
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    let nonce = aesgcm.fromHexNonce("cafebabefacedbaddecaf888")
    let aad = bytesFromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    let ciphertext = bytesFromHex(
      "522dc1f099567d07f47f37a32a84427d" &
      "643a8cdcbfe5c0c97598a2bd2555d1aa" &
      "8cb08e48590dbb3da7b08b1056828838" &
      "c5f61e6393ba7a0abcc9f662"
    )
    let tag = aesgcm.fromHexTag("76fc6ece0f4e1768cddf8853bb2d551b")
    var plaintext = newSeq[byte](ciphertext.len)

    let status = aes256GcmDecryptRaw(
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
    check hexOf(plaintext) ==
      "d9313225f88406e5a55909c5aff5269a" &
      "86a7a9531534f7da2e4c303d8a318a72" &
      "1c3c0c95956809532fcf0e2449a6b525" &
      "b16aedf5aa0de657ba637b39"

  test "raw decrypt rejects tampered tag":
    let key = aesgcm.fromHexKey(
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    let nonce = aesgcm.fromHexNonce("cafebabefacedbaddecaf888")
    let aad = bytesFromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    let ciphertext = bytesFromHex(
      "522dc1f099567d07f47f37a32a84427d" &
      "643a8cdcbfe5c0c97598a2bd2555d1aa" &
      "8cb08e48590dbb3da7b08b1056828838" &
      "c5f61e6393ba7a0abcc9f662"
    )
    var tag = aesgcm.fromHexTag("76fc6ece0f4e1768cddf8853bb2d551b")
    var plaintext = newSeq[byte](ciphertext.len)
    tag[0] = tag[0] xor 0x01

    let status = aes256GcmDecryptRaw(
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

  test "high-level encrypt and decrypt match the NIST vector":
    let key = aesgcm.fromHexKey(
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    let nonce = aesgcm.fromHexNonce("cafebabefacedbaddecaf888")
    let aad = bytesFromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    let plaintext = bytesFromHex(
      "d9313225f88406e5a55909c5aff5269a" &
      "86a7a9531534f7da2e4c303d8a318a72" &
      "1c3c0c95956809532fcf0e2449a6b525" &
      "b16aedf5aa0de657ba637b39"
    )

    let (ciphertext, tag) = aes256gcmEncrypt(key, nonce, plaintext, aad)
    check hexOf(ciphertext) ==
      "522dc1f099567d07f47f37a32a84427d" &
      "643a8cdcbfe5c0c97598a2bd2555d1aa" &
      "8cb08e48590dbb3da7b08b1056828838" &
      "c5f61e6393ba7a0abcc9f662"
    check hexOf(tag) == "76fc6ece0f4e1768cddf8853bb2d551b"
    check aes256gcmDecrypt(key, nonce, ciphertext, tag, aad) == plaintext
