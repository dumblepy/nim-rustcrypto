import unittest

import ./utils
import ../../src/rustcrypto/algorithm/chacha20poly1305

suite "chacha20poly1305":
  test "raw encrypt matches the RFC 8439 vector":
    let key = chacha20poly1305.fromHexKey(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    let nonce = chacha20poly1305.fromHexNonce("070000004041424344454647")
    let aad = bytesFromHex("50515253c0c1c2c3c4c5c6c7")
    let plaintext = bytesFromHex(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    )
    var ciphertext = newSeq[byte](plaintext.len)
    var tag: ChaCha20Poly1305Tag

    let status = chacha20Poly1305EncryptRaw(
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
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    check hexOf(tag) == "1ae10b594f09e26a7e902ecbd0600691"

  test "raw decrypt matches the RFC 8439 vector":
    let key = chacha20poly1305.fromHexKey(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    let nonce = chacha20poly1305.fromHexNonce("070000004041424344454647")
    let aad = bytesFromHex("50515253c0c1c2c3c4c5c6c7")
    let ciphertext = bytesFromHex(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    )
    let tag = chacha20poly1305.fromHexTag("1ae10b594f09e26a7e902ecbd0600691")
    var plaintext = newSeq[byte](ciphertext.len)

    let status = chacha20Poly1305DecryptRaw(
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
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"

  test "raw decrypt rejects tampered tag":
    let key = chacha20poly1305.fromHexKey(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    let nonce = chacha20poly1305.fromHexNonce("070000004041424344454647")
    let aad = bytesFromHex("50515253c0c1c2c3c4c5c6c7")
    let ciphertext = bytesFromHex(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    )
    var tag = chacha20poly1305.fromHexTag("1ae10b594f09e26a7e902ecbd0600691")
    var plaintext = newSeq[byte](ciphertext.len)
    tag[0] = tag[0] xor 0x01

    let status = chacha20Poly1305DecryptRaw(
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

  test "high-level encrypt and decrypt match the RFC 8439 vector":
    let key = chacha20poly1305.fromHexKey(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    let nonce = chacha20poly1305.fromHexNonce("070000004041424344454647")
    let aad = bytesFromHex("50515253c0c1c2c3c4c5c6c7")
    let plaintext = bytesFromHex(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    )

    let (ciphertext, tag) = chacha20poly1305Encrypt(key, nonce, plaintext, aad)
    check hexOf(ciphertext) ==
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    check hexOf(tag) == "1ae10b594f09e26a7e902ecbd0600691"
    check chacha20poly1305Decrypt(key, nonce, ciphertext, tag, aad) == plaintext
