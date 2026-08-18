import unittest

import ./utils
import ../../src/rustcrypto/algorithm/hmac

suite "hmac":
  test "raw accepts empty key and message via null pointers":
    var output: HmacSha256Mac
    let status = hmacSha256Raw(
      nil,
      0,
      nil,
      0,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"

  test "raw matches RFC 4231 test case 1":
    var key = newString(20)
    for i in 0 ..< key.len:
      key[i] = char(0x0b)
    let message = "Hi There"
    var output: HmacSha256Mac

    let status = hmacSha256Raw(
      cast[ptr uint8](unsafeAddr key[0]),
      csize_t(key.len),
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

  test "high-level matches RFC 4231 test case 2":
    let output = hmacSha256("Jefe", "what do ya want for nothing?")

    check hexOf(output) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    check hmacSha256Hex("Jefe", "what do ya want for nothing?") ==
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

  test "raw rejects null output":
    let status = hmacSha256Raw(
      nil,
      0,
      nil,
      0,
      nil,
      csize_t(HmacSha256MacLen),
    )

    check status == RustCryptoErrNullOutput

  test "raw rejects short output buffer":
    let message = "what do ya want for nothing?"
    let key = "Jefe"
    var output: array[HmacSha256MacLen - 1, byte]

    let status = hmacSha256Raw(
      cast[ptr uint8](unsafeAddr key[0]),
      csize_t(key.len),
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw rejects null key when length is non-zero":
    let message = "what do ya want for nothing?"
    var output: HmacSha256Mac

    let status = hmacSha256Raw(
      nil,
      1,
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData

  test "raw rejects null message when length is non-zero":
    let key = "Jefe"
    var output: HmacSha256Mac

    let status = hmacSha256Raw(
      cast[ptr uint8](unsafeAddr key[0]),
      csize_t(key.len),
      nil,
      1,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData
