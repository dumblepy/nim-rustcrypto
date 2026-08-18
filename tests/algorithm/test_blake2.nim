import unittest

import ./utils
import ../../src/rustcrypto/algorithm/blake2

suite "blake2":
  test "raw blake2b-512 matches the RFC 7693 vector":
    let input = "abc"
    var output: Blake2b512Digest

    let status = blake2b512Raw(
      bytesPtr(input),
      csize_t(input.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) ==
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" &
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"

  test "raw blake2s-256 matches the RFC 7693 vector":
    let input = "abc"
    var output: Blake2s256Digest

    let status = blake2s256Raw(
      bytesPtr(input),
      csize_t(input.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"

  test "raw blake2b-512 rejects short output buffers":
    let input = "abc"
    var output = newSeq[byte](Blake2b512DigestLen - 1)

    let status = blake2b512Raw(
      bytesPtr(input),
      csize_t(input.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "high-level blake2 APIs match the RFC 7693 vectors":
    check hexOf(blake2b512("abc")) ==
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" &
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    check hexOf(blake2s256("abc")) ==
      "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
