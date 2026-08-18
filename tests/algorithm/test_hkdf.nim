import unittest

import ./utils
import ../../src/rustcrypto/algorithm/hkdf

proc bytesString(bytes: openArray[byte]): string =
  result = newString(bytes.len)
  for i, value in bytes:
    result[i] = char(value)

proc repeatedBytes(count: int, value: byte): seq[byte] =
  result = newSeq[byte](count)
  for i in 0 ..< count:
    result[i] = value

suite "hkdf":
  test "raw extract matches RFC 5869 test case 1 PRK":
    let ikm = repeatedBytes(22, 0x0b.byte)
    let salt = @[
      byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]
    var output: HkdfSha256Prk

    let status = hkdfSha256ExtractRaw(
      bytesPtr(salt),
      csize_t(salt.len),
      bytesPtr(ikm),
      csize_t(ikm.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

  test "raw expand matches RFC 5869 test case 1 OKM":
    let prk = @[
      byte 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
      0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
      0xd7, 0xc2, 0xb3, 0xe5,
    ]
    let info = @[
      byte 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ]
    var output = newSeq[byte](42)

    let status = hkdfSha256ExpandRaw(
      bytesPtr(prk),
      csize_t(prk.len),
      bytesPtr(info),
      csize_t(info.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

  test "raw derive accepts empty salt and info via null pointers":
    let ikm = repeatedBytes(22, 0x0b.byte)
    var output = newSeq[byte](42)

    let status = hkdfSha256DeriveRaw(
      nil,
      0,
      bytesPtr(ikm),
      csize_t(ikm.len),
      nil,
      0,
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check hexOf(output) == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

  test "high-level extract and expand match RFC 5869 test case 1":
    let ikm = bytesString(repeatedBytes(22, 0x0b.byte))
    let salt = bytesString(@[
      byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ])
    let info = bytesString(@[
      byte 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ])

    let prk = hkdfSha256Extract(salt, ikm)
    check hexOf(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

    let okm = hkdfSha256Expand(prk, info, 42)
    check hexOf(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

  test "high-level derive matches RFC 5869 test case 3":
    let ikm = bytesString(repeatedBytes(22, 0x0b.byte))

    let okm = hkdfSha256Derive("", ikm, "", 42)
    check hexOf(okm) == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

  test "raw extract rejects null output":
    let ikm = repeatedBytes(22, 0x0b.byte)
    let salt = @[
      byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]

    let status = hkdfSha256ExtractRaw(
      bytesPtr(salt),
      csize_t(salt.len),
      bytesPtr(ikm),
      csize_t(ikm.len),
      nil,
      csize_t(HkdfSha256PrkLen),
    )

    check status == RustCryptoErrNullOutput

  test "raw extract rejects short output buffer":
    let ikm = repeatedBytes(22, 0x0b.byte)
    let salt = @[
      byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]
    var output: array[HkdfSha256PrkLen - 1, byte]

    let status = hkdfSha256ExtractRaw(
      bytesPtr(salt),
      csize_t(salt.len),
      bytesPtr(ikm),
      csize_t(ikm.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort

  test "raw expand rejects short PRK":
    let prk = newSeq[byte](HkdfSha256PrkLen - 1)
    let info = @[
      byte 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ]
    var output = newSeq[byte](42)

    let status = hkdfSha256ExpandRaw(
      bytesPtr(prk),
      csize_t(prk.len),
      bytesPtr(info),
      csize_t(info.len),
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidPrkLength

  test "raw derive rejects invalid length":
    let ikm = repeatedBytes(22, 0x0b.byte)
    var output = newSeq[byte](1)

    let status = hkdfSha256DeriveRaw(
      nil,
      0,
      bytesPtr(ikm),
      csize_t(ikm.len),
      nil,
      0,
      bytesPtr(output),
      csize_t(HkdfSha256MaxOkmLen + 1),
    )

    check status == RustCryptoErrInvalidLength

  test "raw derive rejects null input with data":
    var output = newSeq[byte](42)

    let status = hkdfSha256DeriveRaw(
      nil,
      0,
      nil,
      1,
      nil,
      0,
      bytesPtr(output),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData
