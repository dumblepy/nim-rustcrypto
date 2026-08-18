import unittest

import ./utils
import ../../src/rustcrypto/algorithm/scrypt

suite "scrypt":
  test "high-level derive matches the empty-input RFC vector":
    let okm = scrypt("", "", 16, 1, 1, 64)
    check hexOf(okm) ==
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" &
      "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"

  test "high-level derive matches the password and salt RFC vector":
    let okm = scrypt("password", "NaCl", 1024, 8, 16, 64)
    check hexOf(okm) ==
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" &
      "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"

  test "high-level derive matches the longer RFC vector":
    let okm = scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64)
    check hexOf(okm) ==
      "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" &
      "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"

  test "raw derive rejects non power of two N":
    var output = newSeq[byte](64)
    let status = scryptRaw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("salt"),
      csize_t("salt".len),
      csize_t(1000),
      csize_t(1),
      csize_t(1),
      bytesPtr(output),
      csize_t(output.len),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidParameter

  test "raw derive rejects short output buffers":
    var output = newSeq[byte](63)
    let status = scryptRaw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("salt"),
      csize_t("salt".len),
      csize_t(16),
      csize_t(1),
      csize_t(1),
      bytesPtr(output),
      csize_t(output.len),
      csize_t(64),
    )

    check status == RustCryptoErrOutputTooShort
