import unittest

import ./utils
import ../../src/rustcrypto/algorithm/pbkdf2

suite "pbkdf2":
  test "high-level derive matches the known one-round vector":
    let okm = pbkdf2HmacSha256("password", "salt", 1, 32)
    check hexOf(okm) ==
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"

  test "high-level derive matches the known two-round vector":
    let okm = pbkdf2HmacSha256("password", "salt", 2, 32)
    check hexOf(okm) ==
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"

  test "high-level derive matches the longer RFC-style vector":
    let okm = pbkdf2HmacSha256(
      "passwordPASSWORDpassword",
      "saltSALTsaltSALTsaltSALTsaltSALTsalt",
      4096,
      40,
    )
    check hexOf(okm) ==
      "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1" &
      "c635518c7dac47e9"

  test "high-level derive accepts empty password and salt":
    let okm = pbkdf2HmacSha256("", "", 1, 32)
    check hexOf(okm) ==
      "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"

  test "raw derive rejects zero iterations":
    var output = newSeq[byte](32)
    let status = pbkdf2HmacSha256Raw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("salt"),
      csize_t("salt".len),
      cuint(0),
      bytesPtr(output),
      csize_t(output.len),
      csize_t(32),
    )
    check status == RustCryptoErrInvalidParameter

  test "raw derive rejects short output buffers":
    var output = newSeq[byte](31)
    let status = pbkdf2HmacSha256Raw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("salt"),
      csize_t("salt".len),
      cuint(1),
      bytesPtr(output),
      csize_t(output.len),
      csize_t(32),
    )
    check status == RustCryptoErrOutputTooShort
