import unittest

import ./utils
import ../../src/rustcrypto/algorithm/argon2

suite "argon2":
  test "high-level derive matches the known Argon2id vector":
    let okm = argon2idDerive("password", "somesalt", 65536, 2, 1, 32)
    check hexOf(okm) == "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"

  test "high-level hash matches the known PHC string":
    let phc = argon2idHashPassword("password", "somesalt", 65536, 2, 1, 32)
    check phc ==
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"

  test "high-level verify accepts the known PHC string":
    check argon2idVerifyPassword(
      "password",
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
    )

  test "high-level verify rejects the wrong password":
    check not argon2idVerifyPassword(
      "wrongpassword",
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
    )

  test "raw derive rejects short output buffers":
    var output = newSeq[byte](3)
    let status = argon2idDeriveRaw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("somesalt"),
      csize_t("somesalt".len),
      cuint(65536),
      cuint(2),
      cuint(1),
      bytesPtr(output),
      csize_t(output.len),
      csize_t(output.len),
    )

    check status == RustCryptoErrInvalidLength

  test "raw hash rejects short output buffers":
    var output = newSeq[byte](16)
    var writtenLen: csize_t
    let status = argon2idHashPasswordRaw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("somesalt"),
      csize_t("somesalt".len),
      cuint(65536),
      cuint(2),
      cuint(1),
      csize_t(32),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw verify rejects malformed PHC strings":
    let status = argon2idVerifyPasswordRaw(
      bytesPtr("password"),
      csize_t("password".len),
      bytesPtr("argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow"),
      csize_t("argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow".len),
    )

    check status == RustCryptoErrInvalidPasswordHashFormat
