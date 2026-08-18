import unittest

import ./utils
import ../../src/rustcrypto/algorithm/passwordhash

suite "password-hash":
  test "high-level validate accepts known PHC strings":
    check passwordHashValidate(
      "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ"
    )
    check passwordHashValidate(
      "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0"
    )

  test "high-level canonicalize round-trips known PHC strings":
    let argon2 = "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ"
    let scrypt = "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0"
    check passwordHashCanonicalize(argon2) == argon2
    check passwordHashCanonicalize(scrypt) == scrypt

  test "high-level validate rejects malformed PHC strings":
    check not passwordHashValidate(
      "argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ"
    )

  test "raw canonicalize rejects short output buffers":
    let phc = "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ"
    var output = newString(10)
    var writtenLen: csize_t

    let status = passwordHashCanonicalizeRaw(
      bytesPtr(phc),
      csize_t(phc.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw validate rejects malformed PHC strings":
    let phc = "argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ"
    let status = passwordHashValidateRaw(bytesPtr(phc), csize_t(phc.len))
    check status == RustCryptoErrInvalidPasswordHashFormat
