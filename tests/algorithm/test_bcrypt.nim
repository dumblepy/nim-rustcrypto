import unittest
import std/strutils

import ../../src/rustcrypto/algorithm/bcrypt

suite "bcrypt":
  test "marker type API hashes and verifies passwords":
    let hash = Bcrypt.hashPassword("password", 4)
    check hash.len == 60
    check hash.startsWith("$2b$04$")
    check Bcrypt.verifyPassword("password", hash)
    check not Bcrypt.verifyPassword("wrong", hash)
    check Bcrypt.validateHash(hash)
    check Bcrypt.cost(hash) == 4
    check Bcrypt.needsRehash(hash, 5)

  test "verifies known bcrypt hashes":
    let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"
    check Bcrypt.verifyPassword("correctbatteryhorsestapler", hash)
    check not Bcrypt.verifyPassword("wrong", hash)
    check Bcrypt.validateHash(hash)
    check Bcrypt.cost(hash) == 4

  test "rejects truncating passwords":
    expect ValueError:
      discard Bcrypt.hashPassword(repeat("x", 72), 4)

    expect ValueError:
      discard Bcrypt.verifyPassword(
        repeat("x", 72),
        "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
      )

  test "rejects invalid cost and malformed hashes":
    expect ValueError:
      discard Bcrypt.hashPassword("password", 3)

    check not Bcrypt.validateHash("not-bcrypt")

    expect ValueError:
      discard Bcrypt.cost("not-bcrypt")
