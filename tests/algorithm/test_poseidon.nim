import unittest
import std/strutils
import ./utils
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/poseidon

suite "poseidon bn254":
  test "matches the documented light-poseidon (circom x5) vector":
    let inputs = [
      fromHexFr("01".repeat(32)),
      fromHexFr("02".repeat(32)),
    ]
    let digest = PoseidonBn254.hash(inputs)
    check digest.frToHex ==
      "0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990"

  test "deterministic and arity/order separated":
    let a = fromHexFr("00".repeat(31) & "01")
    let b = fromHexFr("00".repeat(31) & "02")
    check PoseidonBn254.hash([a, b]) == PoseidonBn254.hash([a, b])
    check PoseidonBn254.hash([a, b]) != PoseidonBn254.hash([a])
    check PoseidonBn254.hash([a, b]) != PoseidonBn254.hash([b, a])

  test "rejects empty and too many inputs":
    expect ValueError:
      discard PoseidonBn254.hash([])

    var inputs: seq[Bn254Fr]
    for i in 0 ..< 13:
      inputs.add(fromHexFr("00".repeat(31) & "01"))
    expect ValueError:
      discard PoseidonBn254.hash(inputs)

  test "rejects non-canonical field elements":
    let bad = fromHexFr("ff".repeat(32))
    expect ValueError:
      discard PoseidonBn254.hash([bad])
