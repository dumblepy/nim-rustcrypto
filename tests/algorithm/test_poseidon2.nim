import unittest
import std/strutils
import ./utils
import ../../src/rustcrypto/algorithm/ffi
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/poseidon2

const
  PermutationZeroKat = [
    "18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
    "095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839",
    "0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59",
    "18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d",
  ]
  NoirHashKat = [
    "18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
    "168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373",
    "038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383",
    "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8",
    "130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9",
    "2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db",
    "07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a",
    "16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238",
  ]
  MultiplesOfRate = [0, 1, 2, 3, 4, 6, 8, 9]

proc fr(value: int): Bn254Fr =
  fromHexFr("00".repeat(31) & toHex(value, 2))

proc frInputs(count: int): seq[Bn254Fr] =
  for value in 1 .. count:
    result.add(fr(value))

suite "poseidon2 bn254":
  test "permutation KAT for the all-zero state":
    let zeros: array[Poseidon2Bn254Width, Bn254Fr] = [
      default(Bn254Fr), default(Bn254Fr), default(Bn254Fr), default(Bn254Fr)
    ]
    let permuted = Poseidon2Bn254.permute(zeros)
    for i in 0 ..< Poseidon2Bn254Width:
      check permuted[i].frToHex == PermutationZeroKat[i]

  test "permutation is deterministic and state-sensitive":
    let state: array[Poseidon2Bn254Width, Bn254Fr] = [
      fr(1), fr(2), fr(3), fr(4)
    ]
    let once = Poseidon2Bn254.permute(state)
    check once == Poseidon2Bn254.permute(state)

    var changed = state
    changed[0] = fr(5)
    check changed != state
    check Poseidon2Bn254.permute(changed) != once

  test "Noir hash KAT for n = 0..7":
    for n in 0 .. 7:
      let digest = Poseidon2Bn254.hash(frInputs(n))
      check digest.frToHex == NoirHashKat[n]

  test "empty input is valid and matches the zero permutation KAT":
    var empty: seq[Bn254Fr]
    let digest = Poseidon2Bn254.hash(empty)
    check digest.frToHex == PermutationZeroKat[0]
    check Poseidon2Bn254.hash([]) == digest

  test "sponge is deterministic and separates length, arity, and order":
    var digests: seq[string]
    for count in MultiplesOfRate:
      let inputs = frInputs(count)
      let first = Poseidon2Bn254.hash(inputs)
      check Poseidon2Bn254.hash(inputs) == first
      digests.add(first.frToHex)

    # Every supported length produces a distinct digest, including the rate
    # multiples (3, 6, 9) that skip the final permutation.
    for i in 0 ..< digests.len:
      for j in i + 1 ..< digests.len:
        check digests[i] != digests[j]

    # Arity separation.
    check Poseidon2Bn254.hash(frInputs(1)) != Poseidon2Bn254.hash(frInputs(2))
    check Poseidon2Bn254.hash(frInputs(2)) != Poseidon2Bn254.hash(frInputs(3))
    check Poseidon2Bn254.hash(frInputs(4)) != Poseidon2Bn254.hash(frInputs(6))

    # Order separation.
    check Poseidon2Bn254.hash([fr(1), fr(2)]) !=
      Poseidon2Bn254.hash([fr(2), fr(1)])
    check Poseidon2Bn254.hash([fr(1), fr(2), fr(3)]) !=
      Poseidon2Bn254.hash([fr(1), fr(3), fr(2)])

  test "accepts the maximum of 12 inputs":
    let digest = Poseidon2Bn254.hash(frInputs(Poseidon2Bn254MaxInputs))
    check digest.frToHex.len == 64
    check Poseidon2Bn254.hash(frInputs(Poseidon2Bn254MaxInputs)) == digest
    check digest != Poseidon2Bn254.hash(frInputs(Poseidon2Bn254MaxInputs - 1))

  test "rejects more than 12 inputs":
    var inputs = frInputs(Poseidon2Bn254MaxInputs)
    inputs.add(fr(Poseidon2Bn254MaxInputs + 1))
    expect ValueError:
      discard Poseidon2Bn254.hash(inputs)

  test "rejects non-canonical field elements":
    let bad = fromHexFr("ff".repeat(32))
    check not Bn254.isCanonicalFr(bad)

    expect ValueError:
      discard Poseidon2Bn254.hash([bad])

    let zero = default(Bn254Fr)
    expect ValueError:
      discard Poseidon2Bn254.permute([bad, zero, zero, zero])
