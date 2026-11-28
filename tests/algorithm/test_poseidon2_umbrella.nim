import unittest
import std/strutils
import ./utils
import ../../src/rustcrypto

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

proc fr(value: int): Bn254Fr =
  fromHexFr("00".repeat(31) & toHex(value, 2))

suite "poseidon2 through the rustcrypto umbrella module":
  test "constants are exported":
    check Poseidon2Bn254Width == 4
    check Poseidon2Bn254Rate == 3
    check Poseidon2Bn254MaxInputs == 12

  test "permutation KAT via umbrella":
    let zeros: array[Poseidon2Bn254Width, Bn254Fr] = [
      default(Bn254Fr), default(Bn254Fr), default(Bn254Fr), default(Bn254Fr)
    ]
    let permuted = Poseidon2Bn254.permute(zeros)
    for i in 0 ..< Poseidon2Bn254Width:
      check permuted[i].frToHex == PermutationZeroKat[i]

  test "Noir hash KAT for n = 0..3 via umbrella":
    for n in 0 .. 3:
      var inputs: seq[Bn254Fr]
      for value in 1 .. n:
        inputs.add(fr(value))
      check Poseidon2Bn254.hash(inputs).frToHex == NoirHashKat[n]

  test "rejects too many inputs via umbrella":
    var inputs: seq[Bn254Fr]
    for value in 1 .. Poseidon2Bn254MaxInputs + 1:
      inputs.add(fr(value))
    expect ValueError:
      discard Poseidon2Bn254.hash(inputs)
