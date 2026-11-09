import std/strutils
import unittest
import ./utils
import ../../src/rustcrypto/algorithm/halo2

const Fixture = staticRead("../fixtures/halo2_kzg_bn254_v1.hex")

proc fixtureValue(name: string): string =
  for line in Fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return line[separator + 1 .. ^1]
  raise newException(ValueError, "missing fixture: " & name)

proc rejected(params, vk, proof, instances: seq[byte]): bool =
  try:
    result = not Halo2KzgBn254.verify(params, vk, proof, instances)
  except ValueError:
    result = true

let
  Params = bytesFromHex(fixtureValue("PARAMS"))
  VerifyingKey = bytesFromHex(fixtureValue("VK"))
  Proof = bytesFromHex(fixtureValue("PROOF"))
  Instances = bytesFromHex(fixtureValue("INSTANCES"))

suite "halo2 kzg bn254 (blake2b, shplonk)":
  test "fixture encodings are valid":
    check Params.len == Halo2KzgBn254ParamsV1Len
    check Halo2KzgBn254.validateParams(Params)
    check Halo2KzgBn254.validateVerifyingKey(VerifyingKey)
    check Halo2KzgBn254.validatePublicInstances(Instances)

  test "verifies the known proof":
    check Halo2KzgBn254.verify(Params, VerifyingKey, Proof, Instances)

  test "rejects a modified public instance":
    var wrong = Instances
    wrong[^1] = wrong[^1] xor 1
    check rejected(Params, VerifyingKey, Proof, wrong)

  test "rejects a modified proof":
    var tampered = Proof
    tampered[0] = tampered[0] xor 1
    check rejected(Params, VerifyingKey, tampered, Instances)

    var tampered2 = Proof
    tampered2[^1] = tampered2[^1] xor 1
    check rejected(Params, VerifyingKey, tampered2, Instances)

  test "rejects modified params":
    var tampered = Params
    tampered[^1] = tampered[^1] xor 1
    check rejected(tampered, VerifyingKey, Proof, Instances)

  test "rejects truncated or oversized blobs":
    check rejected(Params, VerifyingKey[0 ..< VerifyingKey.len - 1], Proof, Instances)

    var trailingProof = Proof
    trailingProof.add(0'u8)
    check rejected(Params, VerifyingKey, trailingProof, Instances)

    var trailingInstances = Instances
    trailingInstances.add(0'u8)
    check rejected(Params, VerifyingKey, Proof, trailingInstances)

    expect ValueError:
      discard Halo2KzgBn254.verify(@[], VerifyingKey, Proof, Instances)
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, @[], Proof, Instances)
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, VerifyingKey, @[], Instances)
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, VerifyingKey, Proof, @[])

  test "rejects mismatched instance column layout":
    var zeroColumns = bytesFromHex("5243483249310000" & "00000000")
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, VerifyingKey, Proof, zeroColumns)

    var twoValues = Instances[0 ..< 12]
    twoValues[11] = 2'u8
    twoValues.add(Instances[12 .. ^1])
    twoValues.add(Instances[12 .. ^1])
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, VerifyingKey, Proof, twoValues)

  test "rejects non-canonical instance values":
    var bad = Instances
    for i in Instances.len - 32 ..< Instances.len:
      bad[i] = 0xff
    expect ValueError:
      discard Halo2KzgBn254.verify(Params, VerifyingKey, Proof, bad)

  test "validate helpers return false for malformed values":
    check not Halo2KzgBn254.validateParams(@[])
    check not Halo2KzgBn254.validateVerifyingKey(@[])
    check not Halo2KzgBn254.validatePublicInstances(@[])
    check not Halo2KzgBn254.validateParams(Params[0 ..< Params.len - 1])
    check not Halo2KzgBn254.validateVerifyingKey(VerifyingKey[0 ..< VerifyingKey.len - 1])
