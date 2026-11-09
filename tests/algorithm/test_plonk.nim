import std/strutils
import unittest
import ./utils
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/plonk

const Fixture = staticRead("../fixtures/plonk_bn254_v1.hex")

proc fixtureValue(name: string): string =
  for line in Fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return line[separator + 1 .. ^1]
  raise newException(ValueError, "missing fixture: " & name)

let
  VerifyingKey = bytesFromHex(fixtureValue("VK"))
  Proof = bytesFromHex(fixtureValue("PROOF"))
  PublicInputs = @[fromHexFr(fixtureValue("INPUTS"))]

suite "plonk bn254 (genshi-core profile)":
  test "fixture encodings are valid":
    check VerifyingKey.len == PlonkBn254VkV1Len
    check Proof.len == PlonkBn254ProofV1MinLen + 3 * Bn254G1Len
    check PlonkBn254.validateVerifyingKey(VerifyingKey)
    check PlonkBn254.validateProof(Proof)

  test "verifies the known proof":
    check PlonkBn254.verify(VerifyingKey, Proof, PublicInputs)

  test "rejects a modified public input":
    let wrong = @[fromHexFr("00".repeat(31) & "09")]
    check not PlonkBn254.verify(VerifyingKey, Proof, wrong)

  test "rejects a modified proof point":
    var tampered = Proof
    tampered[63] = tampered[63] xor 1
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, tampered, PublicInputs)

  test "rejects a modified verifying key":
    var tampered = VerifyingKey
    tampered[135] = tampered[135] xor 1
    expect ValueError:
      discard PlonkBn254.verify(tampered, Proof, PublicInputs)

  test "rejects truncated, oversized, and empty inputs":
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey[0 ..< VerifyingKey.len - 1], Proof, PublicInputs)

    var trailingProof = Proof
    trailingProof.add(0'u8)
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, trailingProof, PublicInputs)

    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, Proof[0 ..< Proof.len - 1], PublicInputs)

    expect ValueError:
      discard PlonkBn254.verify(@[], Proof, PublicInputs)

    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, @[], PublicInputs)

  test "rejects wrong public input count":
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, Proof, @[])
    let twoInputs = @[
      fromHexFr("00".repeat(31) & "08"),
      fromHexFr("00".repeat(31) & "09"),
    ]
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, Proof, twoInputs)

  test "rejects non-canonical public inputs":
    var bad: Bn254Fr
    for i in 0 ..< bad.len:
      bad[i] = 0xff
    expect ValueError:
      discard PlonkBn254.verify(VerifyingKey, Proof, @[bad])

  test "validate helpers return false for malformed values":
    check not PlonkBn254.validateVerifyingKey(@[])
    check not PlonkBn254.validateProof(@[])
    check not PlonkBn254.validateProof(Proof[0 ..< Proof.len - 1])
