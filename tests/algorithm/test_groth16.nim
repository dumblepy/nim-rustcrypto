import std/strutils
import unittest
import ./utils
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/groth16

const Fixture = staticRead("../fixtures/groth16_bn254_v1.hex")

proc fixtureValue(name: string): string =
  for line in Fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return line[separator + 1 .. ^1]
  raise newException(ValueError, "missing fixture: " & name)

let
  VkHex = fixtureValue("VK")
  ProofHex = fixtureValue("PROOF")
  InputsHex = fixtureValue("INPUTS")
  VerifyingKey = bytesFromHex(VkHex)
  Proof = bytesFromHex(ProofHex)
  PublicInputs = @[fromHexFr(InputsHex)]

suite "groth16 bn254":
  test "fixture encodings are valid":
    check VerifyingKey.len == Groth16Bn254VkV1HeaderLen + Bn254G1Len + 3 * Bn254G2Len + 4 +
      2 * Bn254G1Len
    check Proof.len == Groth16Bn254ProofV1Len
    check Groth16Bn254.validateVerifyingKey(VerifyingKey)
    check Groth16Bn254.validateProof(Proof)

  test "verifies the known proof":
    check Groth16Bn254.verify(VerifyingKey, Proof, PublicInputs)

  test "rejects a modified public input":
    let wrong = @[fromHexFr("00".repeat(31) & "0a")]
    check not Groth16Bn254.verify(VerifyingKey, Proof, wrong)

  test "rejects a modified proof point":
    var tampered = Proof
    tampered[63] = tampered[63] xor 1
    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey, tampered, PublicInputs)

  test "rejects a modified verifying key":
    var tampered = VerifyingKey
    tampered[71] = tampered[71] xor 1
    expect ValueError:
      discard Groth16Bn254.verify(tampered, Proof, PublicInputs)

  test "rejects truncated, oversized, and empty inputs":
    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey[0 ..< VerifyingKey.len - 1], Proof, PublicInputs)

    var trailing = VerifyingKey
    trailing.add(0'u8)
    expect ValueError:
      discard Groth16Bn254.verify(trailing, Proof, PublicInputs)

    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey, Proof[0 ..< Proof.len - 1], PublicInputs)

    expect ValueError:
      discard Groth16Bn254.verify(@[], Proof, PublicInputs)

    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey, @[], PublicInputs)

  test "rejects wrong public input count":
    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey, Proof, @[])

  test "rejects non-canonical public inputs":
    var bad: Bn254Fr
    for i in 0 ..< bad.len:
      bad[i] = 0xff
    expect ValueError:
      discard Groth16Bn254.verify(VerifyingKey, Proof, @[bad])

  test "validate helpers return false for malformed values":
    check not Groth16Bn254.validateVerifyingKey(@[])
    check not Groth16Bn254.validateProof(@[])
    check not Groth16Bn254.validateProof(Proof[0 ..< Proof.len - 1])
