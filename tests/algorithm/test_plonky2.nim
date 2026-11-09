import std/strutils
import unittest
import ./utils
import ../../src/rustcrypto/algorithm/plonky2

const Fixture = staticRead("../fixtures/plonky2_v1.hex")

proc fixtureValue(name: string): string =
  for line in Fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return line[separator + 1 .. ^1]
  raise newException(ValueError, "missing fixture: " & name)

proc rejected(proof, verifier, common: seq[byte]): bool =
  try:
    result = not Plonky2Goldilocks.verify(proof, verifier, common)
  except ValueError:
    result = true

let
  MulProof = bytesFromHex(fixtureValue("MUL_PROOF"))
  MulVerifier = bytesFromHex(fixtureValue("MUL_VERIFIER"))
  MulCommon = bytesFromHex(fixtureValue("MUL_COMMON"))
  AddProof = bytesFromHex(fixtureValue("ADD_PROOF"))
  AddVerifier = bytesFromHex(fixtureValue("ADD_VERIFIER"))
  AddCommon = bytesFromHex(fixtureValue("ADD_COMMON"))

suite "plonky2 goldilocks":
  test "fixture encodings are valid":
    check Plonky2Goldilocks.validateVerifierCircuitData(MulVerifier)
    check Plonky2Goldilocks.validateCommonCircuitData(MulCommon)
    check Plonky2Goldilocks.validateVerifierCircuitData(AddVerifier)
    check Plonky2Goldilocks.validateCommonCircuitData(AddCommon)

  test "verifies both known proofs":
    check Plonky2Goldilocks.verify(MulProof, MulVerifier, MulCommon)
    check Plonky2Goldilocks.verify(AddProof, AddVerifier, AddCommon)

  test "rejects mismatched verifier/common circuit data":
    check rejected(MulProof, AddVerifier, AddCommon)
    check rejected(AddProof, MulVerifier, MulCommon)
    check rejected(MulProof, AddVerifier, MulCommon)
    check rejected(MulProof, MulVerifier, AddCommon)

  test "rejects a modified proof":
    var tampered = MulProof
    let last = tampered.len - 1
    tampered[last] = tampered[last] xor 1
    check rejected(tampered, MulVerifier, MulCommon)

  test "rejects truncated and empty blobs":
    check rejected(MulProof[0 ..< MulProof.len - 1], MulVerifier, MulCommon)
    check rejected(MulProof, MulVerifier[0 ..< MulVerifier.len - 1], MulCommon)
    check rejected(MulProof, MulVerifier, MulCommon[0 ..< MulCommon.len - 1])

    expect ValueError:
      discard Plonky2Goldilocks.verify(@[], MulVerifier, MulCommon)
    expect ValueError:
      discard Plonky2Goldilocks.verify(MulProof, @[], MulCommon)
    expect ValueError:
      discard Plonky2Goldilocks.verify(MulProof, MulVerifier, @[])

  test "validate helpers return false for malformed values":
    check not Plonky2Goldilocks.validateVerifierCircuitData(@[])
    check not Plonky2Goldilocks.validateCommonCircuitData(@[])
    var garbage = @[1'u8, 2, 3, 4]
    check not Plonky2Goldilocks.validateVerifierCircuitData(garbage)
    check not Plonky2Goldilocks.validateCommonCircuitData(garbage)
