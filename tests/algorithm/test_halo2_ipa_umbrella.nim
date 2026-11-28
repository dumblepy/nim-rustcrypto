import std/strutils
import unittest
import ../../src/rustcrypto

const Fixture = staticRead("../fixtures/halo2_ipa_bn254_v1.hex")
const Poseidon2Fixture = staticRead("../fixtures/halo2_ipa_poseidon2_v1.hex")

proc fixtureValue(fixture: string; name: string): seq[byte] =
  ## Parses a `NAME=hex` fixture line; accepts lowercase and uppercase hex.
  for rawLine in fixture.splitLines():
    let line = rawLine.strip()
    let separator = line.find('=')
    if separator <= 0 or line[0 ..< separator].strip() != name:
      continue
    let hex = line[separator + 1 .. ^1].strip()
    if hex.len mod 2 != 0:
      raise newException(ValueError, "odd-length fixture hex for " & name)
    result = newSeq[byte](hex.len div 2)
    for i in 0 ..< result.len:
      result[i] = byte(parseHexInt(hex[2 * i .. 2 * i + 1]))
    return
  raise newException(ValueError, "missing fixture value: " & name)

suite "halo2 ipa through the rustcrypto umbrella module":
  test "constants are exported":
    check Halo2IpaBn254CircuitCubicV1 == 1'u32
    check Halo2IpaBn254CircuitPoseidon2Hash3V1 == 2'u32
    check Halo2IpaBn254CircuitPoseidon2HashV1Base == 0x100'u32
    check Halo2IpaBn254MinK == 4'u32
    check Halo2IpaBn254Poseidon2Hash3MinK == 7'u32
    check Halo2IpaBn254MaxK == 16'u32
    check Halo2IpaBn254MaxVkLen > 0
    check Halo2IpaBn254MaxPkLen > 0
    check Halo2IpaBn254MaxProofLen > 0
    check Halo2IpaBn254MaxInstanceColumns == 8
    check Halo2IpaBn254MaxInstanceValues == 4096

  test "committed cubic fixture verifies through the umbrella export":
    let
      verifyingKey = fixtureValue(Fixture, "VK")
      proof = fixtureValue(Fixture, "PROOF")
      instances = fixtureValue(Fixture, "INSTANCES")
    check Halo2IpaBn254.validateVerifyingKey(verifyingKey)
    check Halo2IpaBn254.validateProof(proof)
    check Halo2IpaBn254.validatePublicInstances(instances)
    check Halo2IpaBn254.verify(verifyingKey, proof, instances)

  test "committed Poseidon2 fixture verifies through the umbrella export":
    let
      verifyingKey = fixtureValue(Poseidon2Fixture, "VK")
      proof = fixtureValue(Poseidon2Fixture, "PROOF")
      instances = fixtureValue(Poseidon2Fixture, "INSTANCES")
      witness = fixtureValue(Poseidon2Fixture, "WITNESS")
    check witness.len == 3 * Bn254FrLen
    check Halo2IpaBn254.validateVerifyingKey(verifyingKey)
    check Halo2IpaBn254.validateProof(proof)
    check Halo2IpaBn254.validatePublicInstances(instances)
    check Halo2IpaBn254.verify(verifyingKey, proof, instances)
    check Halo2IpaBn254.verify(verifyingKey, proof, instances)
