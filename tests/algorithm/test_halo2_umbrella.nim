import std/strutils
import unittest
# Exercise the umbrella module export path, not only the dedicated module.
import ../../src/rustcrypto

const Fixture = staticRead("../fixtures/halo2_kzg_bn254_v1.hex")

proc bytesFromHex(hex: string): seq[byte] =
  doAssert hex.len mod 2 == 0
  for i in countup(0, hex.len - 1, 2):
    result.add(parseHexInt(hex[i .. i + 1]).byte)

proc fixtureValue(name: string): seq[byte] =
  for line in Fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return bytesFromHex(line[separator + 1 .. ^1])
  raise newException(ValueError, "missing fixture: " & name)

suite "halo2 through the rustcrypto umbrella module":
  test "Halo2KzgBn254 is exported and verifies the known proof":
    let
      params = fixtureValue("PARAMS")
      vk = fixtureValue("VK")
      proof = fixtureValue("PROOF")
      instances = fixtureValue("INSTANCES")

    check Halo2KzgBn254.validateParams(params)
    check Halo2KzgBn254.validateVerifyingKey(vk)
    check Halo2KzgBn254.validatePublicInstances(instances)
    check Halo2KzgBn254.verify(params, vk, proof, instances)
