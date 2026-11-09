import std/strutils
import unittest
import ./utils
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/groth16
import ../../src/rustcrypto/algorithm/plonk
import ../../src/rustcrypto/algorithm/plonky2
import ../../src/rustcrypto/algorithm/halo2

const
  Groth16Fixture = staticRead("../fixtures/groth16_bn254_v1.hex")
  PlonkFixture = staticRead("../fixtures/plonk_bn254_v1.hex")
  Plonky2Fixture = staticRead("../fixtures/plonky2_v1.hex")
  Halo2Fixture = staticRead("../fixtures/halo2_kzg_bn254_v1.hex")

proc fixtureValue(fixture, name: string): seq[byte] =
  for line in fixture.splitLines:
    let separator = line.find('=')
    if separator > 0 and line[0 ..< separator] == name:
      return bytesFromHex(line[separator + 1 .. ^1])
  raise newException(ValueError, "missing fixture: " & name)

proc fixtureFr(fixture, name: string): Bn254Fr =
  fromHexFr(bytesToHexString(fixtureValue(fixture, name)))

let
  G16Vk = fixtureValue(Groth16Fixture, "VK")
  G16Proof = fixtureValue(Groth16Fixture, "PROOF")
  G16Inputs = @[fixtureFr(Groth16Fixture, "INPUTS")]

  PlonkVk = fixtureValue(PlonkFixture, "VK")
  PlonkProof = fixtureValue(PlonkFixture, "PROOF")
  PlonkInputs = @[fixtureFr(PlonkFixture, "INPUTS")]

  Plonky2Proof = fixtureValue(Plonky2Fixture, "MUL_PROOF")
  Plonky2Verifier = fixtureValue(Plonky2Fixture, "MUL_VERIFIER")
  Plonky2Common = fixtureValue(Plonky2Fixture, "MUL_COMMON")

  Halo2Params = fixtureValue(Halo2Fixture, "PARAMS")
  Halo2Vk = fixtureValue(Halo2Fixture, "VK")
  Halo2Proof = fixtureValue(Halo2Fixture, "PROOF")
  Halo2Instances = fixtureValue(Halo2Fixture, "INSTANCES")

template rejects(body: untyped): bool =
  block:
    var rejected = false
    try:
      if not body:
        rejected = true
    except ValueError:
      rejected = true
    rejected

suite "zkp scheme separation":
  test "Groth16 does not accept PLONK, Plonky2, or Halo2 proofs":
    check rejects(Groth16Bn254.verify(G16Vk, PlonkProof, G16Inputs))
    check rejects(Groth16Bn254.verify(G16Vk, Plonky2Proof, G16Inputs))
    check rejects(Groth16Bn254.verify(G16Vk, Halo2Proof, G16Inputs))

  test "PLONK does not accept Groth16, Plonky2, or Halo2 proofs":
    check rejects(PlonkBn254.verify(PlonkVk, G16Proof, PlonkInputs))
    check rejects(PlonkBn254.verify(PlonkVk, Plonky2Proof, PlonkInputs))
    check rejects(PlonkBn254.verify(PlonkVk, Halo2Proof, PlonkInputs))

  test "Plonky2 does not accept Groth16, PLONK, or Halo2 proofs":
    check rejects(Plonky2Goldilocks.verify(G16Proof, Plonky2Verifier, Plonky2Common))
    check rejects(Plonky2Goldilocks.verify(PlonkProof, Plonky2Verifier, Plonky2Common))
    check rejects(Plonky2Goldilocks.verify(Halo2Proof, Plonky2Verifier, Plonky2Common))

  test "Halo2 does not accept Groth16, PLONK, or Plonky2 proofs":
    check rejects(Halo2KzgBn254.verify(Halo2Params, Halo2Vk, G16Proof, Halo2Instances))
    check rejects(Halo2KzgBn254.verify(Halo2Params, Halo2Vk, PlonkProof, Halo2Instances))
    check rejects(Halo2KzgBn254.verify(Halo2Params, Halo2Vk, Plonky2Proof, Halo2Instances))
