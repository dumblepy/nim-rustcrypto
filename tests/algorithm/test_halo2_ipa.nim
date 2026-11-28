import std/strutils
import unittest
import ../../src/rustcrypto/algorithm/ffi
import ../../src/rustcrypto/algorithm/halo2_ipa
import ../../src/rustcrypto/algorithm/bn254
import ../../src/rustcrypto/algorithm/poseidon2

const Fixture = staticRead("../fixtures/halo2_ipa_bn254_v1.hex")
const Poseidon2Fixture = staticRead("../fixtures/halo2_ipa_poseidon2_v1.hex")
const Poseidon2Arity12Fixture =
  staticRead("../fixtures/halo2_ipa_poseidon2_arity12_v1.hex")

const
  ## v1 instances envelope: magic (8) + column_count u32 (4).
  IpaInstancesHeaderLen = 12
  ## value_count u32 that precedes each instance column.
  IpaInstanceValueCountLen = 4

const
  FrOneHex = "0000000000000000000000000000000000000000000000000000000000000001"
  FrTwoHex = "0000000000000000000000000000000000000000000000000000000000000002"
  FrThreeHex = "0000000000000000000000000000000000000000000000000000000000000003"
  FrThirtyFiveHex = "0000000000000000000000000000000000000000000000000000000000000023"
  FrThirtySixHex = "0000000000000000000000000000000000000000000000000000000000000024"
  FrFourHex = "0000000000000000000000000000000000000000000000000000000000000004"
  Poseidon2DigestHex =
    "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8"

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

let
  VerifyingKey = fixtureValue(Fixture, "VK")
  Proof = fixtureValue(Fixture, "PROOF")
  Instances = fixtureValue(Fixture, "INSTANCES")
  Witness = fixtureValue(Fixture, "WITNESS")
  Poseidon2Vk = fixtureValue(Poseidon2Fixture, "VK")
  Poseidon2Proof = fixtureValue(Poseidon2Fixture, "PROOF")
  Poseidon2Instances = fixtureValue(Poseidon2Fixture, "INSTANCES")
  Poseidon2Witness = fixtureValue(Poseidon2Fixture, "WITNESS")
  Poseidon2Arity12Vk = fixtureValue(Poseidon2Arity12Fixture, "VK")
  Poseidon2Arity12Proof = fixtureValue(Poseidon2Arity12Fixture, "PROOF")
  Poseidon2Arity12Instances = fixtureValue(Poseidon2Arity12Fixture, "INSTANCES")
  Poseidon2Arity12Witness = fixtureValue(Poseidon2Arity12Fixture, "WITNESS")

proc poseidon2Witness(
    inputs: array[3, Bn254Fr]
): seq[byte] =
  ## Concatenates three canonical BE `Fr` values into the id-2 witness.
  for input in inputs:
    result.add input

proc poseidon2Inputs(): array[3, Bn254Fr] =
  [
    fromHexFr(FrOneHex),
    fromHexFr(FrTwoHex),
    fromHexFr(FrThreeHex),
  ]

proc rejected(
    verifyingKey, proof, publicInstances: openArray[byte]
): bool =
  ## `true` when `verify` returns false or raises `ValueError`.
  try:
    result = not Halo2IpaBn254.verify(verifyingKey, proof, publicInstances)
  except ValueError:
    result = true

proc frFromU64(value: uint64): Bn254Fr =
  ## Encodes a small integer as canonical big-endian BN254 `Fr`.
  var remaining = value
  for index in countdown(Bn254FrLen - 1, 0):
    result[index] = byte(remaining and 0xFF'u64)
    remaining = remaining shr 8

proc poseidon2ArityInputs(arity: int): seq[Bn254Fr] =
  ## Inputs `1, .., arity` for the arbitrary-arity Poseidon2 hash tests.
  result = newSeq[Bn254Fr](arity)
  for index in 0 ..< arity:
    result[index] = frFromU64(uint64(index + 1))

suite "halo2 ipa bn254 (transparent, no trusted setup)":
  test "fixture encodings are valid and the proof verifies":
    check Witness.len == Bn254FrLen
    check Halo2IpaBn254.validateVerifyingKey(VerifyingKey)
    check Halo2IpaBn254.validateProof(Proof)
    check Halo2IpaBn254.validatePublicInstances(Instances)
    check Halo2IpaBn254.verify(VerifyingKey, Proof, Instances)
    # Repeated verification is side-effect free.
    check Halo2IpaBn254.verify(VerifyingKey, Proof, Instances)

  test "encodePublicInstances matches the committed wire format":
    check encodePublicInstances([fromHexFr(FrThirtyFiveHex)]) ==
      Instances
    var noncanonical: Bn254Fr
    for i in 0 ..< noncanonical.len:
      noncanonical[i] = 0xFF
    expect ValueError:
      discard encodePublicInstances([noncanonical])

  test "rejects a modified public instance":
    var wrong = Instances
    wrong[^1] = wrong[^1] xor 1 # y = 35 -> 34, still canonical
    check rejected(VerifyingKey, Proof, wrong)

    let wrongValue = encodePublicInstances([fromHexFr(FrThirtySixHex)])
    check not Halo2IpaBn254.verify(VerifyingKey, Proof, wrongValue)

  test "rejects a modified or truncated proof":
    var tamperedLast = Proof
    tamperedLast[^1] = tamperedLast[^1] xor 1
    check rejected(VerifyingKey, tamperedLast, Instances)

    var tamperedFirst = Proof
    tamperedFirst[0] = tamperedFirst[0] xor 1
    check rejected(VerifyingKey, tamperedFirst, Instances)

    var trailing = Proof
    trailing.add(0'u8)
    check rejected(VerifyingKey, trailing, Instances)

    expect ValueError:
      discard Halo2IpaBn254.verify(
        VerifyingKey, Proof[0 ..< Proof.len - 1], Instances
      )

  test "rejects bad magic, wrong lengths, and empty blobs":
    var badVkMagic = VerifyingKey
    badVkMagic[0] = badVkMagic[0] xor 1
    expect ValueError:
      discard Halo2IpaBn254.verify(badVkMagic, Proof, Instances)

    var badProofMagic = Proof
    badProofMagic[0] = badProofMagic[0] xor 1
    expect ValueError:
      discard Halo2IpaBn254.verify(VerifyingKey, badProofMagic, Instances)

    var badInstancesMagic = Instances
    badInstancesMagic[0] = badInstancesMagic[0] xor 1
    expect ValueError:
      discard Halo2IpaBn254.verify(VerifyingKey, Proof, badInstancesMagic)

    expect ValueError:
      discard Halo2IpaBn254.verify(
        VerifyingKey[0 ..< VerifyingKey.len - 1], Proof, Instances
      )
    expect ValueError:
      discard Halo2IpaBn254.verify(
        VerifyingKey, Proof, Instances[0 ..< Instances.len - 1]
      )

    let empty: seq[byte] = @[]
    expect ValueError:
      discard Halo2IpaBn254.verify(empty, Proof, Instances)
    expect ValueError:
      discard Halo2IpaBn254.verify(VerifyingKey, empty, Instances)
    expect ValueError:
      discard Halo2IpaBn254.verify(VerifyingKey, Proof, empty)

    check not Halo2IpaBn254.validateVerifyingKey(empty)
    check not Halo2IpaBn254.validateProvingKey(empty)
    check not Halo2IpaBn254.validateProof(empty)
    check not Halo2IpaBn254.validatePublicInstances(empty)

  test "rejects a non-canonical Fr public instance":
    var noncanonical = Instances
    for i in noncanonical.len - Bn254FrLen ..< noncanonical.len:
      noncanonical[i] = 0xFF
    check not Halo2IpaBn254.validatePublicInstances(noncanonical)
    expect ValueError:
      discard Halo2IpaBn254.verify(VerifyingKey, Proof, noncanonical)

  test "prepare/prove/verify roundtrip":
    let (provingVk, provingPk) = Halo2IpaBn254.prepare(
      Halo2IpaBn254CircuitCubicV1, 8'u32
    )
    check Halo2IpaBn254.validateVerifyingKey(provingVk)
    check Halo2IpaBn254.validateProvingKey(provingPk)

    let witness = fromHexFr(FrThreeHex)
    let y = fromHexFr(FrThirtyFiveHex)
    let instances = encodePublicInstances([y])
    let proof = Halo2IpaBn254.prove(provingPk, witness, instances)
    check Halo2IpaBn254.validateProof(proof)
    check Halo2IpaBn254.verify(provingVk, proof, instances)

    let wrongInstances = encodePublicInstances(
      [fromHexFr(FrThirtySixHex)]
    )
    check not Halo2IpaBn254.verify(provingVk, proof, wrongInstances)

    expect ValueError:
      discard Halo2IpaBn254.prove(provingPk, witness, wrongInstances)
    expect ValueError:
      discard Halo2IpaBn254.prove(
        provingPk, fromHexFr(FrFourHex), instances
      )
    expect ValueError:
      discard Halo2IpaBn254.prove(provingPk, @[], instances)
    expect ValueError:
      discard Halo2IpaBn254.prepare(3'u32, 8'u32)
    expect ValueError:
      discard Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 3'u32)
    expect ValueError:
      discard Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 17'u32)
    expect ValueError:
      discard Halo2IpaBn254.prepare(
        Halo2IpaBn254CircuitPoseidon2Hash3V1, 6'u32
      )
    expect ValueError:
      discard Halo2IpaBn254.prepare(
        Halo2IpaBn254CircuitPoseidon2Hash3V1, 17'u32
      )

  test "poseidon2 fixture encodings are valid and the proof verifies":
    check Poseidon2Witness.len == 3 * Bn254FrLen
    check Halo2IpaBn254.validateVerifyingKey(Poseidon2Vk)
    check Halo2IpaBn254.validateProof(Poseidon2Proof)
    check Halo2IpaBn254.validatePublicInstances(Poseidon2Instances)
    check Halo2IpaBn254.verify(Poseidon2Vk, Poseidon2Proof, Poseidon2Instances)
    # Repeated verification is side-effect free.
    check Halo2IpaBn254.verify(Poseidon2Vk, Poseidon2Proof, Poseidon2Instances)
    # The fixture is the registered circuit id 2.
    let circuitId =
      uint32(Poseidon2Vk[8]) shl 24 or
      uint32(Poseidon2Vk[9]) shl 16 or
      uint32(Poseidon2Vk[10]) shl 8 or
      uint32(Poseidon2Vk[11])
    check circuitId == Halo2IpaBn254CircuitPoseidon2Hash3V1

  test "poseidon2 pinned verification binds the approved V2 VK":
    # SHA-256 of the complete committed V2 Poseidon2 VK envelope.
    const poseidon2VkSha256Hex =
      "2dd45d84727cdeae9b23ace1a12bcb8d86d9b1a516b6ee0058867da02e063f7e"
    var poseidon2VkSha256 = newSeq[byte](Halo2IpaBn254VkDigestLen)
    for i in 0 ..< poseidon2VkSha256.len:
      poseidon2VkSha256[i] =
        byte(parseHexInt(poseidon2VkSha256Hex[2 * i .. 2 * i + 1]))

    check Halo2IpaBn254.validateVerifyingKeyPinned(
      Poseidon2Vk, poseidon2VkSha256
    )
    check Halo2IpaBn254.verifyPinned(
      Poseidon2Vk, poseidon2VkSha256, Poseidon2Proof, Poseidon2Instances
    )

    var wrongDigest = poseidon2VkSha256
    wrongDigest[0] = if wrongDigest[0] == 0: 1'u8 else: 0'u8
    check not Halo2IpaBn254.validateVerifyingKeyPinned(
      Poseidon2Vk, wrongDigest
    )
    # A pin mismatch is an approval failure, not an invalid proof: the wrapper
    # raises `RustCryptoErrInvalidVerifyingKey`.
    expect ValueError:
      discard Halo2IpaBn254.verifyPinned(
        Poseidon2Vk, wrongDigest, Poseidon2Proof, Poseidon2Instances
      )

  test "encodePoseidon2HashInstances matches the fixture instances":
    let inputs = poseidon2Inputs()
    let digest = fromHexFr(Poseidon2DigestHex)
    check encodePoseidon2HashInstances(inputs, digest) == Poseidon2Instances
    check poseidon2Witness(inputs) == Poseidon2Witness

    var noncanonical = poseidon2Inputs()
    for i in 0 ..< noncanonical[0].len:
      noncanonical[0][i] = 0xFF
    expect ValueError:
      discard encodePoseidon2HashInstances(
        noncanonical, fromHexFr(Poseidon2DigestHex)
      )

  test "poseidon2 rejects a wrong digest and modified proof":
    # The digest is the first 32 bytes after the instances header.
    let digestStart = IpaInstancesHeaderLen + IpaInstanceValueCountLen
    var wrongDigest = Poseidon2Instances
    wrongDigest[digestStart + Bn254FrLen - 1] =
      wrongDigest[digestStart + Bn254FrLen - 1] xor 1
    check Halo2IpaBn254.validatePublicInstances(wrongDigest)
    check not Halo2IpaBn254.verify(
      Poseidon2Vk, Poseidon2Proof, wrongDigest
    )

    var tamperedLast = Poseidon2Proof
    tamperedLast[^1] = tamperedLast[^1] xor 1
    check rejected(Poseidon2Vk, tamperedLast, Poseidon2Instances)

    var tamperedFirst = Poseidon2Proof
    tamperedFirst[0] = tamperedFirst[0] xor 1
    check rejected(Poseidon2Vk, tamperedFirst, Poseidon2Instances)

    expect ValueError:
      discard Halo2IpaBn254.verify(
        Poseidon2Vk,
        Poseidon2Proof[0 ..< Poseidon2Proof.len - 1],
        Poseidon2Instances,
      )

  test "poseidon2 rejects non-canonical and wrong-shaped instances":
    let inputStart = IpaInstancesHeaderLen + IpaInstanceValueCountLen + Bn254FrLen
    var noncanonical = Poseidon2Instances
    for i in inputStart ..< inputStart + Bn254FrLen:
      noncanonical[i] = 0xFF
    check not Halo2IpaBn254.validatePublicInstances(noncanonical)
    expect ValueError:
      discard Halo2IpaBn254.verify(
        Poseidon2Vk, Poseidon2Proof, noncanonical
      )

    let oneValue = encodePublicInstances([fromHexFr(Poseidon2DigestHex)])
    check rejected(Poseidon2Vk, Poseidon2Proof, oneValue)
    expect ValueError:
      discard Halo2IpaBn254.verify(
        Poseidon2Vk,
        Poseidon2Proof,
        encodePublicInstances(
          [fromHexFr(Poseidon2DigestHex), fromHexFr(FrOneHex)]
        ),
      )

  test "poseidon2 prepare/prove/verify roundtrip":
    let (provingVk, provingPk) = Halo2IpaBn254.prepare(
      Halo2IpaBn254CircuitPoseidon2Hash3V1, 8'u32
    )
    check Halo2IpaBn254.validateVerifyingKey(provingVk)
    check Halo2IpaBn254.validateProvingKey(provingPk)

    let inputs = poseidon2Inputs()
    let digest = fromHexFr(Poseidon2DigestHex)
    let witness = poseidon2Witness(inputs)
    let instances = encodePoseidon2HashInstances(inputs, digest)
    let proof = Halo2IpaBn254.prove(provingPk, witness, instances)
    check Halo2IpaBn254.validateProof(proof)
    check Halo2IpaBn254.verify(provingVk, proof, instances)

    var wrongDigest = instances
    wrongDigest[IpaInstancesHeaderLen + IpaInstanceValueCountLen + Bn254FrLen - 1] =
      wrongDigest[IpaInstancesHeaderLen + IpaInstanceValueCountLen + Bn254FrLen - 1] xor 1
    check not Halo2IpaBn254.verify(provingVk, proof, wrongDigest)

    # A witness that disagrees with the public inputs is rejected.
    var wrongWitness = poseidon2Witness(inputs)
    wrongWitness[^1] = wrongWitness[^1] xor 1
    expect ValueError:
      discard Halo2IpaBn254.prove(provingPk, wrongWitness, instances)

    # The cubic witness length (32 bytes) is not a Poseidon2 witness.
    expect ValueError:
      discard Halo2IpaBn254.prove(
        provingPk, fromHexFr(FrOneHex), instances
      )

  test "arbitrary arity circuit ids and minimum k":
    check Halo2IpaBn254CircuitPoseidon2HashV1Base == 0x100'u32
    check poseidon2HashCircuitId(0) == 0x100'u32
    check poseidon2HashCircuitId(3) == 0x103'u32
    check poseidon2HashCircuitId(12) == 0x10C'u32
    expect ValueError:
      discard poseidon2HashCircuitId(-1)
    expect ValueError:
      discard poseidon2HashCircuitId(13)

    for arity in 0 .. 3:
      check poseidon2HashMinK(arity) == 7'u32
    for arity in 4 .. 9:
      check poseidon2HashMinK(arity) == 8'u32
    for arity in 10 .. 12:
      check poseidon2HashMinK(arity) == 9'u32
    expect ValueError:
      discard poseidon2HashMinK(13)

  test "encodePoseidon2HashInstances accepts 0..12 inputs":
    let digest = fromHexFr(Poseidon2DigestHex)
    for arity in 0 .. 12:
      let inputs = poseidon2ArityInputs(arity)
      let encoded = encodePoseidon2HashInstances(inputs, digest)
      check encoded.len ==
        IpaInstancesHeaderLen + IpaInstanceValueCountLen +
          (arity + 1) * Bn254FrLen
      check Halo2IpaBn254.validatePublicInstances(encoded)

    var tooMany = newSeq[Bn254Fr](13)
    for index in 0 ..< tooMany.len:
      tooMany[index] = fromHexFr(FrOneHex)
    expect ValueError:
      discard encodePoseidon2HashInstances(tooMany, digest)

  test "arbitrary arity 12 fixture verifies":
    check Poseidon2Arity12Witness.len == 12 * Bn254FrLen
    check Halo2IpaBn254.validateVerifyingKey(Poseidon2Arity12Vk)
    check Halo2IpaBn254.validateProof(Poseidon2Arity12Proof)
    check Halo2IpaBn254.validatePublicInstances(Poseidon2Arity12Instances)
    check Halo2IpaBn254.verify(
      Poseidon2Arity12Vk, Poseidon2Arity12Proof, Poseidon2Arity12Instances
    )

    var circuitId: uint32
    for index in 8 ..< 12:
      circuitId = (circuitId shl 8) or uint32(Poseidon2Arity12Vk[index])
    check circuitId == poseidon2HashCircuitId(12)

    var expectedWitness: seq[byte]
    for input in poseidon2ArityInputs(12):
      expectedWitness.add input
    check expectedWitness == Poseidon2Arity12Witness

    # The legacy id-2 fixture remains the 3-input circuit.
    var legacyCircuitId: uint32
    for index in 8 ..< 12:
      legacyCircuitId =
        (legacyCircuitId shl 8) or uint32(Poseidon2Vk[index])
    check legacyCircuitId == Halo2IpaBn254CircuitPoseidon2Hash3V1

  test "arbitrary arity prepare/prove/verify roundtrip":
    for arity in [0, 2, 4, 9, 12]:
      let minK = poseidon2HashMinK(arity)
      let (verifyingKey, provingKey) =
        Halo2IpaBn254.preparePoseidon2Hash(arity, minK)
      check Halo2IpaBn254.validateVerifyingKey(verifyingKey)
      check Halo2IpaBn254.validateProvingKey(provingKey)

      # The circuit id encodes the arity and is not the legacy id 2.
      var encodedCircuitId: uint32
      for index in 8 ..< 12:
        encodedCircuitId =
          (encodedCircuitId shl 8) or uint32(verifyingKey[index])
      check encodedCircuitId == poseidon2HashCircuitId(arity)

      let inputs = poseidon2ArityInputs(arity)
      let digest = Poseidon2Bn254.hash(inputs)
      let instances = encodePoseidon2HashInstances(inputs, digest)
      check Halo2IpaBn254.validatePublicInstances(instances)
      let proof = Halo2IpaBn254.provePoseidon2Hash(
        provingKey, inputs, digest
      )
      check Halo2IpaBn254.validateProof(proof)
      check Halo2IpaBn254.verify(verifyingKey, proof, instances)

      # A wrong digest is structurally valid but does not verify.
      let digestLast = IpaInstancesHeaderLen + IpaInstanceValueCountLen +
        Bn254FrLen - 1
      var wrongInstances = instances
      wrongInstances[digestLast] = wrongInstances[digestLast] xor 1
      check Halo2IpaBn254.validatePublicInstances(wrongInstances)
      check not Halo2IpaBn254.verify(
        verifyingKey, proof, wrongInstances
      )

      # A wrong digest is also rejected before proving.
      var wrongDigest = digest
      wrongDigest[^1] = wrongDigest[^1] xor 1
      expect ValueError:
        discard Halo2IpaBn254.provePoseidon2Hash(
          provingKey, inputs, wrongDigest
        )

      # `k` below the computed minimum is rejected.
      expect ValueError:
        discard Halo2IpaBn254.preparePoseidon2Hash(arity, minK - 1)
      expect ValueError:
        discard Halo2IpaBn254.preparePoseidon2Hash(arity, 17'u32)
      expect ValueError:
        discard Halo2IpaBn254.preparePoseidon2Hash(13, 9'u32)
