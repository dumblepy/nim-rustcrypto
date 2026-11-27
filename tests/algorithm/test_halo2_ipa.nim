import std/strutils
import unittest
import ../../src/rustcrypto/algorithm/ffi
import ../../src/rustcrypto/algorithm/halo2_ipa
import ../../src/rustcrypto/algorithm/bn254

const Fixture = staticRead("../fixtures/halo2_ipa_bn254_v1.hex")

const
  FrThreeHex = "0000000000000000000000000000000000000000000000000000000000000003"
  FrThirtyFiveHex = "0000000000000000000000000000000000000000000000000000000000000023"
  FrThirtySixHex = "0000000000000000000000000000000000000000000000000000000000000024"
  FrFourHex = "0000000000000000000000000000000000000000000000000000000000000004"

proc fixtureValue(name: string): seq[byte] =
  ## Parses a `NAME=hex` fixture line; accepts lowercase and uppercase hex.
  for rawLine in Fixture.splitLines():
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
  VerifyingKey = fixtureValue("VK")
  Proof = fixtureValue("PROOF")
  Instances = fixtureValue("INSTANCES")
  Witness = fixtureValue("WITNESS")

proc rejected(
    verifyingKey, proof, publicInstances: openArray[byte]
): bool =
  ## `true` when `verify` returns false or raises `ValueError`.
  try:
    result = not Halo2IpaBn254.verify(verifyingKey, proof, publicInstances)
  except ValueError:
    result = true

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
      discard Halo2IpaBn254.prepare(2'u32, 8'u32)
    expect ValueError:
      discard Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 3'u32)
    expect ValueError:
      discard Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 17'u32)
