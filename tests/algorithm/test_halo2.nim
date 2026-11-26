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

  test "rejects a modified verifying key inside the protocol region":
    check VerifyingKey.len > 20

    # The protocol body starts at offset 12. Its first 8 bytes encode
    # `domain.k`, which `PlonkVerifier::verify` never reads, so flipping only
    # that byte still verifies. Offset 20 is `domain.n` (little-endian u64),
    # which the verifier does consume, so tampering there must be rejected.
    var wrongDomain = VerifyingKey
    wrongDomain[20] = wrongDomain[20] xor 1
    check wrongDomain.len == VerifyingKey.len
    check rejected(Params, wrongDomain, Proof, Instances)

    var wrongTail = VerifyingKey
    wrongTail[^1] = wrongTail[^1] xor 1
    check wrongTail.len == VerifyingKey.len
    check rejected(Params, wrongTail, Proof, Instances)

  test "rejects a tampered SRS/params blob":
    var wrongFirst = Params
    wrongFirst[0] = wrongFirst[0] xor 1
    check rejected(wrongFirst, VerifyingKey, Proof, Instances)

    var wrongLast = Params
    wrongLast[^1] = wrongLast[^1] xor 1
    check wrongLast.len == Params.len
    check rejected(wrongLast, VerifyingKey, Proof, Instances)

  test "raw verify rejects null pointers with non-zero lengths":
    check halo2KzgBn254VerifyRaw(
      nil,
      csize_t(Halo2KzgBn254ParamsV1Len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrNullInputWithData

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      nil,
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrNullInputWithData

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      nil,
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrNullInputWithData

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Proof.len),
      nil,
      csize_t(Instances.len),
    ) == RustCryptoErrNullInputWithData

  test "raw validate helpers enforce null and zero-length contracts":
    check halo2KzgBn254ParamsValidateRaw(nil, csize_t(0)) ==
      RustCryptoErrInvalidLength
    check halo2KzgBn254ParamsValidateRaw(
      nil, csize_t(Halo2KzgBn254ParamsV1Len)
    ) == RustCryptoErrNullInputWithData

    check halo2KzgBn254VkValidateRaw(nil, csize_t(0)) ==
      RustCryptoErrInvalidVerifyingKey
    check halo2KzgBn254VkValidateRaw(nil, csize_t(12)) ==
      RustCryptoErrNullInputWithData

    check halo2KzgBn254InstancesValidateRaw(nil, csize_t(0)) ==
      RustCryptoErrInvalidLength
    check halo2KzgBn254InstancesValidateRaw(nil, csize_t(12)) ==
      RustCryptoErrNullInputWithData

  test "raw verify rejects zero-length fields":
    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(0),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrInvalidLength

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(0),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrInvalidVerifyingKey

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(0),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrInvalidProofFormat

    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(0),
    ) == RustCryptoErrInvalidLength

  test "repeated verification is stable":
    for _ in 0 ..< 50:
      check Halo2KzgBn254.verify(Params, VerifyingKey, Proof, Instances)

  test "validate helpers reject short, truncated, and oversized inputs":
    check not Halo2KzgBn254.validateParams(@[0'u8])
    check not Halo2KzgBn254.validateVerifyingKey(@[0'u8])
    check not Halo2KzgBn254.validatePublicInstances(@[0'u8])

    check not Halo2KzgBn254.validateParams(Params[0 ..< Params.len - 1])
    check not Halo2KzgBn254.validateVerifyingKey(
      VerifyingKey[0 ..< VerifyingKey.len - 1]
    )

    # The documented VK maximum is 12 + 2 MiB; only go one byte past it.
    let oversizedVk = newSeq[byte](12 + Halo2KzgBn254MaxProtocolLen + 1)
    check not Halo2KzgBn254.validateVerifyingKey(oversizedVk)

    check halo2KzgBn254ParamsValidateRaw(
      bytesPtr(Params), csize_t(Params.len - 1)
    ) == RustCryptoErrInvalidLength

    # Length checks run before any dereference, so the valid fixture pointers
    # are safe to pair with oversized declared lengths.
    check halo2KzgBn254VkValidateRaw(
      bytesPtr(VerifyingKey), csize_t(12 + Halo2KzgBn254MaxProtocolLen + 1)
    ) == RustCryptoErrInvalidVerifyingKey
    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(12 + Halo2KzgBn254MaxProtocolLen + 1),
      bytesPtr(Proof),
      csize_t(Proof.len),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrInvalidVerifyingKey
    check halo2KzgBn254VerifyRaw(
      bytesPtr(Params),
      csize_t(Params.len),
      bytesPtr(VerifyingKey),
      csize_t(VerifyingKey.len),
      bytesPtr(Proof),
      csize_t(Halo2KzgBn254MaxProofLen + 1),
      bytesPtr(Instances),
      csize_t(Instances.len),
    ) == RustCryptoErrInvalidProofFormat
    check halo2KzgBn254InstancesValidateRaw(
      bytesPtr(Instances), csize_t(Halo2KzgBn254MaxProofLen + 1)
    ) == RustCryptoErrInvalidLength
