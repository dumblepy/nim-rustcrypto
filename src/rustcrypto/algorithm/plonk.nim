import ./ffi
import ./common
import ./bn254

type
  PlonkBn254* = object

proc publicInputsBuffer(publicInputs: openArray[Bn254Fr]): seq[byte] =
  result = newSeq[byte](publicInputs.len * Bn254FrLen)
  for i in 0 ..< publicInputs.len:
    for j in 0 ..< Bn254FrLen:
      result[i * Bn254FrLen + j] = publicInputs[i][j]

proc validateVerifyingKey*(T: type PlonkBn254; verifyingKey: openArray[byte]): bool =
  ## Validates the v1 PLONK/BN254 verifying-key encoding without verification.
  if verifyingKey.len != PlonkBn254VkV1Len:
    return false
  plonkBn254VkValidateRaw(
    bytesPtr(verifyingKey), csize_t(verifyingKey.len)
  ) == RustCryptoOk

proc validateProof*(T: type PlonkBn254; proof: openArray[byte]): bool =
  ## Validates the v1 PLONK/BN254 proof encoding without verification.
  if proof.len < PlonkBn254ProofV1MinLen:
    return false
  plonkBn254ProofValidateRaw(
    bytesPtr(proof), csize_t(proof.len)
  ) == RustCryptoOk

proc verify*(
    T: type PlonkBn254;
    verifyingKey: openArray[byte];
    proof: openArray[byte];
    publicInputs: openArray[Bn254Fr];
  ): bool =
  ## Verifies a PLONK/BN254 proof in the fixed **genshi-core 0.3.0 profile**.
  ##
  ## This is not gnark-compatible PLONK. The verifying key carries the KZG SRS
  ## `[1]_2` and `[tau]_2` elements and genshi's canonical VK blob; proofs use
  ## genshi's Keccak Fiat-Shamir transcript and 4-wire selector layout.
  ##
  ## Returns `false` only for a structurally valid proof that fails verification.
  ## Malformed encodings, non-canonical field elements, and public-input count
  ## mismatches raise `ValueError`.
  if verifyingKey.len != PlonkBn254VkV1Len:
    raise newException(ValueError, "PlonkBn254.verify: invalid verifying key length")
  if proof.len < PlonkBn254ProofV1MinLen:
    raise newException(ValueError, "PlonkBn254.verify: invalid proof length")
  if publicInputs.len > PlonkBn254MaxPublicInputs:
    raise newException(ValueError, "PlonkBn254.verify: too many public inputs")

  let inputBytes = publicInputsBuffer(publicInputs)
  let status = plonkBn254VerifyRaw(
    bytesPtr(verifyingKey),
    csize_t(verifyingKey.len),
    bytesPtr(proof),
    csize_t(proof.len),
    bytesPtr(inputBytes),
    csize_t(inputBytes.len),
    csize_t(publicInputs.len),
  )
  case status
  of RustCryptoOk:
    result = true
  of RustCryptoErrVerificationFailed:
    result = false
  else:
    raiseRustCryptoStatus(status, "rustcrypto_plonk_bn254_verify")
