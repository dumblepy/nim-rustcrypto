import ./ffi
import ./common
import ./bn254

type
  Groth16Bn254* = object

proc groth16VkMaxLen(): int =
  Groth16Bn254VkV1HeaderLen + Bn254G1Len + 3 * Bn254G2Len + 4 +
    Groth16Bn254MaxIcLen * Bn254G1Len

proc publicInputsBuffer(publicInputs: openArray[Bn254Fr]): seq[byte] =
  result = newSeq[byte](publicInputs.len * Bn254FrLen)
  for i in 0 ..< publicInputs.len:
    for j in 0 ..< Bn254FrLen:
      result[i * Bn254FrLen + j] = publicInputs[i][j]

proc validateVerifyingKey*(T: type Groth16Bn254; verifyingKey: openArray[byte]): bool =
  ## Validates the v1 Groth16/BN254 verifying-key encoding without a pairing check.
  if verifyingKey.len < Groth16Bn254VkV1HeaderLen or verifyingKey.len > groth16VkMaxLen():
    return false
  groth16Bn254VkValidateRaw(
    bytesPtr(verifyingKey), csize_t(verifyingKey.len)
  ) == RustCryptoOk

proc validateProof*(T: type Groth16Bn254; proof: openArray[byte]): bool =
  ## Validates the v1 Groth16/BN254 proof encoding without a pairing check.
  if proof.len != Groth16Bn254ProofV1Len:
    return false
  groth16Bn254ProofValidateRaw(
    bytesPtr(proof), csize_t(proof.len)
  ) == RustCryptoOk

proc verify*(
    T: type Groth16Bn254;
    verifyingKey: openArray[byte];
    proof: openArray[byte];
    publicInputs: openArray[Bn254Fr];
  ): bool =
  ## Verifies a Groth16/BN254 proof against a v1 verifying key and ordered public inputs.
  ##
  ## - Returns `true` when the proof verifies.
  ## - Returns `false` when the encodings are structurally valid but the proof does not verify.
  ## - Raises `ValueError` for malformed keys/proofs, non-canonical field elements,
  ##   or a public-input count that does not match the verifying key.
  ##
  ## A successful result only means the proof is valid for the supplied verifying key.
  ## The caller is responsible for deciding whether that key (circuit) is trusted.
  if verifyingKey.len < Groth16Bn254VkV1HeaderLen or verifyingKey.len > groth16VkMaxLen():
    raise newException(ValueError, "Groth16Bn254.verify: invalid verifying key length")
  if proof.len != Groth16Bn254ProofV1Len:
    raise newException(ValueError, "Groth16Bn254.verify: invalid proof length")
  if publicInputs.len > Groth16Bn254MaxPublicInputs:
    raise newException(ValueError, "Groth16Bn254.verify: too many public inputs")

  let inputBytes = publicInputsBuffer(publicInputs)
  let status = groth16Bn254VerifyRaw(
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
    raiseRustCryptoStatus(status, "rustcrypto_groth16_bn254_verify")
