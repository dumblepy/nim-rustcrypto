import ./ffi
import ./common

type
  Plonky2Goldilocks* = object

proc validateVerifierCircuitData*(T: type Plonky2Goldilocks; verifierOnlyCircuitData: openArray[byte]): bool =
  ## Validates plonky2 `VerifierOnlyCircuitData` bytes.
  if verifierOnlyCircuitData.len < 1 or verifierOnlyCircuitData.len > Plonky2MaxBlobLen:
    return false
  plonky2VerifierValidateRaw(
    bytesPtr(verifierOnlyCircuitData), csize_t(verifierOnlyCircuitData.len)
  ) == RustCryptoOk

proc validateCommonCircuitData*(T: type Plonky2Goldilocks; commonCircuitData: openArray[byte]): bool =
  ## Validates plonky2 `CommonCircuitData` bytes and their resource bounds.
  if commonCircuitData.len < 1 or commonCircuitData.len > Plonky2MaxBlobLen:
    return false
  plonky2CommonValidateRaw(
    bytesPtr(commonCircuitData), csize_t(commonCircuitData.len)
  ) == RustCryptoOk

proc verify*(
    T: type Plonky2Goldilocks;
    proofWithPublicInputs: openArray[byte];
    verifierOnlyCircuitData: openArray[byte];
    commonCircuitData: openArray[byte];
  ): bool =
  ## Verifies a Plonky2/Goldilocks (`D = 2`, `PoseidonGoldilocksConfig`) proof.
  ##
  ## The three blobs must be produced by the matching qp-plonky2 1.6.0 profile:
  ## `ProofWithPublicInputs::to_bytes`, `VerifierOnlyCircuitData::to_bytes`, and
  ## `CommonCircuitData::to_bytes(&DefaultGateSerializer)`.
  ##
  ## Returns `false` only for a structurally valid proof that fails verification.
  ## Malformed blobs and mismatched circuit data raise `ValueError`.
  ##
  ## Plonky2 proofs are circuit-configuration specific. The caller must pin the
  ## verifier/common circuit data (including its circuit digest) to an approved circuit.
  if proofWithPublicInputs.len < 1 or proofWithPublicInputs.len > Plonky2MaxBlobLen:
    raise newException(ValueError, "Plonky2Goldilocks.verify: invalid proof length")
  if verifierOnlyCircuitData.len < 1 or verifierOnlyCircuitData.len > Plonky2MaxBlobLen:
    raise newException(ValueError, "Plonky2Goldilocks.verify: invalid verifier data length")
  if commonCircuitData.len < 1 or commonCircuitData.len > Plonky2MaxBlobLen:
    raise newException(ValueError, "Plonky2Goldilocks.verify: invalid common circuit data length")

  let status = plonky2VerifyRaw(
    bytesPtr(proofWithPublicInputs),
    csize_t(proofWithPublicInputs.len),
    bytesPtr(verifierOnlyCircuitData),
    csize_t(verifierOnlyCircuitData.len),
    bytesPtr(commonCircuitData),
    csize_t(commonCircuitData.len),
  )
  case status
  of RustCryptoOk:
    result = true
  of RustCryptoErrVerificationFailed:
    result = false
  else:
    raiseRustCryptoStatus(status, "rustcrypto_plonky2_verify")
