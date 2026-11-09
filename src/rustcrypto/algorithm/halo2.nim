import ./ffi
import ./common

when defined(wasm32):
  {.error: "Halo2 KZG/BN254 verification (snark-verifier/halo2-axiom) is not supported on wasm32 targets. Use the native (Linux x86_64 / macOS arm64) archive.".}

type
  Halo2KzgBn254* = object

proc validateParams*(T: type Halo2KzgBn254; params: openArray[byte]): bool =
  ## Validates the v1 Halo2 KZG/BN254 params (SRS subset).
  if params.len != Halo2KzgBn254ParamsV1Len:
    return false
  halo2KzgBn254ParamsValidateRaw(
    bytesPtr(params), csize_t(params.len)
  ) == RustCryptoOk

proc validateVerifyingKey*(T: type Halo2KzgBn254; verifyingKey: openArray[byte]): bool =
  ## Validates the v1 Halo2 KZG/BN254 verifying key (bincode-encoded protocol).
  if verifyingKey.len < 12 or verifyingKey.len > 12 + Halo2KzgBn254MaxProtocolLen:
    return false
  halo2KzgBn254VkValidateRaw(
    bytesPtr(verifyingKey), csize_t(verifyingKey.len)
  ) == RustCryptoOk

proc validatePublicInstances*(T: type Halo2KzgBn254; publicInstances: openArray[byte]): bool =
  ## Validates the v1 Halo2 public-instances encoding.
  if publicInstances.len < 12 or publicInstances.len > Halo2KzgBn254MaxProofLen:
    return false
  halo2KzgBn254InstancesValidateRaw(
    bytesPtr(publicInstances), csize_t(publicInstances.len)
  ) == RustCryptoOk

proc verify*(
    T: type Halo2KzgBn254;
    params: openArray[byte];
    verifyingKey: openArray[byte];
    proof: openArray[byte];
    publicInstances: openArray[byte];
  ): bool =
  ## Verifies a Halo2 PSE/Axiom KZG/BN254 **SHPLONK** proof with the **Blake2b**
  ## Fiat-Shamir transcript.
  ##
  ## This profile is neither Zcash `halo2_proofs` IPA/Pasta nor gnark PLONK.
  ## `params` is the v1 SRS subset (`[1]_1`, `[1]_2`, `[tau]_2`), `verifyingKey`
  ## contains the bincode-encoded `PlonkProtocol`, and `publicInstances` is the
  ## v1 multi-column instance encoding.
  ##
  ## Returns `false` only for a structurally valid proof that fails verification.
  ## Malformed blobs, mismatched instance counts, and non-canonical field
  ## elements raise `ValueError`.
  ##
  ## The caller must trust the SRS and the verifying key (circuit).
  if params.len != Halo2KzgBn254ParamsV1Len:
    raise newException(ValueError, "Halo2KzgBn254.verify: invalid params length")
  if verifyingKey.len < 12 or verifyingKey.len > 12 + Halo2KzgBn254MaxProtocolLen:
    raise newException(ValueError, "Halo2KzgBn254.verify: invalid verifying key length")
  if proof.len < 1 or proof.len > Halo2KzgBn254MaxProofLen:
    raise newException(ValueError, "Halo2KzgBn254.verify: invalid proof length")
  if publicInstances.len < 12 or publicInstances.len > Halo2KzgBn254MaxProofLen:
    raise newException(ValueError, "Halo2KzgBn254.verify: invalid public instances length")

  let status = halo2KzgBn254VerifyRaw(
    bytesPtr(params),
    csize_t(params.len),
    bytesPtr(verifyingKey),
    csize_t(verifyingKey.len),
    bytesPtr(proof),
    csize_t(proof.len),
    bytesPtr(publicInstances),
    csize_t(publicInstances.len),
  )
  case status
  of RustCryptoOk:
    result = true
  of RustCryptoErrVerificationFailed:
    result = false
  else:
    raiseRustCryptoStatus(status, "rustcrypto_halo2_kzg_bn254_verify")
