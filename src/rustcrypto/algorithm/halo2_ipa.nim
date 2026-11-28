import ./ffi
import ./common
import ./bn254

const
  ## v1 envelope headers: magic | (circuit_id, k, payload_len) or proof_len.
  Halo2IpaBn254VkHeaderLen = 20
  Halo2IpaBn254PkHeaderLen = 20
  Halo2IpaBn254ProofHeaderLen = 12
  Halo2IpaBn254InstancesHeaderLen = 12
  Halo2IpaBn254InstancesMagic = "RCH2IPI1"
  Halo2IpaBn254MaxInstancesBlobLen =
    Halo2IpaBn254InstancesHeaderLen +
    Halo2IpaBn254MaxInstanceColumns * 4 +
    Halo2IpaBn254MaxInstanceValues * Bn254FrLen
  ## Arbitrary-arity Poseidon2 hash family (circuit ids BASE + 0..=12).
  Halo2IpaBn254Poseidon2MaxArity = 12
  Halo2IpaBn254Poseidon2Rate = 3
  ## Rows occupied by one Poseidon2 permutation (64 rounds + initial state).
  Halo2IpaBn254Poseidon2PermutationRows = 65
  ## Rows reserved by halo2 for blinding (`blinding_factors + 1`).
  Halo2IpaBn254Poseidon2ReservedRows = 6

type
  Halo2IpaBn254* = object

proc poseidon2HashCircuitId*(arity: int): uint32 =
  ## Returns the registered circuit id for a fixed `arity`-input Poseidon2 hash:
  ## `Halo2IpaBn254CircuitPoseidon2HashV1Base + arity`.
  ##
  ## `arity` must be in `0..=12`; anything else
  ## raises `ValueError`. Circuit id 2 remains the legacy 3-input circuit and is
  ## not part of this range.
  if arity < 0 or arity > Halo2IpaBn254Poseidon2MaxArity:
    raise newException(
      ValueError,
      "Halo2IpaBn254.poseidon2HashCircuitId: arity must be in 0.." &
        $Halo2IpaBn254Poseidon2MaxArity & ", got " & $arity,
    )
  Halo2IpaBn254CircuitPoseidon2HashV1Base + uint32(arity)

proc poseidon2HashMinK*(arity: int): uint32 =
  ## Minimum `k` for the fixed `arity`-input Poseidon2 hash circuit.
  ##
  ## Halo2 reserves `blinding_factors + 1 = 6` rows, so the minimum is the
  ## smallest `k` with `2^k - 6 >= hash_circuit_rows(arity)`, where one
  ## permutation occupies 65 rows. This yields `7` for arity `0..=3`, `8` for
  ## `4..=9`, and `9` for `10..=12`.
  if arity < 0 or arity > Halo2IpaBn254Poseidon2MaxArity:
    raise newException(
      ValueError,
      "Halo2IpaBn254.poseidon2HashMinK: arity must be in 0.." &
        $Halo2IpaBn254Poseidon2MaxArity & ", got " & $arity,
    )
  let permutations =
    if arity == 0 or arity mod Halo2IpaBn254Poseidon2Rate != 0:
      arity div Halo2IpaBn254Poseidon2Rate + 1
    else:
      arity div Halo2IpaBn254Poseidon2Rate
  let rows = permutations * Halo2IpaBn254Poseidon2PermutationRows
  for k in int(Halo2IpaBn254MinK) .. int(Halo2IpaBn254MaxK):
    if (1 shl k) - Halo2IpaBn254Poseidon2ReservedRows >= rows:
      return uint32(k)
  raise newException(
    ValueError,
    "Halo2IpaBn254.poseidon2HashMinK: no supported k for arity " & $arity,
  )

proc appendU32Be(output: var seq[byte]; value: uint32) =
  output.add byte((value shr 24) and 0xFF'u32)
  output.add byte((value shr 16) and 0xFF'u32)
  output.add byte((value shr 8) and 0xFF'u32)
  output.add byte(value and 0xFF'u32)

proc prepare*(
    T: type Halo2IpaBn254; circuitId: uint32; k: uint32
): tuple[verifyingKey: seq[byte], provingKey: seq[byte]] =
  ## Derives the transparent IPA params from `k`, then generates the VK/PK for
  ## an approved built-in circuit. No trusted setup is used and no randomness is
  ## consumed; the same `(circuitId, k)` always yields the same keys.
  ##
  ## Supported circuits:
  ## - `Halo2IpaBn254CircuitCubicV1` (id 1): `k` in `Halo2IpaBn254MinK..MaxK`.
  ## - `Halo2IpaBn254CircuitPoseidon2Hash3V1` (id 2): 3-input Poseidon2 hash,
  ##   `k` in `Halo2IpaBn254Poseidon2Hash3MinK..MaxK`.
  ## - `Halo2IpaBn254CircuitPoseidon2HashV1Base + arity` (arity 0..=12):
  ##   fixed `arity`-input Poseidon2 hash, `k` at least `poseidon2HashMinK`.
  let minK =
    if circuitId == Halo2IpaBn254CircuitCubicV1:
      Halo2IpaBn254MinK
    elif circuitId == Halo2IpaBn254CircuitPoseidon2Hash3V1:
      Halo2IpaBn254Poseidon2Hash3MinK
    elif circuitId >= Halo2IpaBn254CircuitPoseidon2HashV1Base and
        circuitId <=
          Halo2IpaBn254CircuitPoseidon2HashV1Base +
            uint32(Halo2IpaBn254Poseidon2MaxArity):
      poseidon2HashMinK(
        int(circuitId - Halo2IpaBn254CircuitPoseidon2HashV1Base)
      )
    else:
      raise newException(
        ValueError, "Halo2IpaBn254.prepare: unsupported circuit id " & $circuitId
      )
  if k < minK or k > Halo2IpaBn254MaxK:
    raise newException(
      ValueError,
      "Halo2IpaBn254.prepare: k must be in " & $minK & ".." &
        $Halo2IpaBn254MaxK & " for circuit " & $circuitId & ", got " & $k,
    )

  # The C ABI writes the required lengths even when the output is null/short.
  var requiredVkLen, requiredPkLen: csize_t
  let sizingStatus = halo2IpaBn254PrepareRaw(
    circuitId,
    k,
    nil,
    0,
    addr requiredVkLen,
    nil,
    0,
    addr requiredPkLen,
  )
  if sizingStatus notin [RustCryptoErrNullOutput, RustCryptoErrOutputTooShort]:
    raiseRustCryptoStatus(sizingStatus, "rustcrypto_halo2_ipa_bn254_prepare")
  if requiredVkLen == 0 or requiredVkLen > csize_t(Halo2IpaBn254MaxVkLen):
    raise newException(
      ValueError, "Halo2IpaBn254.prepare: invalid verifying key length"
    )
  if requiredPkLen == 0 or requiredPkLen > csize_t(Halo2IpaBn254MaxPkLen):
    raise newException(
      ValueError, "Halo2IpaBn254.prepare: invalid proving key length"
    )

  var verifyingKey = newSeq[byte](int(requiredVkLen))
  var provingKey = newSeq[byte](int(requiredPkLen))
  var vkLen, pkLen: csize_t
  let status = halo2IpaBn254PrepareRaw(
    circuitId,
    k,
    bytesPtr(verifyingKey),
    csize_t(verifyingKey.len),
    addr vkLen,
    bytesPtr(provingKey),
    csize_t(provingKey.len),
    addr pkLen,
  )
  if status != RustCryptoOk:
    raiseRustCryptoStatus(status, "rustcrypto_halo2_ipa_bn254_prepare")
  if vkLen != csize_t(verifyingKey.len) or pkLen != csize_t(provingKey.len):
    raise newException(
      ValueError, "Halo2IpaBn254.prepare: Rust returned an inconsistent key length"
    )

  result = (verifyingKey: verifyingKey, provingKey: provingKey)

proc preparePoseidon2Hash*(
    T: type Halo2IpaBn254; arity: int; k: uint32
): tuple[verifyingKey: seq[byte], provingKey: seq[byte]] =
  ## Prepares the VK/PK for the fixed `arity`-input Poseidon2 hash circuit.
  ##
  ## `arity` must be in `0..=12` (12) and `k` at
  ## least `poseidon2HashMinK(arity)`. This is the arbitrary-arity API; circuit
  ## id `2` remains the legacy 3-input circuit available through `prepare`.
  let circuitId = poseidon2HashCircuitId(arity)
  let minK = poseidon2HashMinK(arity)
  if k < minK or k > Halo2IpaBn254MaxK:
    raise newException(
      ValueError,
      "Halo2IpaBn254.preparePoseidon2Hash: k must be in " & $minK & ".." &
        $Halo2IpaBn254MaxK & " for arity " & $arity & ", got " & $k,
    )
  prepare(Halo2IpaBn254, circuitId, k)

proc provingKeyCircuitId(provingKey: openArray[byte]): uint32 =
  ## Reads the circuit id from the v1 PK header (magic | circuit_id u32 BE | ...).
  for index in 8 ..< 12:
    result = (result shl 8) or uint32(provingKey[index])

proc prove*(
    T: type Halo2IpaBn254;
    provingKey: openArray[byte];
    witness: openArray[byte];
    expectedPublicInstances: openArray[byte];
): seq[byte] =
  ## Produces a proof with the OS CSPRNG for blinding.
  ##
  ## The required witness length and instance shape come from the circuit id in
  ## the proving key header:
  ## - cubic (id 1): `witness` is exactly 32 canonical big-endian BN254 `Fr`
  ##   bytes and the instances are one column with one value.
  ## - Poseidon2 hash3 (id 2): `witness` is exactly 96 bytes (three canonical
  ##   big-endian `Fr` values) and the instances are one column with four values
  ##   `[digest, input0, input1, input2]`.
  ## - Poseidon2 arbitrary arity (`BASE + n`, `n` in `0..=12`): `witness` is
  ##   exactly `32 * n` bytes (empty for `n = 0`) and the instances are one
  ##   column with `n + 1` values `[digest, input0, .., input{n-1}]`.
  ##
  ## `expectedPublicInstances` must be the v1 instances blob produced by
  ## `encodePublicInstances` / `encodePoseidon2HashInstances` for the same
  ## statement.
  if provingKey.len < Halo2IpaBn254PkHeaderLen or
      provingKey.len > Halo2IpaBn254MaxPkLen:
    raise newException(ValueError, "Halo2IpaBn254.prove: invalid proving key length")
  let circuitId = provingKeyCircuitId(provingKey)
  let witnessLen =
    if circuitId == Halo2IpaBn254CircuitCubicV1:
      Bn254FrLen
    elif circuitId == Halo2IpaBn254CircuitPoseidon2Hash3V1:
      3 * Bn254FrLen
    elif circuitId >= Halo2IpaBn254CircuitPoseidon2HashV1Base and
        circuitId <=
          Halo2IpaBn254CircuitPoseidon2HashV1Base +
            uint32(Halo2IpaBn254Poseidon2MaxArity):
      int(circuitId - Halo2IpaBn254CircuitPoseidon2HashV1Base) * Bn254FrLen
    else:
      raise newException(
        ValueError, "Halo2IpaBn254.prove: unsupported circuit id " & $circuitId
      )
  if witness.len != witnessLen:
    raise newException(
      ValueError,
      "Halo2IpaBn254.prove: witness must be exactly " & $witnessLen &
        " bytes for circuit " & $circuitId,
    )
  if expectedPublicInstances.len < Halo2IpaBn254InstancesHeaderLen or
      expectedPublicInstances.len > Halo2IpaBn254MaxInstancesBlobLen:
    raise newException(
      ValueError, "Halo2IpaBn254.prove: invalid public instances length"
    )

  # Proving is randomized, so the sizing call performs one full proof and then
  # repeats it for the caller-owned output buffer.
  var requiredLen: csize_t
  let sizingStatus = halo2IpaBn254ProveRaw(
    bytesPtr(provingKey),
    csize_t(provingKey.len),
    bytesPtr(witness),
    csize_t(witness.len),
    bytesPtr(expectedPublicInstances),
    csize_t(expectedPublicInstances.len),
    nil,
    0,
    addr requiredLen,
  )
  if sizingStatus notin [RustCryptoErrNullOutput, RustCryptoErrOutputTooShort]:
    raiseRustCryptoStatus(sizingStatus, "rustcrypto_halo2_ipa_bn254_prove")
  if requiredLen == 0 or requiredLen > csize_t(Halo2IpaBn254MaxProofLen):
    raise newException(ValueError, "Halo2IpaBn254.prove: invalid proof length")

  var proof = newSeq[byte](int(requiredLen))
  var proofLen: csize_t
  let status = halo2IpaBn254ProveRaw(
    bytesPtr(provingKey),
    csize_t(provingKey.len),
    bytesPtr(witness),
    csize_t(witness.len),
    bytesPtr(expectedPublicInstances),
    csize_t(expectedPublicInstances.len),
    bytesPtr(proof),
    csize_t(proof.len),
    addr proofLen,
  )
  if status != RustCryptoOk:
    raiseRustCryptoStatus(status, "rustcrypto_halo2_ipa_bn254_prove")
  if proofLen != csize_t(proof.len):
    raise newException(
      ValueError, "Halo2IpaBn254.prove: Rust returned an inconsistent proof length"
    )

  result = proof

proc verify*(
    T: type Halo2IpaBn254;
    verifyingKey: openArray[byte];
    proof: openArray[byte];
    publicInstances: openArray[byte];
): bool =
  ## Verifies a transparent Halo2 IPA/BN254 proof against the expected public
  ## instances. Returns `false` only for a structurally valid but invalid proof.
  ##
  ## The circuit id is read from the verifying key header and selects the
  ## instance shape: cubic (id 1) takes one column with one value; Poseidon2
  ## hash3 (id 2) takes one column `[digest, input0, input1, input2]`; the
  ## arbitrary-arity Poseidon2 family (`BASE + n`) takes one column with
  ## `n + 1` values.
  ##
  ## The IPA params are regenerated deterministically from the `k` embedded in
  ## the verifying key header (optionally cached per canister instance in the
  ## Rust core). The verification path must not require caller entropy,
  ## filesystem, clock, threads, or network; the wasm runtime smoke enforces
  ## that contract by throwing on every host import.
  if verifyingKey.len < Halo2IpaBn254VkHeaderLen or
      verifyingKey.len > Halo2IpaBn254MaxVkLen:
    raise newException(ValueError, "Halo2IpaBn254.verify: invalid verifying key length")
  if proof.len < Halo2IpaBn254ProofHeaderLen or
      proof.len > Halo2IpaBn254MaxProofLen:
    raise newException(ValueError, "Halo2IpaBn254.verify: invalid proof length")
  if publicInstances.len < Halo2IpaBn254InstancesHeaderLen or
      publicInstances.len > Halo2IpaBn254MaxInstancesBlobLen:
    raise newException(
      ValueError, "Halo2IpaBn254.verify: invalid public instances length"
    )

  let status = halo2IpaBn254VerifyRaw(
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
    raiseRustCryptoStatus(status, "rustcrypto_halo2_ipa_bn254_verify")

proc validateVerifyingKey*(T: type Halo2IpaBn254; verifyingKey: openArray[byte]): bool =
  ## Validates the v1 VK envelope, including the embedded `halo2_axiom` key.
  if verifyingKey.len < Halo2IpaBn254VkHeaderLen or
      verifyingKey.len > Halo2IpaBn254MaxVkLen:
    return false
  halo2IpaBn254VkValidateRaw(
    bytesPtr(verifyingKey), csize_t(verifyingKey.len)
  ) == RustCryptoOk

proc validateProvingKey*(T: type Halo2IpaBn254; provingKey: openArray[byte]): bool =
  ## Validates the v1 PK envelope, including the embedded `halo2_axiom` key.
  if provingKey.len < Halo2IpaBn254PkHeaderLen or
      provingKey.len > Halo2IpaBn254MaxPkLen:
    return false
  halo2IpaBn254PkValidateRaw(
    bytesPtr(provingKey), csize_t(provingKey.len)
  ) == RustCryptoOk

proc validateProof*(T: type Halo2IpaBn254; proof: openArray[byte]): bool =
  ## Validates the v1 proof envelope (magic, length, exact size).
  if proof.len < Halo2IpaBn254ProofHeaderLen or
      proof.len > Halo2IpaBn254MaxProofLen:
    return false
  halo2IpaBn254ProofValidateRaw(
    bytesPtr(proof), csize_t(proof.len)
  ) == RustCryptoOk

proc validatePublicInstances*(
    T: type Halo2IpaBn254; publicInstances: openArray[byte]
): bool =
  ## Validates the v1 instances encoding (magic, counts, canonical `Fr`,
  ## trailing bytes).
  if publicInstances.len < Halo2IpaBn254InstancesHeaderLen or
      publicInstances.len > Halo2IpaBn254MaxInstancesBlobLen:
    return false
  halo2IpaBn254InstancesValidateRaw(
    bytesPtr(publicInstances), csize_t(publicInstances.len)
  ) == RustCryptoOk

proc encodePublicInstances*(values: openArray[Bn254Fr]): seq[byte] =
  ## Encodes one instance column (`values`) in the v1 instances wire format:
  ## `"RCH2IPI1" | column_count u32 BE | value_count u32 BE | Fr*32 BE`.
  ##
  ## Values must already be canonical big-endian `Fr` encodings; non-canonical
  ## inputs raise `ValueError` instead of being reduced.
  if values.len > Halo2IpaBn254MaxInstanceValues:
    raise newException(
      ValueError, "Halo2IpaBn254.encodePublicInstances: too many instance values"
    )
  for value in values:
    if not Bn254.isCanonicalFr(value):
      raise newException(
        ValueError,
        "Halo2IpaBn254.encodePublicInstances: non-canonical BN254 Fr value",
      )

  result = newSeqOfCap[byte](
    Halo2IpaBn254InstancesHeaderLen + values.len * Bn254FrLen
  )
  for ch in Halo2IpaBn254InstancesMagic:
    result.add byte(ord(ch))
  appendU32Be(result, 1'u32) # one instance column
  appendU32Be(result, uint32(values.len))
  for value in values:
    result.add value

proc encodePoseidon2HashInstances*(
    inputs: openArray[Bn254Fr]; digest: Bn254Fr
): seq[byte] =
  ## Encodes the Poseidon2 hash public instance column
  ## `[digest, inputs[0], .., inputs[n-1]]` in the v1 instances wire format.
  ##
  ## `inputs.len` must be in `0..=12` (12). This
  ## covers the legacy circuit id 2 (3 inputs) and the arbitrary-arity family
  ## (`BASE + n`). Values must already be canonical big-endian `Fr` encodings;
  ## non-canonical inputs raise `ValueError`.
  if inputs.len > Halo2IpaBn254Poseidon2MaxArity:
    raise newException(
      ValueError,
      "Halo2IpaBn254.encodePoseidon2HashInstances: inputs must be 0.." &
        $Halo2IpaBn254Poseidon2MaxArity,
    )
  var values = newSeqOfCap[Bn254Fr](inputs.len + 1)
  values.add digest
  for input in inputs:
    values.add input
  encodePublicInstances(values)

proc provePoseidon2Hash*(
    T: type Halo2IpaBn254;
    provingKey: openArray[byte];
    inputs: openArray[Bn254Fr];
    digest: Bn254Fr;
): seq[byte] =
  ## Proves the arbitrary-arity Poseidon2 hash circuit in `provingKey` with the
  ## OS CSPRNG for blinding.
  ##
  ## `inputs.len` must be in `0..=12` and must match
  ## the arity encoded in the proving key header. The witness is the
  ## concatenation of the canonical big-endian `Fr` inputs (empty for 0 inputs)
  ## and the public instance column is `[digest, inputs...]`. A digest that does
  ## not equal the circuit's Poseidon2 output is rejected by the Rust core with
  ## `ValueError`.
  if inputs.len > Halo2IpaBn254Poseidon2MaxArity:
    raise newException(
      ValueError,
      "Halo2IpaBn254.provePoseidon2Hash: inputs must be 0.." &
        $Halo2IpaBn254Poseidon2MaxArity,
    )
  var witness = newSeqOfCap[byte](inputs.len * Bn254FrLen)
  for input in inputs:
    witness.add input
  let instances = encodePoseidon2HashInstances(inputs, digest)
  prove(Halo2IpaBn254, provingKey, witness, instances)
