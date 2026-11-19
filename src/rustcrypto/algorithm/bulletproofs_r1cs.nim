## Experimental Bulletproofs R1CS using approved Ristretto255 circuit definitions.
import ./[common, ffi]

const
  BulletproofsR1csProfile* = "bulletproofs-r1cs-ristretto255-v1"
  scalarBytes = 32
  commitmentCountOffset = 38
  maxPublicInputs = 128
  maxWitness = 1024
  maxCommitments = 64
  maxProofBytes = 42 + 1057 + maxCommitments * scalarBytes

type
  BulletproofsR1cs* = object
  BulletproofsR1csProver* = object
  BulletproofsR1csError* = object of ValueError
    status*: cint
  BulletproofsR1csCircuit* = object
    encoding: seq[byte]
  BulletproofsR1csProof* = object
    encoding: seq[byte]
  BulletproofsR1csPublicInput* = distinct array[32, byte]
  BulletproofsR1csWitness* = distinct array[32, byte]
  BulletproofsR1csBlinding* = distinct array[32, byte]
  BulletproofsR1csCommitment* = distinct array[32, byte]

proc checkStatus(status: cint) =
  if status < 0:
    var error = newException(BulletproofsR1csError, "Bulletproofs R1CS error " & $status)
    error.status = status
    raise error

proc packedPtr[T](values: openArray[T]): ptr byte =
  static:
    doAssert sizeof(T) == scalarBytes
  if values.len > 0:
    cast[ptr byte](unsafeAddr values[0])
  else:
    nil

proc loadCircuit*(T: type BulletproofsR1cs; approvedEncoding: openArray[byte]): BulletproofsR1csCircuit =
  ## Call with a locally approved circuit.
  checkStatus bulletproofsR1csValidateRaw(3, bytesPtr(approvedEncoding), csize_t(approvedEncoding.len))
  result.encoding = @approvedEncoding

proc loadProof*(T: type BulletproofsR1cs; encoding: openArray[byte]): BulletproofsR1csProof =
  checkStatus bulletproofsR1csValidateRaw(0, bytesPtr(encoding), csize_t(encoding.len))
  result.encoding = @encoding

proc toBytes*(proof: BulletproofsR1csProof): seq[byte] =
  result = newSeq[byte](proof.encoding.len)
  for i, value in proof.encoding:
    result[i] = value

proc validateProof*(T: type BulletproofsR1cs; encoding: openArray[byte]): bool =
  bulletproofsR1csValidateRaw(0, bytesPtr(encoding), csize_t(encoding.len)) == 0

proc validatePublicInputs*(T: type BulletproofsR1cs; values: openArray[BulletproofsR1csPublicInput]): bool =
  values.len <= maxPublicInputs and
    bulletproofsR1csValidateRaw(1, packedPtr(values), csize_t(values.len * scalarBytes)) == 0

proc validateCommitments*(T: type BulletproofsR1cs; values: openArray[BulletproofsR1csCommitment]): bool =
  values.len <= maxCommitments and
    bulletproofsR1csValidateRaw(2, packedPtr(values), csize_t(values.len * scalarBytes)) == 0

proc commitments*(proof: BulletproofsR1csProof): seq[BulletproofsR1csCommitment] =
  checkStatus bulletproofsR1csValidateRaw(0, bytesPtr(proof.encoding), csize_t(proof.encoding.len))
  let count = int(proof.encoding[commitmentCountOffset]) or
    (int(proof.encoding[commitmentCountOffset + 1]) shl 8)
  result = newSeq[BulletproofsR1csCommitment](count)
  if count > 0:
    let byteCount = count * scalarBytes
    copyMem(addr result[0], unsafeAddr proof.encoding[proof.encoding.len - byteCount], byteCount)

proc prove*(
    T: type BulletproofsR1csProver;
    circuit: BulletproofsR1csCircuit;
    publicInputs: openArray[BulletproofsR1csPublicInput];
    witness: openArray[BulletproofsR1csWitness];
    context: openArray[byte];
    blindings: openArray[BulletproofsR1csBlinding] = [];
): BulletproofsR1csProof =
  ## Empty blindings select fresh OS randomness. Supply existing secret openings
  ## only when proving a statement about previously agreed commitments.
  if publicInputs.len > maxPublicInputs or witness.len > maxWitness or blindings.len > maxCommitments:
    checkStatus(-2)
  result.encoding = newSeq[byte](maxProofBytes)
  let status = bulletproofsR1csProveRaw(
    bytesPtr(circuit.encoding), csize_t(circuit.encoding.len),
    packedPtr(publicInputs), csize_t(publicInputs.len * scalarBytes),
    packedPtr(witness), csize_t(witness.len * scalarBytes),
    packedPtr(blindings), csize_t(blindings.len * scalarBytes),
    bytesPtr(context), csize_t(context.len),
    addr result.encoding[0], csize_t(result.encoding.len),
  )
  checkStatus(status)
  result.encoding.setLen(int(status))

proc verify*(
    T: type BulletproofsR1cs;
    circuit: BulletproofsR1csCircuit;
    publicInputs: openArray[BulletproofsR1csPublicInput];
    context: openArray[byte];
    proof: BulletproofsR1csProof;
): bool =
  ## For a statement with pre-agreed commitments, compare proof.commitments
  ## with the expected ordered list as part of verification.
  if publicInputs.len > maxPublicInputs:
    checkStatus(-2)
  let status = bulletproofsR1csVerifyRaw(
    bytesPtr(circuit.encoding), csize_t(circuit.encoding.len),
    packedPtr(publicInputs), csize_t(publicInputs.len * scalarBytes),
    bytesPtr(context), csize_t(context.len),
    bytesPtr(proof.encoding), csize_t(proof.encoding.len),
  )
  checkStatus(status)
  result = status == 1

proc `==`*(left, right: BulletproofsR1csCommitment): bool {.borrow.}

proc verifyWithCommitments*(
    T: type BulletproofsR1cs;
    circuit: BulletproofsR1csCircuit;
    publicInputs: openArray[BulletproofsR1csPublicInput];
    context: openArray[byte];
    proof: BulletproofsR1csProof;
    expected: openArray[BulletproofsR1csCommitment];
): bool =
  ## Verify a statement whose ordered commitments were supplied independently.
  if expected.len > maxCommitments:
    checkStatus(-2)
  if not T.validateCommitments(expected):
    checkStatus(-1)
  let actual = proof.commitments
  if actual.len != expected.len:
    checkStatus(-3)
  for i, commitment in actual:
    if commitment != expected[i]:
      return false
  T.verify(circuit, publicInputs, context, proof)
