import std/sysrand
import ./[ffi, common, bn254]

type
  Groth16Bn254Prover* = object
  Groth16Wire* = object
    index: uint32
  Groth16Circuit* = object
    publicCount, privateCount, nodes, cost: int
    operations: seq[byte]
  Groth16KeyPair* = object
    provingKey*, verifyingKey*: seq[byte]

const Groth16ProverMaxKeyBytes* = 16 * 1024 * 1024

# Volatile writes prevent dead-store elimination before releasing temporary buffers.
{.emit: """
static void rustcrypto_prover_wipe(void *buffer, size_t length) {
  volatile unsigned char *p = (volatile unsigned char *)buffer;
  while (length != 0) { *p++ = 0; --length; }
}
""".}
proc wipeSecret(buffer: pointer; length: csize_t) {.importc: "rustcrypto_prover_wipe", nodecl.}

proc clearWitness*(T: type Groth16Bn254Prover; witness: var openArray[Bn254Fr]) =
  ## Clears the caller-owned witness array; callers remain responsible for other copies.
  if witness.len > 0:
    wipeSecret(addr witness[0], csize_t(witness.len * sizeof(Bn254Fr)))

proc appendU32(outBytes: var seq[byte]; value: uint32) =
  for shift in [24, 16, 8, 0]:
    outBytes.add(byte((value shr shift) and 255))

proc circuit*(T: type Groth16Bn254Prover; publicCount, privateCount: int): Groth16Circuit =
  if publicCount notin 1..256 or privateCount notin 0..256:
    raise newException(ValueError, "Groth16 circuit: input count out of bounds")
  Groth16Circuit(publicCount: publicCount, privateCount: privateCount)

proc publicInput*(c: Groth16Circuit; index: int): Groth16Wire =
  if index < 0 or index >= c.publicCount:
    raise newException(ValueError, "Groth16 circuit: public input index")
  Groth16Wire(index: uint32(index))

proc privateInput*(c: Groth16Circuit; index: int): Groth16Wire =
  if index < 0 or index >= c.privateCount:
    raise newException(ValueError, "Groth16 circuit: private input index")
  Groth16Wire(index: uint32(c.publicCount + index))

proc operation(c: var Groth16Circuit; tag, aux: byte;
    args: openArray[Groth16Wire]; constant: Bn254Fr = default(Bn254Fr)): Groth16Wire =
  let next = c.publicCount + c.privateCount + c.nodes
  let cost = if tag == 4:
    let width = args.len + 1
    let partial = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65][args.len - 1]
    3 * (8 * width + partial) + (8 + partial) * width + 8
  elif tag == 5: 768
  elif tag == 6: 6
  elif tag == 0: 1
  else: 2
  if c.publicCount == 0 or c.nodes >= 1024 or c.cost + cost > 32768:
    raise newException(ValueError, "Groth16 circuit: resource limit")
  for arg in args:
    if int(arg.index) >= next:
      raise newException(ValueError, "Groth16 circuit: forward reference")
  c.operations.add([tag, aux, byte(args.len)])
  for arg in args: c.operations.appendU32(arg.index)
  if tag == 0: c.operations.add(constant)
  inc c.nodes
  c.cost += cost
  Groth16Wire(index: uint32(next))

proc constant*(c: var Groth16Circuit; value: Bn254Fr): Groth16Wire =
  if not Bn254.isCanonicalFr(value):
    raise newException(ValueError, "Groth16 circuit: non-canonical constant")
  c.operation(0, 0, [], value)

proc add*(c: var Groth16Circuit; a, b: Groth16Wire): Groth16Wire =
  c.operation(1, 0, [a, b])
proc mul*(c: var Groth16Circuit; a, b: Groth16Wire): Groth16Wire =
  c.operation(2, 0, [a, b])
proc enforceEqual*(c: var Groth16Circuit; a, b: Groth16Wire) =
  discard c.operation(3, 0, [a, b])
proc poseidon*(c: var Groth16Circuit; inputs: openArray[Groth16Wire]): Groth16Wire =
  if inputs.len notin 1..12:
    raise newException(ValueError, "Groth16 circuit: Poseidon arity")
  c.operation(4, 0, inputs)
proc enforceRange*(c: var Groth16Circuit; value: Groth16Wire; bits: int) =
  if bits notin 1..128:
    raise newException(ValueError, "Groth16 circuit: range must be 1..128 bits")
  discard c.operation(5, byte(bits), [value])
proc select*(c: var Groth16Circuit; selector, yes, no: Groth16Wire): Groth16Wire =
  c.operation(6, 0, [selector, yes, no])
proc boundedSum*(c: var Groth16Circuit; values: openArray[Groth16Wire]; bits: int): Groth16Wire =
  if values.len == 0:
    raise newException(ValueError, "Groth16 circuit: empty sum")
  result = c.constant(default(Bn254Fr))
  for value in values:
    c.enforceRange(value, bits)
    result = c.add(result, value)
    c.enforceRange(result, bits)
proc merkleRoot*(c: var Groth16Circuit; leaf: Groth16Wire;
    siblings, directions: openArray[Groth16Wire]): Groth16Wire =
  if siblings.len == 0 or siblings.len > 32 or siblings.len != directions.len:
    raise newException(ValueError, "Groth16 circuit: invalid Merkle path")
  result = leaf
  for i in 0..<siblings.len:
    let left = c.select(directions[i], siblings[i], result)
    let right = c.select(directions[i], result, siblings[i])
    result = c.poseidon([left, right])
proc prf*(c: var Groth16Circuit; domain: Bn254Fr; secret, context: Groth16Wire): Groth16Wire =
  let domainWire = c.constant(domain)
  c.poseidon([domainWire, secret, context])
proc toBytes*(c: Groth16Circuit): seq[byte] =
  if c.publicCount == 0:
    raise newException(ValueError, "Groth16 circuit: uninitialized")
  result = @[82'u8, 67, 67, 73, 82, 48, 49, 0]
  for n in [c.publicCount, c.privateCount, c.nodes]: result.appendU32(uint32(n))
  result.add(c.operations)

proc hostRandom(output: ptr uint8; length: csize_t): cint {.cdecl.} =
  try:
    if length > 32 or output == nil: return RustCryptoErrRandomFailed
    var random = newSeq[byte](int(length))
    defer:
      if random.len > 0: wipeSecret(addr random[0], csize_t(random.len))
    if not urandom(random): return RustCryptoErrRandomFailed
    if random.len > 0: copyMem(output, addr random[0], random.len)
    RustCryptoOk
  except:
    RustCryptoErrRandomFailed

proc setup*(T: type Groth16Bn254Prover; circuit: Groth16Circuit): Groth16KeyPair =
  ## Single-party setup for development. Production needs reviewed key provenance.
  let definition = circuit.toBytes()
  result.provingKey = newSeq[byte](Groth16ProverMaxKeyBytes)
  result.verifyingKey = newSeq[byte](460 + 257 * 64)
  var pkLen, vkLen: csize_t
  let status = groth16Bn254SetupRaw(bytesPtr(definition), csize_t(definition.len), hostRandom,
    addr result.provingKey[0], csize_t(result.provingKey.len), addr pkLen,
    addr result.verifyingKey[0], csize_t(result.verifyingKey.len), addr vkLen)
  if status != RustCryptoOk: raiseRustCryptoStatus(status, "Groth16Bn254Prover.setup")
  result.provingKey.setLen(int(pkLen))
  result.verifyingKey.setLen(int(vkLen))

proc encodeFields(values: openArray[Bn254Fr]): seq[byte] =
  for value in values: result.add(value)

proc prove*(T: type Groth16Bn254Prover; circuit: Groth16Circuit;
    provingKey: openArray[byte]; publicInputs, witness: openArray[Bn254Fr]): array[256, byte] =
  if publicInputs.len != circuit.publicCount or witness.len != circuit.privateCount or
      provingKey.len == 0 or provingKey.len > Groth16ProverMaxKeyBytes:
    raise newException(ValueError, "Groth16 prover: invalid input/key length")
  let definition = circuit.toBytes()
  let inputs = encodeFields(publicInputs)
  var secrets = encodeFields(witness)
  defer:
    if secrets.len > 0: wipeSecret(addr secrets[0], csize_t(secrets.len))
  let status = groth16Bn254ProveRaw(bytesPtr(definition), csize_t(definition.len),
    bytesPtr(provingKey), csize_t(provingKey.len), bytesPtr(inputs), csize_t(inputs.len),
    bytesPtr(secrets), csize_t(secrets.len), hostRandom, addr result[0], 256)
  if status != RustCryptoOk: raiseRustCryptoStatus(status, "Groth16Bn254Prover.prove")
