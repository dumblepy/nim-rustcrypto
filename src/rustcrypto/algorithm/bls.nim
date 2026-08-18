import ./ffi
import ./common

type
  Bls* = object
  BlsScalar* = array[Bls12381ScalarLen, byte]
  BlsG1Compressed* = array[Bls12381G1CompressedLen, byte]
  BlsG1Uncompressed* = array[Bls12381G1UncompressedLen, byte]
  BlsG2Compressed* = array[Bls12381G2CompressedLen, byte]
  BlsG2Uncompressed* = array[Bls12381G2UncompressedLen, byte]
  BlsPrivateKey* = array[Bls12381ScalarLen, byte]
  BlsPublicKey* = array[Bls12381G1CompressedLen, byte]
  BlsSignature* = array[Bls12381G2CompressedLen, byte]
  BlsMessageHash* = array[Bls12381G2CompressedLen, byte]
  BlsAugG1PublicKey* = BlsG2Compressed
  BlsAugG1Signature* = BlsG1Compressed
  BlsAugG1MessageHash* = BlsG1Compressed

proc blsBytesHex*(value: openArray[byte]): string =
  ## Hex dump for any BLS-related fixed-size byte representation.
  bytesToHexString(value)

proc raiseIfError(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrVerificationFailed:
    raise newException(
      ValueError,
      operation & " failed: unexpected verification status (use bool-returning API)",
    )
  else:
    raiseRustCryptoStatus(status, operation)

proc boolFromVerify(status: cint; operation: string): bool =
  case status
  of RustCryptoOk:
    return true
  of RustCryptoErrVerificationFailed:
    return false
  else:
    raiseRustCryptoStatus(status, operation)

proc boolFromPairingEq(status: cint; operation: string): bool =
  boolFromVerify(status, operation)

proc boolFromPairingProductIdentity(status: cint; operation: string): bool =
  boolFromVerify(status, operation)

proc fromHexScalar*(hex: string): BlsScalar =
  fromHexDigest[BlsScalar](hex, Bls12381ScalarLen)

proc fromHexG1Compressed*(hex: string): BlsG1Compressed =
  fromHexDigest[BlsG1Compressed](hex, Bls12381G1CompressedLen)

proc fromHexG2Compressed*(hex: string): BlsG2Compressed =
  fromHexDigest[BlsG2Compressed](hex, Bls12381G2CompressedLen)

proc fromHexPrivateKey*(hex: string): BlsPrivateKey =
  fromHexDigest[BlsPrivateKey](hex, Bls12381ScalarLen)

proc fromHexPublicKey*(hex: string): BlsPublicKey =
  fromHexDigest[BlsPublicKey](hex, Bls12381G1CompressedLen)

proc fromHexSignature*(hex: string): BlsSignature =
  fromHexDigest[BlsSignature](hex, Bls12381G2CompressedLen)

proc fromHexMessageHash*(hex: string): BlsMessageHash =
  fromHexDigest[BlsMessageHash](hex, Bls12381G2CompressedLen)

proc scalarValidate*(T: type Bls, s: BlsScalar): bool =
  bls12_381ScalarValidateRaw(cast[ptr uint8](unsafeAddr s[0]), csize_t(s.len)) == RustCryptoOk

proc randomScalar*(T: type Bls): BlsScalar =
  var output: BlsScalar
  raiseIfError(
    bls12_381ScalarRandomRaw(cast[ptr uint8](addr output[0]), csize_t(output.len)),
    "rustcrypto_bls12_381_scalar_random",
  )
  output

proc scalarAdd*(T: type Bls; lhs, rhs: BlsScalar): BlsScalar =
  var output: BlsScalar
  raiseIfError(
    bls12_381ScalarAddRaw(
      cast[ptr uint8](unsafeAddr lhs[0]),
      csize_t(lhs.len),
      cast[ptr uint8](unsafeAddr rhs[0]),
      csize_t(rhs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_scalar_add",
  )
  output

proc scalarMul*(T: type Bls; lhs, rhs: BlsScalar): BlsScalar =
  var output: BlsScalar
  raiseIfError(
    bls12_381ScalarMulRaw(
      cast[ptr uint8](unsafeAddr lhs[0]),
      csize_t(lhs.len),
      cast[ptr uint8](unsafeAddr rhs[0]),
      csize_t(rhs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_scalar_mul",
  )
  output

proc scalarInvert*(T: type Bls; value: BlsScalar): BlsScalar =
  var output: BlsScalar
  raiseIfError(
    bls12_381ScalarInvertRaw(
      cast[ptr uint8](unsafeAddr value[0]),
      csize_t(value.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_scalar_invert",
  )
  output

proc g1Generator*(T: type Bls; U: typedesc[BlsG1Compressed]): BlsG1Compressed =
  var output: BlsG1Compressed
  raiseIfError(
    bls12_381G1GeneratorRaw(
      cast[ptr uint8](addr output[0]), csize_t(output.len), BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g1_generator",
  )
  output

proc g2Generator*(T: type Bls; U: typedesc[BlsG2Compressed]): BlsG2Compressed =
  var output: BlsG2Compressed
  raiseIfError(
    bls12_381G2GeneratorRaw(
      cast[ptr uint8](addr output[0]), csize_t(output.len), BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g2_generator",
  )
  output

proc g1Add*(T: type Bls; lhs, rhs: BlsG1Compressed): BlsG1Compressed =
  var output: BlsG1Compressed
  raiseIfError(
    bls12_381G1AddRaw(
      cast[ptr uint8](unsafeAddr lhs[0]),
      csize_t(lhs.len),
      cast[ptr uint8](unsafeAddr rhs[0]),
      csize_t(rhs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g1_add",
  )
  output

proc g2Add*(T: type Bls; lhs, rhs: BlsG2Compressed): BlsG2Compressed =
  var output: BlsG2Compressed
  raiseIfError(
    bls12_381G2AddRaw(
      cast[ptr uint8](unsafeAddr lhs[0]),
      csize_t(lhs.len),
      cast[ptr uint8](unsafeAddr rhs[0]),
      csize_t(rhs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g2_add",
  )
  output

proc g1Neg*(T: type Bls; point: BlsG1Compressed): BlsG1Compressed =
  var output: BlsG1Compressed
  raiseIfError(
    bls12_381G1NegRaw(
      cast[ptr uint8](unsafeAddr point[0]),
      csize_t(point.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g1_neg",
  )
  output

proc g2Neg*(T: type Bls; point: BlsG2Compressed): BlsG2Compressed =
  var output: BlsG2Compressed
  raiseIfError(
    bls12_381G2NegRaw(
      cast[ptr uint8](unsafeAddr point[0]),
      csize_t(point.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g2_neg",
  )
  output

proc g1Mul*(T: type Bls; point: BlsG1Compressed; scalar: BlsScalar): BlsG1Compressed =
  var output: BlsG1Compressed
  raiseIfError(
    bls12_381G1MulRaw(
      cast[ptr uint8](unsafeAddr point[0]),
      csize_t(point.len),
      cast[ptr uint8](unsafeAddr scalar[0]),
      csize_t(scalar.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g1_mul",
  )
  output

proc g2Mul*(T: type Bls; point: BlsG2Compressed; scalar: BlsScalar): BlsG2Compressed =
  var output: BlsG2Compressed
  raiseIfError(
    bls12_381G2MulRaw(
      cast[ptr uint8](unsafeAddr point[0]),
      csize_t(point.len),
      cast[ptr uint8](unsafeAddr scalar[0]),
      csize_t(scalar.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
      BlsPointFormatCompressed,
    ),
    "rustcrypto_bls12_381_g2_mul",
  )
  output

proc pairingEq*(
    T: type Bls; g1Lhs: BlsG1Compressed; g2Lhs: BlsG2Compressed; g1Rhs: BlsG1Compressed; g2Rhs: BlsG2Compressed,
): bool =
  boolFromPairingEq(
    bls12_381PairingEqRaw(
      cast[ptr uint8](unsafeAddr g1Lhs[0]),
      csize_t(g1Lhs.len),
      cast[ptr uint8](unsafeAddr g2Lhs[0]),
      csize_t(g2Lhs.len),
      cast[ptr uint8](unsafeAddr g1Rhs[0]),
      csize_t(g1Rhs.len),
      cast[ptr uint8](unsafeAddr g2Rhs[0]),
      csize_t(g2Rhs.len),
    ),
    "rustcrypto_bls12_381_pairing_eq",
  )

proc pairingProductIsIdentity*(
    T: type Bls; g1Points: openArray[BlsG1Compressed]; g2Points: openArray[BlsG2Compressed],
): bool =
  if g1Points.len != g2Points.len or g1Points.len == 0:
    raise newException(ValueError, "pairingProductIsIdentity requires equal non-empty G1/G2 arrays")
  var g1flat = newSeq[byte](g1Points.len * Bls12381G1CompressedLen)
  var g2flat = newSeq[byte](g2Points.len * Bls12381G2CompressedLen)
  for i in 0 ..< g1Points.len:
    copyMem(addr g1flat[i * Bls12381G1CompressedLen], unsafeAddr g1Points[i][0], Bls12381G1CompressedLen)
    copyMem(addr g2flat[i * Bls12381G2CompressedLen], unsafeAddr g2Points[i][0], Bls12381G2CompressedLen)
  boolFromPairingProductIdentity(
    bls12_381PairingProductIsIdentityRaw(
      cast[ptr uint8](addr g1flat[0]),
      csize_t(g1flat.len),
      cast[ptr uint8](addr g2flat[0]),
      csize_t(g2flat.len),
      csize_t(g1Points.len),
    ),
    "rustcrypto_bls12_381_pairing_product_is_identity",
  )

proc privateKeyFromSeed*(T: type Bls; seed: openArray[byte]): BlsPrivateKey =
  if seed.len < 32:
    raise newException(ValueError, "Bls.privateKeyFromSeed requires at least 32 bytes")
  var output: BlsPrivateKey
  raiseIfError(
    bls12_381SignaturePrivateKeyFromSeedRaw(
      bytesPtr(seed), csize_t(seed.len), cast[ptr uint8](addr output[0]), csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_private_key_from_seed",
  )
  output

proc generatePrivateKey*(T: type Bls): BlsPrivateKey =
  var output: BlsPrivateKey
  raiseIfError(
    bls12_381SignaturePrivateKeyGenerateRaw(cast[ptr uint8](addr output[0]), csize_t(output.len)),
    "rustcrypto_bls12_381_signature_private_key_generate",
  )
  output

proc privateKeyFromDecimalString*(T: type Bls; value: string): BlsPrivateKey =
  var output: BlsPrivateKey
  raiseIfError(
    bls12_381SignaturePrivateKeyFromDecimalStringRaw(
      bytesPtr(value), csize_t(value.len), cast[ptr uint8](addr output[0]), csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_private_key_from_decimal_string",
  )
  output

proc publicKey*(T: type Bls; privateKey: BlsPrivateKey): BlsPublicKey =
  var output: BlsPublicKey
  raiseIfError(
    bls12_381SignaturePublicKeyRaw(
      cast[ptr uint8](unsafeAddr privateKey[0]),
      csize_t(privateKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_public_key",
  )
  output

proc hash*(T: type Bls; message: openArray[byte]): BlsMessageHash =
  var output: BlsMessageHash
  raiseIfError(
    bls12_381SignatureHashRaw(
      bytesPtr(message), csize_t(message.len), cast[ptr uint8](addr output[0]), csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_hash",
  )
  output

proc sign*(T: type Bls; message: openArray[byte]; privateKey: BlsPrivateKey): BlsSignature =
  var output: BlsSignature
  raiseIfError(
    bls12_381SignatureSignRaw(
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr privateKey[0]),
      csize_t(privateKey.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_sign",
  )
  output

proc aggregate*(T: type Bls; signatures: openArray[BlsSignature]): BlsSignature =
  if signatures.len == 0:
    raise newException(ValueError, "Bls.aggregate requires a non-empty signature list")
  var slab = newSeq[byte](signatures.len * Bls12381G2CompressedLen)
  for i in 0 ..< signatures.len:
    copyMem(addr slab[i * Bls12381G2CompressedLen], unsafeAddr signatures[i][0], Bls12381G2CompressedLen)
  var output: BlsSignature
  raiseIfError(
    bls12_381SignatureAggregateRaw(
      cast[ptr uint8](addr slab[0]),
      csize_t(slab.len),
      csize_t(signatures.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_aggregate",
  )
  output

proc verify*(
    T: type Bls; signature: BlsSignature; hashes: openArray[BlsMessageHash]; publicKeys: openArray[BlsPublicKey],
): bool =
  if hashes.len != publicKeys.len:
    raise newException(ValueError, "Bls.verify requires hashes and publicKeys of the same length")
  var hflat = newSeq[byte](hashes.len * Bls12381G2CompressedLen)
  var pkflat = newSeq[byte](publicKeys.len * Bls12381G1CompressedLen)
  for i in 0 ..< hashes.len:
    copyMem(addr hflat[i * Bls12381G2CompressedLen], unsafeAddr hashes[i][0], Bls12381G2CompressedLen)
    copyMem(addr pkflat[i * Bls12381G1CompressedLen], unsafeAddr publicKeys[i][0], Bls12381G1CompressedLen)
  boolFromVerify(
    bls12_381SignatureVerifyRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      cast[ptr uint8](addr hflat[0]),
      csize_t(hflat.len),
      cast[ptr uint8](addr pkflat[0]),
      csize_t(pkflat.len),
      csize_t(hashes.len),
    ),
    "rustcrypto_bls12_381_signature_verify",
  )

proc verifyMessages*(
    T: type Bls; signature: BlsSignature; messages: openArray[seq[byte]]; publicKeys: openArray[BlsPublicKey],
): bool =
  if messages.len != publicKeys.len:
    raise newException(ValueError, "Bls.verifyMessages requires messages and publicKeys of the same length")
  var msgPtrs = newSeq[ptr uint8](messages.len)
  var lens = newSeq[csize_t](messages.len)
  for i in 0 ..< messages.len:
    msgPtrs[i] = bytesPtr(messages[i])
    lens[i] = csize_t(messages[i].len)
  var pkflat = newSeq[byte](publicKeys.len * Bls12381G1CompressedLen)
  for i in 0 ..< publicKeys.len:
    copyMem(addr pkflat[i * Bls12381G1CompressedLen], unsafeAddr publicKeys[i][0], Bls12381G1CompressedLen)
  boolFromVerify(
    bls12_381SignatureVerifyMessagesRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      cast[ptr ptr uint8](unsafeAddr msgPtrs[0]),
      cast[ptr csize_t](unsafeAddr lens[0]),
      csize_t(messages.len),
      cast[ptr uint8](addr pkflat[0]),
      csize_t(pkflat.len),
    ),
    "rustcrypto_bls12_381_signature_verify_messages",
  )

proc verify*(T: type Bls; message: openArray[byte]; publicKey: BlsPublicKey; signature: BlsSignature): bool =
  verifyMessages(T, signature, @[@message], @[publicKey])

proc hashAugG1*(
    T: type Bls; publicKey: BlsAugG1PublicKey; message: openArray[byte],
): BlsAugG1MessageHash =
  ## Hash `publicKey || message` to G1 with `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_`.
  ## This is not the same as `Bls.hash`, which hashes only the message to G2 (minimal-pk-size).
  var output: BlsAugG1MessageHash
  raiseIfError(
    bls12_381SignatureHashG1AugRaw(
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_bls12_381_signature_hash_g1_aug",
  )
  output

proc verifyAugG1*(
    T: type Bls; signature: BlsAugG1Signature; messageHash: BlsAugG1MessageHash; publicKey: BlsAugG1PublicKey,
): bool =
  boolFromVerify(
    bls12_381SignatureVerifyG1AugHashRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      cast[ptr uint8](unsafeAddr messageHash[0]),
      csize_t(messageHash.len),
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
    ),
    "rustcrypto_bls12_381_signature_verify_g1_aug_hash",
  )

proc verifyAugG1Message*(
    T: type Bls; signature: BlsAugG1Signature; message: openArray[byte]; publicKey: BlsAugG1PublicKey,
): bool =
  boolFromVerify(
    bls12_381SignatureVerifyG1AugMessageRaw(
      cast[ptr uint8](unsafeAddr signature[0]),
      csize_t(signature.len),
      bytesPtr(message),
      csize_t(message.len),
      cast[ptr uint8](unsafeAddr publicKey[0]),
      csize_t(publicKey.len),
    ),
    "rustcrypto_bls12_381_signature_verify_g1_aug_message",
  )
