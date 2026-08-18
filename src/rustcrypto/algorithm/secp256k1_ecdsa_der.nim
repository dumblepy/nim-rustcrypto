import ./ecdsa_common
import ./ffi
import ./common

type
  Secp256k1DerSignature* = ecdsa_common.Secp256k1DerSignature

proc `$`*(value: Secp256k1DerSignature): string =
  bytesToHexString(value)

proc secp256k1EcdsaSignatureToDer*(
    signature: Secp256k1Signature,
  ): Secp256k1DerSignature =
  var output = newSeq[byte](Secp256k1SignatureDerMaxLen)
  var writtenLen: csize_t
  let status = secp256k1EcdsaSignatureToDerRaw(
    bytesPtr(signature),
    csize_t(signature.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseSignatureDerError(status, "rustcrypto_secp256k1_ecdsa_signature_to_der")
  output.setLen(int(writtenLen))
  output

proc secp256k1EcdsaSignatureFromDer*(
    signatureDer: openArray[byte],
  ): Secp256k1Signature =
  var output: Secp256k1Signature
  let status = secp256k1EcdsaSignatureFromDerRaw(
    bytesPtr(signatureDer),
    csize_t(signatureDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignatureDerError(status, "rustcrypto_secp256k1_ecdsa_signature_from_der")
  output
