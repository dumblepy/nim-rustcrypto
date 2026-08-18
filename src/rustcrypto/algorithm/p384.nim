import ./ecdsa_common
import ./ffi
import ./common

type
  P384* = object
  P384SecretKey* = array[P384SecretKeyLen, byte]
  P384CompressedPublicKey* = array[P384PublicKeyCompressedLen, byte]
  P384UncompressedPublicKey* = array[P384PublicKeyUncompressedLen, byte]
  P384Signature* = array[P384SignatureLen, byte]
  P384MessageDigest* = array[P384MessageDigestLen, byte]
  P384PrivateKeyPkcs8Der* = seq[byte]
  P384PublicKeySpkiDer* = seq[byte]

proc `$`*(value: P384CompressedPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: P384UncompressedPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: P384Signature): string =
  bytesToHexString(value)

proc `$`*(value: P384PublicKeySpkiDer): string =
  bytesToHexString(value)

proc randomSecretKey*(): P384SecretKey
proc raiseIfError(status: cint; operation: string)

proc cptr(data: string): ptr uint8 =
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc cptr(data: openArray[byte]): ptr uint8 =
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc generateSecretKey*(T: type P384): P384SecretKey =
  randomSecretKey()

proc publicKeyCompressed*(T: type P384, secretKey: P384SecretKey): P384CompressedPublicKey =
  var output: P384CompressedPublicKey
  let status = p384PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P384PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_from_secret_key")
  output

proc publicKeyUncompressed*(T: type P384, secretKey: P384SecretKey): P384UncompressedPublicKey =
  var output: P384UncompressedPublicKey
  let status = p384PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P384PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_from_secret_key")
  output

proc randomSecretKey*(): P384SecretKey =
  while true:
    result = urandomBytes[P384SecretKeyLen]()
    var publicKey: P384CompressedPublicKey
    let status = p384PublicKeyFromSecretKeyRaw(
      bytesPtr(result),
      csize_t(result.len),
      cast[ptr uint8](addr publicKey[0]),
      csize_t(publicKey.len),
      P384PublicKeyFormatCompressed,
    )
    case status
    of RustCryptoOk:
      return result
    of RustCryptoErrInvalidSecretKey:
      discard
    of RustCryptoErrPanic:
      raise newException(ValueError, "rustcrypto_p384_random_secret_key failed: panic")
    else:
      raise newException(
        ValueError,
        "rustcrypto_p384_random_secret_key failed: unexpected status " & $status,
      )

proc fromHexSecretKey*(hex: string): P384SecretKey =
  fromHexDigest[P384SecretKey](hex, P384SecretKeyLen)

proc fromHexPublicKeyCompressed*(hex: string): P384CompressedPublicKey =
  fromHexDigest[P384CompressedPublicKey](hex, P384PublicKeyCompressedLen)

proc fromHexPublicKeyUncompressed*(hex: string): P384UncompressedPublicKey =
  fromHexDigest[P384UncompressedPublicKey](hex, P384PublicKeyUncompressedLen)

proc fromHexSignature*(hex: string): P384Signature =
  fromHexDigest[P384Signature](hex, P384SignatureLen)

proc fromHexMessageDigest*(hex: string): P384MessageDigest =
  fromHexDigest[P384MessageDigest](hex, P384MessageDigestLen)

proc basePointSecretKey*(): P384SecretKey =
  result = default(P384SecretKey)
  result[P384SecretKeyLen - 1] = 1

proc fixedArrayFromBytes[T](data: openArray[byte]): T =
  doAssert data.len == result.len
  for i in 0 ..< data.len:
    result[i] = data[i]

proc privateKeyToPkcs8Der*(
    T: type P384,
    privateKey: P384SecretKey,
  ): P384PrivateKeyPkcs8Der =
  var output = newSeq[byte](P384PrivateKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p384PrivateKeyToPkcs8DerRaw(
    cptr(privateKey),
    csize_t(privateKey.len),
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p384_private_key_to_pkcs8_der")
  output.setLen(int(writtenLen))
  output

proc privateKeyFromPkcs8Der*(
    T: type P384,
    privateKeyDer: openArray[byte],
  ): P384SecretKey =
  var output: P384SecretKey
  let status = p384PrivateKeyFromPkcs8DerRaw(
    cptr(privateKeyDer),
    csize_t(privateKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_p384_private_key_from_pkcs8_der")
  output

proc publicKeyToSpkiDer*(
    T: type P384,
    publicKey: P384CompressedPublicKey,
  ): P384PublicKeySpkiDer =
  var output = newSeq[byte](P384PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p384PublicKeyToSpkiDerRaw(
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatCompressed,
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc publicKeyToSpkiDer*(
    T: type P384,
    publicKey: P384UncompressedPublicKey,
  ): P384PublicKeySpkiDer =
  var output = newSeq[byte](P384PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p384PublicKeyToSpkiDerRaw(
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatUncompressed,
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p384_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc publicKeyFromSpkiDer*(
    T: type P384,
    publicKeyDer: openArray[byte],
    _: typedesc[P384CompressedPublicKey],
  ): P384CompressedPublicKey =
  fixedArrayFromBytes[P384CompressedPublicKey](
    block:
      var output = newSeq[byte](P384PublicKeyCompressedLen)
      let status = p384PublicKeyFromSpkiDerRaw(
        cptr(publicKeyDer),
        csize_t(publicKeyDer.len),
        cptr(output),
        csize_t(output.len),
        P384PublicKeyFormatCompressed,
      )
      raiseIfError(status, "rustcrypto_p384_public_key_from_spki_der")
      output
  )

proc publicKeyFromSpkiDer*(
    T: type P384,
    publicKeyDer: openArray[byte],
    _: typedesc[P384UncompressedPublicKey],
  ): P384UncompressedPublicKey =
  fixedArrayFromBytes[P384UncompressedPublicKey](
    block:
      var output = newSeq[byte](P384PublicKeyUncompressedLen)
      let status = p384PublicKeyFromSpkiDerRaw(
        cptr(publicKeyDer),
        csize_t(publicKeyDer.len),
        cptr(output),
        csize_t(output.len),
        P384PublicKeyFormatUncompressed,
      )
      raiseIfError(status, "rustcrypto_p384_public_key_from_spki_der")
      output
  )

proc raiseIfError(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidSecretKey:
    raise newException(ValueError, operation & " failed: invalid secret key")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, operation & " failed: invalid public key format")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, operation & " failed: invalid message digest")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc sign*(T: type P384, message: string, secretKey: P384SecretKey): P384Signature =
  var output: P384Signature
  let status = p384EcdsaSignSha384Raw(
    cptr(message),
    csize_t(message.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p384_ecdsa_sign_sha384")
  output

proc sign*(T: type P384, messageDigest: P384MessageDigest, secretKey: P384SecretKey): P384Signature =
  var output: P384Signature
  let status = p384EcdsaSignPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p384_ecdsa_sign_prehash")
  output

proc verify*(
    T: type P384,
    message: string,
    publicKey: P384CompressedPublicKey,
    signature: P384Signature,
  ): bool =
  let status = p384EcdsaVerifySha384Raw(
    cptr(message),
    csize_t(message.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_sha384")

proc verify*(
    T: type P384,
    message: string,
    publicKey: P384UncompressedPublicKey,
    signature: P384Signature,
  ): bool =
  let status = p384EcdsaVerifySha384Raw(
    cptr(message),
    csize_t(message.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_sha384")

proc verify*(
    T: type P384,
    messageDigest: P384MessageDigest,
    publicKey: P384CompressedPublicKey,
    signature: P384Signature,
  ): bool =
  let status = p384EcdsaVerifyPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_prehash")

proc verify*(
    T: type P384,
    messageDigest: P384MessageDigest,
    publicKey: P384UncompressedPublicKey,
    signature: P384Signature,
  ): bool =
  let status = p384EcdsaVerifyPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P384PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p384_ecdsa_verify_prehash")
