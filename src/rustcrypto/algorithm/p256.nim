import ./ecdsa_common
import ./ffi
import ./common

type
  P256* = object
  P256SecretKey* = array[P256SecretKeyLen, byte]
  P256CompressedPublicKey* = array[P256PublicKeyCompressedLen, byte]
  P256UncompressedPublicKey* = array[P256PublicKeyUncompressedLen, byte]
  P256Signature* = array[P256SignatureLen, byte]
  P256MessageDigest* = array[P256MessageDigestLen, byte]
  P256PrivateKeyPkcs8Der* = seq[byte]
  P256PublicKeySpkiDer* = seq[byte]

proc `$`*(value: P256CompressedPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: P256UncompressedPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: P256Signature): string =
  bytesToHexString(value)

proc `$`*(value: P256PublicKeySpkiDer): string =
  bytesToHexString(value)

proc randomSecretKey*(): P256SecretKey
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

proc generateSecretKey*(T: type P256): P256SecretKey =
  randomSecretKey()

proc publicKeyCompressed*(T: type P256, secretKey: P256SecretKey): P256CompressedPublicKey =
  var output: P256CompressedPublicKey
  let status = p256PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P256PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_from_secret_key")
  output

proc publicKeyUncompressed*(T: type P256, secretKey: P256SecretKey): P256UncompressedPublicKey =
  var output: P256UncompressedPublicKey
  let status = p256PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    P256PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_from_secret_key")
  output

proc randomSecretKey*(): P256SecretKey =
  while true:
    result = urandomBytes[P256SecretKeyLen]()
    var publicKey: P256CompressedPublicKey
    let status = p256PublicKeyFromSecretKeyRaw(
      bytesPtr(result),
      csize_t(result.len),
      cast[ptr uint8](addr publicKey[0]),
      csize_t(publicKey.len),
      P256PublicKeyFormatCompressed,
    )
    case status
    of RustCryptoOk:
      return result
    of RustCryptoErrInvalidSecretKey:
      discard
    of RustCryptoErrPanic:
      raise newException(ValueError, "rustcrypto_p256_random_secret_key failed: panic")
    else:
      raise newException(
        ValueError,
        "rustcrypto_p256_random_secret_key failed: unexpected status " & $status,
      )

proc fromHexSecretKey*(hex: string): P256SecretKey =
  fromHexDigest[P256SecretKey](hex, P256SecretKeyLen)

proc fromHexPublicKeyCompressed*(hex: string): P256CompressedPublicKey =
  fromHexDigest[P256CompressedPublicKey](hex, P256PublicKeyCompressedLen)

proc fromHexPublicKeyUncompressed*(hex: string): P256UncompressedPublicKey =
  fromHexDigest[P256UncompressedPublicKey](hex, P256PublicKeyUncompressedLen)

proc fromHexSignature*(hex: string): P256Signature =
  fromHexDigest[P256Signature](hex, P256SignatureLen)

proc fromHexMessageDigest*(hex: string): P256MessageDigest =
  fromHexDigest[P256MessageDigest](hex, P256MessageDigestLen)

proc basePointSecretKey*(): P256SecretKey =
  result = default(P256SecretKey)
  result[P256SecretKeyLen - 1] = 1

proc fixedArrayFromBytes[T](data: openArray[byte]): T =
  doAssert data.len == result.len
  for i in 0 ..< data.len:
    result[i] = data[i]

proc privateKeyToPkcs8Der*(
    T: type P256,
    privateKey: P256SecretKey,
  ): P256PrivateKeyPkcs8Der =
  var output = newSeq[byte](P256PrivateKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p256PrivateKeyToPkcs8DerRaw(
    cptr(privateKey),
    csize_t(privateKey.len),
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p256_private_key_to_pkcs8_der")
  output.setLen(int(writtenLen))
  output

proc privateKeyFromPkcs8Der*(
    T: type P256,
    privateKeyDer: openArray[byte],
  ): P256SecretKey =
  var output: P256SecretKey
  let status = p256PrivateKeyFromPkcs8DerRaw(
    cptr(privateKeyDer),
    csize_t(privateKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_p256_private_key_from_pkcs8_der")
  output

proc publicKeyToSpkiDer*(
    T: type P256,
    publicKey: P256CompressedPublicKey,
  ): P256PublicKeySpkiDer =
  var output = newSeq[byte](P256PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p256PublicKeyToSpkiDerRaw(
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatCompressed,
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc publicKeyToSpkiDer*(
    T: type P256,
    publicKey: P256UncompressedPublicKey,
  ): P256PublicKeySpkiDer =
  var output = newSeq[byte](P256PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = p256PublicKeyToSpkiDerRaw(
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatUncompressed,
    cptr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_p256_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc publicKeyFromSpkiDer*(
    T: type P256,
    publicKeyDer: openArray[byte],
    _: typedesc[P256CompressedPublicKey],
  ): P256CompressedPublicKey =
  fixedArrayFromBytes[P256CompressedPublicKey](
    block:
      let outputLen = P256PublicKeyCompressedLen
      var output = newSeq[byte](outputLen)
      let status = p256PublicKeyFromSpkiDerRaw(
        cptr(publicKeyDer),
        csize_t(publicKeyDer.len),
        cptr(output),
        csize_t(output.len),
        P256PublicKeyFormatCompressed,
      )
      raiseIfError(status, "rustcrypto_p256_public_key_from_spki_der")
      output
  )

proc publicKeyFromSpkiDer*(
    T: type P256,
    publicKeyDer: openArray[byte],
    _: typedesc[P256UncompressedPublicKey],
  ): P256UncompressedPublicKey =
  fixedArrayFromBytes[P256UncompressedPublicKey](
    block:
      let outputLen = P256PublicKeyUncompressedLen
      var output = newSeq[byte](outputLen)
      let status = p256PublicKeyFromSpkiDerRaw(
        cptr(publicKeyDer),
        csize_t(publicKeyDer.len),
        cptr(output),
        csize_t(output.len),
        P256PublicKeyFormatUncompressed,
      )
      raiseIfError(status, "rustcrypto_p256_public_key_from_spki_der")
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

proc sign*(T: type P256, message: string, secretKey: P256SecretKey): P256Signature =
  var output: P256Signature
  let status = p256EcdsaSignSha256Raw(
    cptr(message),
    csize_t(message.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p256_ecdsa_sign_sha256")
  output

proc sign*(T: type P256, messageDigest: P256MessageDigest, secretKey: P256SecretKey): P256Signature =
  var output: P256Signature
  let status = p256EcdsaSignPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_p256_ecdsa_sign_prehash")
  output

proc verify*(
    T: type P256,
    message: string,
    publicKey: P256CompressedPublicKey,
    signature: P256Signature,
  ): bool =
  let status = p256EcdsaVerifySha256Raw(
    cptr(message),
    csize_t(message.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_sha256")

proc verify*(
    T: type P256,
    message: string,
    publicKey: P256UncompressedPublicKey,
    signature: P256Signature,
  ): bool =
  let status = p256EcdsaVerifySha256Raw(
    cptr(message),
    csize_t(message.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_sha256")

proc verify*(
    T: type P256,
    messageDigest: P256MessageDigest,
    publicKey: P256CompressedPublicKey,
    signature: P256Signature,
  ): bool =
  let status = p256EcdsaVerifyPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_prehash")

proc verify*(
    T: type P256,
    messageDigest: P256MessageDigest,
    publicKey: P256UncompressedPublicKey,
    signature: P256Signature,
  ): bool =
  let status = p256EcdsaVerifyPrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    P256PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_p256_ecdsa_verify_prehash")
