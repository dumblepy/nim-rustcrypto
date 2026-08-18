import ./ecdsa_common
import ./ffi
import ./common

type
  Secp256k1* = object
  Secp256k1SecretKey* = array[Secp256k1SecretKeyLen, byte]
  Secp256k1CompressedPublicKey* = array[Secp256k1PublicKeyCompressedLen, byte]
  Secp256k1UncompressedPublicKey* = array[Secp256k1PublicKeyUncompressedLen, byte]
  Secp256k1MessageDigest* = ecdsa_common.Secp256k1MessageDigest
  Secp256k1Signature* = ecdsa_common.Secp256k1Signature
  Secp256k1RecoverableSignature* = array[Secp256k1RecoverableSignatureLen, byte]
  Secp256k1DerSignature* = ecdsa_common.Secp256k1DerSignature

proc `$`*(value: Secp256k1CompressedPublicKey): string =
  bytesToHexString(value)

proc `$`*(value: Secp256k1Signature): string =
  bytesToHexString(value)

proc `$`*(value: Secp256k1UncompressedPublicKey |
    Secp256k1RecoverableSignature): string =
  bytesToHexString(value)

proc randomSecretKey*(): Secp256k1SecretKey
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

proc sha256Digest(message: string): Secp256k1MessageDigest =
  let status = sha256Raw(
    cptr(message),
    csize_t(message.len),
    cast[ptr uint8](addr result[0]),
    csize_t(result.len),
  )
  raiseRustCryptoStatus(status, "rustcrypto_sha256")

proc randomSecretKey*(): Secp256k1SecretKey =
  while true:
    result = urandomBytes[Secp256k1SecretKeyLen]()
    var publicKey: Secp256k1CompressedPublicKey
    let status = secp256k1PublicKeyFromSecretKeyRaw(
      bytesPtr(result),
      csize_t(result.len),
      cast[ptr uint8](addr publicKey[0]),
      csize_t(publicKey.len),
      Secp256k1PublicKeyFormatCompressed,
    )
    case status
    of RustCryptoOk:
      return result
    of RustCryptoErrInvalidSecretKey:
      discard
    of RustCryptoErrPanic:
      raise newException(ValueError, "rustcrypto_secp256k1_random_secret_key failed: panic")
    else:
      raise newException(
        ValueError,
        "rustcrypto_secp256k1_random_secret_key failed: unexpected status " & $status,
      )

proc generateSecretKey*(T: type Secp256k1): Secp256k1SecretKey =
  randomSecretKey()

proc publicKeyCompressed*(
    T: type Secp256k1,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1CompressedPublicKey =
  var output: Secp256k1CompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatCompressed,
  )
  raiseIfError(status, "rustcrypto_secp256k1_public_key_from_secret_key")
  output

proc publicKeyUncompressed*(
    T: type Secp256k1,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1UncompressedPublicKey =
  var output: Secp256k1UncompressedPublicKey
  let status = secp256k1PublicKeyFromSecretKeyRaw(
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
    Secp256k1PublicKeyFormatUncompressed,
  )
  raiseIfError(status, "rustcrypto_secp256k1_public_key_from_secret_key")
  output

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
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(
      ValueError,
      operation & " failed: unexpected status " & $status,
    )

proc sign*(
    T: type Secp256k1,
    message: string,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1Signature =
  var output: Secp256k1Signature
  let status = secp256k1EcdsaSignRaw(
    cptr(sha256Digest(message)),
    csize_t(Secp256k1MessageDigestLen),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_ecdsa_sign_prehash")
  output

proc sign*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1Signature =
  var output: Secp256k1Signature
  let status = secp256k1EcdsaSignRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_ecdsa_sign_prehash")
  output

proc verify*(
    T: type Secp256k1,
    message: string,
    publicKey: Secp256k1CompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cptr(sha256Digest(message)),
    csize_t(Secp256k1MessageDigestLen),
    cptr(publicKey),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_ecdsa_verify_prehash")

proc verify*(
    T: type Secp256k1,
    message: string,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cptr(sha256Digest(message)),
    csize_t(Secp256k1MessageDigestLen),
    cptr(publicKey),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_ecdsa_verify_prehash")

proc verify*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1CompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatCompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_ecdsa_verify_prehash")

proc verify*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: Secp256k1Signature,
  ): bool =
  let status = secp256k1EcdsaVerifyRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(publicKey),
    csize_t(publicKey.len),
    Secp256k1PublicKeyFormatUncompressed,
    cptr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, "rustcrypto_secp256k1_ecdsa_verify_prehash")


proc verifyRecoverable*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1CompressedPublicKey,
    signature: Secp256k1RecoverableSignature,
  ): bool =
  var recovered: Secp256k1CompressedPublicKey
  let status = secp256k1EcdsaRecoverPublicKeyRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(signature),
    csize_t(signature.len),
    cast[ptr uint8](addr recovered[0]),
    csize_t(recovered.len),
    Secp256k1PublicKeyFormatCompressed,
  )
  case status
  of RustCryptoOk:
    recovered == publicKey
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullOutput,
     RustCryptoErrOutputTooShort,
     RustCryptoErrNullInputWithData,
     RustCryptoErrInvalidMessageDigest,
     RustCryptoErrInvalidSignature,
     RustCryptoErrInvalidPublicKeyFormat,
     RustCryptoErrPanic:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_recover_public_key failed: " & $status,
    )
  else:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_recover_public_key failed: unexpected status " & $status,
    )

proc verifyRecoverable*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    publicKey: Secp256k1UncompressedPublicKey,
    signature: Secp256k1RecoverableSignature,
  ): bool =
  var recovered: Secp256k1UncompressedPublicKey
  let status = secp256k1EcdsaRecoverPublicKeyRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(signature),
    csize_t(signature.len),
    cast[ptr uint8](addr recovered[0]),
    csize_t(recovered.len),
    Secp256k1PublicKeyFormatUncompressed,
  )
  case status
  of RustCryptoOk:
    recovered == publicKey
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullOutput,
     RustCryptoErrOutputTooShort,
     RustCryptoErrNullInputWithData,
     RustCryptoErrInvalidMessageDigest,
     RustCryptoErrInvalidSignature,
     RustCryptoErrInvalidPublicKeyFormat,
     RustCryptoErrPanic:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_recover_public_key failed: " & $status,
    )
  else:
    raise newException(
      ValueError,
      "rustcrypto_secp256k1_ecdsa_recover_public_key failed: unexpected status " & $status,
    )

proc signRecoverable*(
    T: type Secp256k1,
    messageDigest: Secp256k1MessageDigest,
    secretKey: Secp256k1SecretKey,
  ): Secp256k1RecoverableSignature =
  var output: Secp256k1RecoverableSignature
  let status = secp256k1EcdsaSignRecoverablePrehashRaw(
    cptr(messageDigest),
    csize_t(messageDigest.len),
    cptr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, "rustcrypto_secp256k1_ecdsa_sign_recoverable_prehash")
  output
