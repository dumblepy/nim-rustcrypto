import ./ffi
import ./common

type
  Secp256k1MessageDigest* = array[Secp256k1MessageDigestLen, byte]
  Secp256k1Signature* = array[Secp256k1SignatureLen, byte]
  Secp256k1DerSignature* = seq[byte]

template secp256k1EcdsaSignMessage*(
    rawProc,
    message,
    secretKey,
    operation: untyped,
  ): untyped =
  var output: Secp256k1Signature
  let status = rawProc(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(secretKey),
    csize_t(secretKey.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseSignError(status, operation)
  output

template secp256k1EcdsaVerifyMessage*(
    rawProc,
    message,
    publicKey,
    signature,
    publicKeyFormat,
    operation: untyped,
  ): untyped =
  let status = rawProc(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    publicKeyFormat,
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, operation)

proc raiseSignError*(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, operation & " failed: invalid message digest")
  of RustCryptoErrInvalidSecretKey:
    raise newException(ValueError, operation & " failed: invalid secret key")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc verifyStatus*(status: cint; operation: string): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidMessageDigest:
    raise newException(ValueError, operation & " failed: invalid message digest")
  of RustCryptoErrInvalidPublicKeyFormat:
    raise newException(ValueError, operation & " failed: invalid public key format")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc raiseSignatureDerError*(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)
