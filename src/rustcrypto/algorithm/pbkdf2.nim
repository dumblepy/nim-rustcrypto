import ./ffi
import ./common

type
  Pbkdf2HmacSha256Okm* = seq[byte]

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
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc pbkdf2HmacSha256*(
    password, salt: string,
    iterations: int,
    okmLen: int,
  ): Pbkdf2HmacSha256Okm =
  if iterations <= 0:
    raise newException(ValueError, "pbkdf2HmacSha256 failed: invalid parameter")
  if okmLen < 0:
    raise newException(ValueError, "pbkdf2HmacSha256 failed: negative output length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = pbkdf2HmacSha256Raw(
    bytesPtr(password),
    csize_t(password.len),
    bytesPtr(salt),
    csize_t(salt.len),
    cuint(iterations),
    bytesPtr(result),
    csize_t(result.len),
    csize_t(okmLen),
  )
  raiseIfError(status, "rustcrypto_pbkdf2_hmac_sha256")
