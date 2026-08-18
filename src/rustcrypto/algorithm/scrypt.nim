import ./ffi
import ./common

type
  ScryptOkm* = seq[byte]

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
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc scrypt*(
    password, salt: string,
    n: int,
    r: int,
    p: int,
    okmLen: int,
  ): ScryptOkm =
  if n < 2:
    raise newException(ValueError, "scrypt failed: invalid parameter")
  if (n and (n - 1)) != 0:
    raise newException(ValueError, "scrypt failed: invalid parameter")
  if r <= 0 or p <= 0:
    raise newException(ValueError, "scrypt failed: invalid parameter")
  if okmLen < 0:
    raise newException(ValueError, "scrypt failed: invalid length")
  if okmLen > ScryptMaxOkmLen:
    raise newException(ValueError, "scrypt failed: invalid length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = scryptRaw(
    bytesPtr(password),
    csize_t(password.len),
    bytesPtr(salt),
    csize_t(salt.len),
    csize_t(n),
    csize_t(r),
    csize_t(p),
    bytesPtr(result),
    csize_t(result.len),
    csize_t(okmLen),
  )
  raiseIfError(status, "rustcrypto_scrypt")
