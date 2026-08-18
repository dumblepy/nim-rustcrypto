import ./ffi
import ./common

type
  PasswordHashString* = string

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
  of RustCryptoErrInvalidPasswordHashFormat:
    raise newException(ValueError, operation & " failed: invalid password hash format")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc passwordHashValidate*(phc: string): bool =
  let status = passwordHashValidateRaw(
    bytesPtr(phc),
    csize_t(phc.len),
  )

  case status
  of RustCryptoOk:
    true
  of RustCryptoErrInvalidPasswordHashFormat:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_password_hash_validate failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_password_hash_validate failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_password_hash_validate failed: unexpected status " & $status,
    )

proc passwordHashCanonicalize*(phc: string): PasswordHashString =
  var output = newString(phc.len)
  var writtenLen: csize_t
  let status = passwordHashCanonicalizeRaw(
    bytesPtr(phc),
    csize_t(phc.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_password_hash_canonicalize")
  output.setLen(int(writtenLen))
  output
