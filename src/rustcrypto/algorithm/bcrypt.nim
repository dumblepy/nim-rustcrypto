import std/strutils

import ./ffi
import ./common

type
  Bcrypt* = object
  BcryptHashString* = string

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
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrVerificationFailed:
    raise newException(ValueError, operation & " failed: verification failed")
  of RustCryptoErrRandomFailed:
    raise newException(ValueError, operation & " failed: random failed")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc validateBcryptCost(cost: int; operation: string) =
  if cost < BcryptMinCost or cost > BcryptMaxCost:
    raise newException(ValueError, operation & " failed: invalid parameter")

proc validateBcryptPassword(password: string; operation: string) =
  if password.len > BcryptMaxPasswordLen:
    raise newException(ValueError, operation & " failed: invalid length")

proc verifyStatus(status: cint): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrInvalidPasswordHashFormat:
    raise newException(
      ValueError,
      "rustcrypto_bcrypt_verify_password failed: invalid password hash format",
    )
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, "rustcrypto_bcrypt_verify_password failed: invalid length")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_bcrypt_verify_password failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_bcrypt_verify_password failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_bcrypt_verify_password failed: unexpected status " & $status,
    )

proc hashPassword*(
    _: type Bcrypt,
    password: string,
    cost: int = BcryptDefaultCost,
  ): BcryptHashString =
  validateBcryptCost(cost, "Bcrypt.hashPassword")
  validateBcryptPassword(password, "Bcrypt.hashPassword")

  result = newString(BcryptHashLen)
  var writtenLen: csize_t
  let status = bcryptHashPasswordRaw(
    bytesPtr(password),
    csize_t(password.len),
    cuint(cost),
    bytesPtr(result),
    csize_t(result.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_bcrypt_hash_password")
  result.setLen(int(writtenLen))

proc verifyPassword*(_: type Bcrypt; password, hash: string): bool =
  validateBcryptPassword(password, "Bcrypt.verifyPassword")

  let status = bcryptVerifyPasswordRaw(
    bytesPtr(password),
    csize_t(password.len),
    bytesPtr(hash),
    csize_t(hash.len),
  )
  verifyStatus(status)

proc validateHash*(_: type Bcrypt; hash: string): bool =
  let status = bcryptValidateHashRaw(
    bytesPtr(hash),
    csize_t(hash.len),
  )

  case status
  of RustCryptoOk:
    true
  of RustCryptoErrInvalidPasswordHashFormat, RustCryptoErrInvalidParameter:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_bcrypt_validate_hash failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_bcrypt_validate_hash failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_bcrypt_validate_hash failed: unexpected status " & $status,
    )

proc cost*(_: type Bcrypt; hash: string): int =
  var cost: cuint
  let status = bcryptCostRaw(
    bytesPtr(hash),
    csize_t(hash.len),
    addr cost,
  )
  raiseIfError(status, "rustcrypto_bcrypt_cost")
  int(cost)

proc needsRehash*(
    _: type Bcrypt,
    hash: string,
    cost: int = BcryptDefaultCost,
  ): bool =
  validateBcryptCost(cost, "Bcrypt.needsRehash")
  Bcrypt.cost(hash) < cost or not hash.startsWith("$2b$")
