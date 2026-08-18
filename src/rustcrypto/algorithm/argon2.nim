import ./ffi
import ./common

type
  Argon2idOkm* = seq[byte]
  Argon2idPasswordHashString* = string

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
  of RustCryptoErrInvalidPasswordHashFormat:
    raise newException(ValueError, operation & " failed: invalid password hash format")
  of RustCryptoErrVerificationFailed:
    raise newException(ValueError, operation & " failed: verification failed")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc verifyStatus(status: cint): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrInvalidPasswordHashFormat:
    raise newException(
      ValueError,
      "rustcrypto_argon2id_verify_password failed: invalid password hash format",
    )
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_argon2id_verify_password failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_argon2id_verify_password failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_argon2id_verify_password failed: unexpected status " & $status,
    )

proc argon2idDerive*(
    password, salt: string,
    mCost: int,
    tCost: int,
    pCost: int,
    hashLen: int,
  ): Argon2idOkm =
  if mCost <= 0 or tCost <= 0 or pCost <= 0:
    raise newException(ValueError, "argon2idDerive failed: invalid parameter")
  if hashLen < Argon2idMinHashLen:
    raise newException(ValueError, "argon2idDerive failed: invalid length")

  result = newSeq[byte](hashLen)
  if hashLen == 0:
    return

  let status = argon2idDeriveRaw(
    bytesPtr(password),
    csize_t(password.len),
    bytesPtr(salt),
    csize_t(salt.len),
    cuint(mCost),
    cuint(tCost),
    cuint(pCost),
    bytesPtr(result),
    csize_t(result.len),
    csize_t(hashLen),
  )
  raiseIfError(status, "rustcrypto_argon2id_derive")

proc estimatePhcCapacity(saltLen: int, hashLen: int): int =
  let saltB64Len = 4 * ((saltLen + 2) div 3)
  let hashB64Len = 4 * ((hashLen + 2) div 3)
  result = 64 + saltB64Len + hashB64Len
  if result < 128:
    result = 128

proc argon2idHashPassword*(
    password, salt: string,
    mCost: int,
    tCost: int,
    pCost: int,
    hashLen: int,
  ): Argon2idPasswordHashString =
  if mCost <= 0 or tCost <= 0 or pCost <= 0:
    raise newException(ValueError, "argon2idHashPassword failed: invalid parameter")
  if hashLen < Argon2idMinHashLen:
    raise newException(ValueError, "argon2idHashPassword failed: invalid length")

  var capacity = estimatePhcCapacity(salt.len, hashLen)
  while true:
    result = newString(capacity)
    var writtenLen: csize_t
    let status = argon2idHashPasswordRaw(
      bytesPtr(password),
      csize_t(password.len),
      bytesPtr(salt),
      csize_t(salt.len),
      cuint(mCost),
      cuint(tCost),
      cuint(pCost),
      csize_t(hashLen),
      bytesPtr(result),
      csize_t(result.len),
      addr writtenLen,
    )

    case status
    of RustCryptoOk:
      result.setLen(int(writtenLen))
      return
    of RustCryptoErrOutputTooShort:
      capacity = capacity * 2
      if capacity < 0:
        raise newException(ValueError, "argon2idHashPassword failed: invalid length")
    else:
      raiseIfError(status, "rustcrypto_argon2id_hash_password")

proc argon2idVerifyPassword*(password, phc: string): bool =
  let status = argon2idVerifyPasswordRaw(
    bytesPtr(password),
    csize_t(password.len),
    bytesPtr(phc),
    csize_t(phc.len),
  )
  verifyStatus(status)
