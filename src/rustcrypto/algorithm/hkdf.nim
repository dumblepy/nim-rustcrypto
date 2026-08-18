import ./ffi
import ./common

type
  HkdfSha256Prk* = array[HkdfSha256PrkLen, byte]
  HkdfSha256Okm* = seq[byte]

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
  of RustCryptoErrInvalidPrkLength:
    raise newException(ValueError, operation & " failed: invalid PRK length")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc hkdfSha256Extract*(salt, ikm: string): HkdfSha256Prk =
  var output: HkdfSha256Prk
  let status = hkdfSha256ExtractRaw(
    bytesPtr(salt),
    csize_t(salt.len),
    bytesPtr(ikm),
    csize_t(ikm.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_hkdf_sha256_extract")
  output

proc hkdfSha256Expand*(prk: HkdfSha256Prk, info: string, okmLen: int): HkdfSha256Okm =
  if okmLen < 0:
    raise newException(ValueError, "hkdfSha256Expand failed: negative output length")
  if okmLen > HkdfSha256MaxOkmLen:
    raise newException(ValueError, "hkdfSha256Expand failed: invalid length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = hkdfSha256ExpandRaw(
    bytesPtr(prk),
    csize_t(prk.len),
    bytesPtr(info),
    csize_t(info.len),
    bytesPtr(result),
    csize_t(result.len),
  )
  raiseIfError(status, "rustcrypto_hkdf_sha256_expand")

proc hkdfSha256Derive*(salt, ikm, info: string, okmLen: int): HkdfSha256Okm =
  if okmLen < 0:
    raise newException(ValueError, "hkdfSha256Derive failed: negative output length")
  if okmLen > HkdfSha256MaxOkmLen:
    raise newException(ValueError, "hkdfSha256Derive failed: invalid length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = hkdfSha256DeriveRaw(
    bytesPtr(salt),
    csize_t(salt.len),
    bytesPtr(ikm),
    csize_t(ikm.len),
    bytesPtr(info),
    csize_t(info.len),
    bytesPtr(result),
    csize_t(result.len),
  )
  raiseIfError(status, "rustcrypto_hkdf_sha256_derive")
