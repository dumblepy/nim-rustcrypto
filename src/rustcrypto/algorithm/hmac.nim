import ./ffi
import ./common

type
  HmacSha256Mac* = array[HmacSha256MacLen, byte]

proc raiseIfError(status: cint) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: null input with data")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_hmac_sha256 failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_hmac_sha256 failed: unexpected status " & $status,
    )

proc hmacSha256*(key, message: string): HmacSha256Mac =
  var output: HmacSha256Mac
  let status = hmacSha256Raw(
    bytesPtr(key),
    csize_t(key.len),
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status)
  output

proc hmacSha256Hex*(key, message: string): string =
  digestToHex(HmacSha256Mac, hmacSha256(key, message))
