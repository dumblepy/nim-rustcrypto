import ./ffi
import ./pkcs8
import ./common

type
  Ed25519PrivateKeyPem* = string
  Ed25519PublicKeyPem* = string

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

proc ed25519PrivateKeyToPkcs8Pem*(
    privateKey: Ed25519PrivateKey,
  ): Ed25519PrivateKeyPem =
  var output = newString(Ed25519PrivateKeyPemMaxLen)
  var writtenLen: csize_t
  let status = ed25519PrivateKeyToPkcs8PemRaw(
    bytesPtr(privateKey),
    csize_t(privateKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_ed25519_private_key_to_pkcs8_pem")
  output.setLen(int(writtenLen))
  output

proc ed25519PrivateKeyFromPkcs8Pem*(
    privateKeyPem: string,
  ): Ed25519PrivateKey =
  var output: Ed25519PrivateKey
  let status = ed25519PrivateKeyFromPkcs8PemRaw(
    bytesPtr(privateKeyPem),
    csize_t(privateKeyPem.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_private_key_from_pkcs8_pem")
  output

proc ed25519PublicKeyToSpkiPem*(
    publicKey: Ed25519PublicKey,
  ): Ed25519PublicKeyPem =
  var output = newString(Ed25519PublicKeyPemMaxLen)
  var writtenLen: csize_t
  let status = ed25519PublicKeyToSpkiPemRaw(
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_ed25519_public_key_to_spki_pem")
  output.setLen(int(writtenLen))
  output

proc ed25519PublicKeyFromSpkiPem*(
    publicKeyPem: string,
  ): Ed25519PublicKey =
  var output: Ed25519PublicKey
  let status = ed25519PublicKeyFromSpkiPemRaw(
    bytesPtr(publicKeyPem),
    csize_t(publicKeyPem.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_public_key_from_spki_pem")
  output
