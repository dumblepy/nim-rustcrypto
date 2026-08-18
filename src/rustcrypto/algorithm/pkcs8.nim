import ./ffi
import ./common

type
  Ed25519PrivateKey* = array[Ed25519PrivateKeyLen, byte]
  Ed25519PublicKey* = array[Ed25519PublicKeyLen, byte]
  Ed25519PrivateKeyPkcs8Der* = seq[byte]
  Ed25519PublicKeySpkiDer* = seq[byte]

proc `$`*(value: Ed25519PublicKeySpkiDer): string =
  bytesToHexString(value)

proc fromHexPrivateKey*(hex: string): Ed25519PrivateKey =
  fromHexDigest[Ed25519PrivateKey](hex, Ed25519PrivateKeyLen)

proc fromHexPublicKey*(hex: string): Ed25519PublicKey =
  fromHexDigest[Ed25519PublicKey](hex, Ed25519PublicKeyLen)

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

proc ed25519PrivateKeyToPkcs8Der*(
    privateKey: Ed25519PrivateKey,
  ): Ed25519PrivateKeyPkcs8Der =
  var output = newSeq[byte](Ed25519PrivateKeyDerMaxLen)
  var writtenLen: csize_t
  let status = ed25519PrivateKeyToPkcs8DerRaw(
    bytesPtr(privateKey),
    csize_t(privateKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_ed25519_private_key_to_pkcs8_der")
  output.setLen(int(writtenLen))
  output

proc ed25519PrivateKeyFromPkcs8Der*(
    privateKeyDer: openArray[byte],
  ): Ed25519PrivateKey =
  var output: Ed25519PrivateKey
  let status = ed25519PrivateKeyFromPkcs8DerRaw(
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_private_key_from_pkcs8_der")
  output

proc ed25519PublicKeyToSpkiDer*(
    publicKey: Ed25519PublicKey,
  ): Ed25519PublicKeySpkiDer =
  var output = newSeq[byte](Ed25519PublicKeyDerMaxLen)
  var writtenLen: csize_t
  let status = ed25519PublicKeyToSpkiDerRaw(
    bytesPtr(publicKey),
    csize_t(publicKey.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_ed25519_public_key_to_spki_der")
  output.setLen(int(writtenLen))
  output

proc ed25519PublicKeyFromSpkiDer*(
    publicKeyDer: openArray[byte],
  ): Ed25519PublicKey =
  var output: Ed25519PublicKey
  let status = ed25519PublicKeyFromSpkiDerRaw(
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_ed25519_public_key_from_spki_der")
  output
