import ./ffi
import ./common

type
  Rsa* = object
  RsaPrivateKeyDer* = seq[byte]
  RsaPublicKeyDer* = seq[byte]
  RsaSignature* = seq[byte]
  RsaCiphertext* = seq[byte]

proc `$`*(value: RsaPublicKeyDer): string =
  bytesToHexString(value)

proc normalizeDer(
    rawProc: proc (
      der: ptr uint8,
      derLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    input: openArray[byte],
    outputLen: int,
    operation: string,
  ): seq[byte]
proc signWithRaw(
    rawProc: proc (
      message: ptr uint8,
      messageLen: csize_t,
      privateKeyDer: ptr uint8,
      privateKeyDerLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    message: string,
    privateKeyDer: openArray[byte],
    operation: string,
  ): RsaSignature
proc verifyWithRaw(
    rawProc: proc (
      message: ptr uint8,
      messageLen: csize_t,
      publicKeyDer: ptr uint8,
      publicKeyDerLen: csize_t,
      signature: ptr uint8,
      signatureLen: csize_t,
    ): cint {.cdecl.},
    message: string,
    publicKeyDer: openArray[byte],
    signature: openArray[byte],
    operation: string,
  ): bool
proc encryptWithRaw(
    rawProc: proc (
      plaintext: ptr uint8,
      plaintextLen: csize_t,
      publicKeyDer: ptr uint8,
      publicKeyDerLen: csize_t,
      label: ptr uint8,
      labelLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    plaintext: openArray[byte],
    publicKeyDer: openArray[byte],
    label: string,
    operation: string,
  ): RsaCiphertext
proc decryptWithRaw(
    rawProc: proc (
      ciphertext: ptr uint8,
      ciphertextLen: csize_t,
      privateKeyDer: ptr uint8,
      privateKeyDerLen: csize_t,
      label: ptr uint8,
      labelLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    ciphertext: openArray[byte],
    privateKeyDer: openArray[byte],
    label: string,
    operation: string,
  ): seq[byte]

proc privateKeyToPkcs8Der*(T: type Rsa, privateKeyDer: openArray[byte]): RsaPrivateKeyDer =
  normalizeDer(
    rsaPrivateKeyToPkcs8DerRaw,
    privateKeyDer,
    RsaPrivateKeyDerMaxLen,
    "rustcrypto_rsa_private_key_to_pkcs8_der",
  )

proc privateKeyFromPkcs8Der*(T: type Rsa, privateKeyDer: openArray[byte]): RsaPrivateKeyDer =
  normalizeDer(
    rsaPrivateKeyFromPkcs8DerRaw,
    privateKeyDer,
    RsaPrivateKeyDerMaxLen,
    "rustcrypto_rsa_private_key_from_pkcs8_der",
  )

proc publicKeyToSpkiDer*(T: type Rsa, publicKeyDer: openArray[byte]): RsaPublicKeyDer =
  normalizeDer(
    rsaPublicKeyToSpkiDerRaw,
    publicKeyDer,
    RsaPublicKeyDerMaxLen,
    "rustcrypto_rsa_public_key_to_spki_der",
  )

proc publicKeyFromSpkiDer*(T: type Rsa, publicKeyDer: openArray[byte]): RsaPublicKeyDer =
  normalizeDer(
    rsaPublicKeyFromSpkiDerRaw,
    publicKeyDer,
    RsaPublicKeyDerMaxLen,
    "rustcrypto_rsa_public_key_from_spki_der",
  )

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
  of RustCryptoErrDecryptionFailed:
    raise newException(ValueError, operation & " failed: decryption failed")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc verifyStatus(status: cint; operation: string): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrVerificationFailed:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrInvalidSignature:
    raise newException(ValueError, operation & " failed: invalid signature")
  of RustCryptoErrDecryptionFailed:
    raise newException(ValueError, operation & " failed: decryption failed")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc normalizeDer(
    rawProc: proc (
      der: ptr uint8,
      derLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    input: openArray[byte],
    outputLen: int,
    operation: string,
  ): seq[byte] =
  var output = newSeq[byte](outputLen)
  var writtenLen: csize_t
  let status = rawProc(
    bytesPtr(input),
    csize_t(input.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, operation)
  output.setLen(int(writtenLen))
  output

proc signWithRaw(
    rawProc: proc (
      message: ptr uint8,
      messageLen: csize_t,
      privateKeyDer: ptr uint8,
      privateKeyDerLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    message: string,
    privateKeyDer: openArray[byte],
    operation: string,
  ): RsaSignature =
  var output = newSeq[byte](max(256, privateKeyDer.len))
  var writtenLen: csize_t
  let status = rawProc(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, operation)
  output.setLen(int(writtenLen))
  output

proc verifyWithRaw(
    rawProc: proc (
      message: ptr uint8,
      messageLen: csize_t,
      publicKeyDer: ptr uint8,
      publicKeyDerLen: csize_t,
      signature: ptr uint8,
      signatureLen: csize_t,
    ): cint {.cdecl.},
    message: string,
    publicKeyDer: openArray[byte],
    signature: openArray[byte],
    operation: string,
  ): bool =
  let status = rawProc(
    bytesPtr(message),
    csize_t(message.len),
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    bytesPtr(signature),
    csize_t(signature.len),
  )
  verifyStatus(status, operation)

proc encryptWithRaw(
    rawProc: proc (
      plaintext: ptr uint8,
      plaintextLen: csize_t,
      publicKeyDer: ptr uint8,
      publicKeyDerLen: csize_t,
      label: ptr uint8,
      labelLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    plaintext: openArray[byte],
    publicKeyDer: openArray[byte],
    label: string,
    operation: string,
  ): RsaCiphertext =
  var output = newSeq[byte](max(256, publicKeyDer.len))
  var writtenLen: csize_t
  let status = rawProc(
    bytesPtr(plaintext),
    csize_t(plaintext.len),
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    bytesPtr(label),
    csize_t(label.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, operation)
  output.setLen(int(writtenLen))
  output

proc decryptWithRaw(
    rawProc: proc (
      ciphertext: ptr uint8,
      ciphertextLen: csize_t,
      privateKeyDer: ptr uint8,
      privateKeyDerLen: csize_t,
      label: ptr uint8,
      labelLen: csize_t,
      output: ptr uint8,
      outputLen: csize_t,
      writtenLen: ptr csize_t,
    ): cint {.cdecl.},
    ciphertext: openArray[byte],
    privateKeyDer: openArray[byte],
    label: string,
    operation: string,
  ): seq[byte] =
  var output = newSeq[byte](max(ciphertext.len, 256))
  var writtenLen: csize_t
  let status = rawProc(
    bytesPtr(ciphertext),
    csize_t(ciphertext.len),
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    bytesPtr(label),
    csize_t(label.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, operation)
  output.setLen(int(writtenLen))
  output

proc pssSignSha256*(T: type Rsa, message: string, privateKeyDer: openArray[byte]): RsaSignature =
  signWithRaw(rsaPssSignSha256Raw, message, privateKeyDer, "rustcrypto_rsa_pss_sign_sha256")

proc pssVerifySha256*(
    T: type Rsa,
    message: string,
    publicKeyDer: openArray[byte],
    signature: openArray[byte],
): bool =
  verifyWithRaw(rsaPssVerifySha256Raw, message, publicKeyDer, signature, "rustcrypto_rsa_pss_verify_sha256")

proc pkcs1v15SignSha256*(
    T: type Rsa,
    message: string,
    privateKeyDer: openArray[byte],
): RsaSignature =
  signWithRaw(
    rsaPkcs1v15SignSha256Raw,
    message,
    privateKeyDer,
    "rustcrypto_rsa_pkcs1v15_sign_sha256",
  )

proc pkcs1v15VerifySha256*(
    T: type Rsa,
    message: string,
    publicKeyDer: openArray[byte],
    signature: openArray[byte],
): bool =
  verifyWithRaw(
    rsaPkcs1v15VerifySha256Raw,
    message,
    publicKeyDer,
    signature,
    "rustcrypto_rsa_pkcs1v15_verify_sha256",
  )

proc oaepSha256Encrypt*(
    T: type Rsa,
    plaintext: openArray[byte],
    publicKeyDer: openArray[byte],
    label: string = "",
): RsaCiphertext =
  encryptWithRaw(
    rsaOaepSha256EncryptRaw,
    plaintext,
    publicKeyDer,
    label,
    "rustcrypto_rsa_oaep_sha256_encrypt",
  )

proc oaepSha256Decrypt*(
    T: type Rsa,
    ciphertext: openArray[byte],
    privateKeyDer: openArray[byte],
    label: string = "",
): seq[byte] =
  decryptWithRaw(
    rsaOaepSha256DecryptRaw,
    ciphertext,
    privateKeyDer,
    label,
    "rustcrypto_rsa_oaep_sha256_decrypt",
  )

proc pkcs1v15Encrypt*(
    T: type Rsa,
    plaintext: openArray[byte],
    publicKeyDer: openArray[byte],
): RsaCiphertext =
  var output = newSeq[byte](max(256, publicKeyDer.len))
  var writtenLen: csize_t
  let status = rsaPkcs1v15EncryptRaw(
    bytesPtr(plaintext),
    csize_t(plaintext.len),
    bytesPtr(publicKeyDer),
    csize_t(publicKeyDer.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_rsa_pkcs1v15_encrypt")
  output.setLen(int(writtenLen))
  output

proc pkcs1v15Decrypt*(
    T: type Rsa,
    ciphertext: openArray[byte],
    privateKeyDer: openArray[byte],
): seq[byte] =
  var output = newSeq[byte](max(ciphertext.len, 256))
  var writtenLen: csize_t
  let status = rsaPkcs1v15DecryptRaw(
    bytesPtr(ciphertext),
    csize_t(ciphertext.len),
    bytesPtr(privateKeyDer),
    csize_t(privateKeyDer.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_rsa_pkcs1v15_decrypt")
  output.setLen(int(writtenLen))
  output
