import ./ffi
import ./common

type
  Aes256GcmSivKey* = array[Aes256GcmSivKeyLen, byte]
  Aes256GcmSivNonce* = array[Aes256GcmSivNonceLen, byte]
  Aes256GcmSivTag* = array[Aes256GcmSivTagLen, byte]
  Aes256GcmSivCiphertext* = seq[byte]
  Aes256GcmSivPlaintext* = seq[byte]

proc fromHex*(_: type Aes256GcmSivKey, hex: string): Aes256GcmSivKey =
  fromHexDigest[Aes256GcmSivKey](hex, Aes256GcmSivKeyLen)

proc fromHex*(_: type Aes256GcmSivNonce, hex: string): Aes256GcmSivNonce =
  fromHexDigest[Aes256GcmSivNonce](hex, Aes256GcmSivNonceLen)

proc fromHex*(_: type Aes256GcmSivTag, hex: string): Aes256GcmSivTag =
  fromHexDigest[Aes256GcmSivTag](hex, Aes256GcmSivTagLen)

proc fromHexKey*(hex: string): Aes256GcmSivKey =
  fromHexDigest[Aes256GcmSivKey](hex, Aes256GcmSivKeyLen)

proc fromHexNonce*(hex: string): Aes256GcmSivNonce =
  fromHexDigest[Aes256GcmSivNonce](hex, Aes256GcmSivNonceLen)

proc fromHexTag*(hex: string): Aes256GcmSivTag =
  fromHexDigest[Aes256GcmSivTag](hex, Aes256GcmSivTagLen)

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
  of RustCryptoErrInvalidKeyLength:
    raise newException(ValueError, operation & " failed: invalid key length")
  of RustCryptoErrInvalidNonceLength:
    raise newException(ValueError, operation & " failed: invalid nonce length")
  of RustCryptoErrInvalidTagLength:
    raise newException(ValueError, operation & " failed: invalid tag length")
  of RustCryptoErrAuthenticationFailed:
    raise newException(ValueError, operation & " failed: authentication failed")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc aes256gcmsivEncrypt*(
    key: Aes256GcmSivKey,
    nonce: Aes256GcmSivNonce,
    plaintext: openArray[byte],
    aad: openArray[byte],
  ): tuple[ciphertext: Aes256GcmSivCiphertext, tag: Aes256GcmSivTag] =
  var ciphertext = newSeq[byte](plaintext.len)
  var tag: Aes256GcmSivTag
  let status = aes256GcmSivEncryptRaw(
    bytesPtr(key),
    csize_t(key.len),
    bytesPtr(nonce),
    csize_t(nonce.len),
    bytesPtr(aad),
    csize_t(aad.len),
    bytesPtr(plaintext),
    csize_t(plaintext.len),
    bytesPtr(ciphertext),
    csize_t(ciphertext.len),
    cast[ptr uint8](addr tag[0]),
    csize_t(tag.len),
  )
  raiseIfError(status, "rustcrypto_aes256gcmsiv_encrypt")
  (ciphertext, tag)

proc aes256gcmsivDecrypt*(
    key: Aes256GcmSivKey,
    nonce: Aes256GcmSivNonce,
    ciphertext: openArray[byte],
    tag: Aes256GcmSivTag,
    aad: openArray[byte],
  ): Aes256GcmSivPlaintext =
  var plaintext = newSeq[byte](ciphertext.len)
  let status = aes256GcmSivDecryptRaw(
    bytesPtr(key),
    csize_t(key.len),
    bytesPtr(nonce),
    csize_t(nonce.len),
    bytesPtr(aad),
    csize_t(aad.len),
    bytesPtr(ciphertext),
    csize_t(ciphertext.len),
    cast[ptr uint8](unsafeAddr tag[0]),
    csize_t(tag.len),
    bytesPtr(plaintext),
    csize_t(plaintext.len),
  )
  raiseIfError(status, "rustcrypto_aes256gcmsiv_decrypt")
  plaintext
