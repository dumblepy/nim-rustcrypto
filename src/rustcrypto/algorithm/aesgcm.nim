import ./ffi
import ./common

type
  Aes256GcmKey* = array[Aes256GcmKeyLen, byte]
  Aes256GcmNonce* = array[Aes256GcmNonceLen, byte]
  Aes256GcmTag* = array[Aes256GcmTagLen, byte]
  Aes256GcmCiphertext* = seq[byte]
  Aes256GcmPlaintext* = seq[byte]

proc fromHex*(_: type Aes256GcmKey, hex: string): Aes256GcmKey =
  fromHexDigest[Aes256GcmKey](hex, Aes256GcmKeyLen)

proc fromHex*(_: type Aes256GcmNonce, hex: string): Aes256GcmNonce =
  fromHexDigest[Aes256GcmNonce](hex, Aes256GcmNonceLen)

proc fromHex*(_: type Aes256GcmTag, hex: string): Aes256GcmTag =
  fromHexDigest[Aes256GcmTag](hex, Aes256GcmTagLen)

proc fromHexKey*(hex: string): Aes256GcmKey =
  fromHexDigest[Aes256GcmKey](hex, Aes256GcmKeyLen)

proc fromHexNonce*(hex: string): Aes256GcmNonce =
  fromHexDigest[Aes256GcmNonce](hex, Aes256GcmNonceLen)

proc fromHexTag*(hex: string): Aes256GcmTag =
  fromHexDigest[Aes256GcmTag](hex, Aes256GcmTagLen)

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

proc aes256gcmEncrypt*(
    key: Aes256GcmKey,
    nonce: Aes256GcmNonce,
    plaintext: openArray[byte],
    aad: openArray[byte],
  ): tuple[ciphertext: Aes256GcmCiphertext, tag: Aes256GcmTag] =
  var ciphertext = newSeq[byte](plaintext.len)
  var tag: Aes256GcmTag
  let status = aes256GcmEncryptRaw(
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
  raiseIfError(status, "rustcrypto_aes256gcm_encrypt")
  (ciphertext, tag)

proc aes256gcmDecrypt*(
    key: Aes256GcmKey,
    nonce: Aes256GcmNonce,
    ciphertext: openArray[byte],
    tag: Aes256GcmTag,
    aad: openArray[byte],
  ): Aes256GcmPlaintext =
  var plaintext = newSeq[byte](ciphertext.len)
  let status = aes256GcmDecryptRaw(
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
  raiseIfError(status, "rustcrypto_aes256gcm_decrypt")
  plaintext
