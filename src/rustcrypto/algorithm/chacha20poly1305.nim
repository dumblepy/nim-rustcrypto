import ./ffi
import ./common

type
  ChaCha20Poly1305Key* = array[ChaCha20Poly1305KeyLen, byte]
  ChaCha20Poly1305Nonce* = array[ChaCha20Poly1305NonceLen, byte]
  ChaCha20Poly1305Tag* = array[ChaCha20Poly1305TagLen, byte]
  ChaCha20Poly1305Ciphertext* = seq[byte]
  ChaCha20Poly1305Plaintext* = seq[byte]

proc fromHex*(_: type ChaCha20Poly1305Key, hex: string): ChaCha20Poly1305Key =
  fromHexDigest[ChaCha20Poly1305Key](hex, ChaCha20Poly1305KeyLen)

proc fromHex*(_: type ChaCha20Poly1305Nonce, hex: string): ChaCha20Poly1305Nonce =
  fromHexDigest[ChaCha20Poly1305Nonce](hex, ChaCha20Poly1305NonceLen)

proc fromHex*(_: type ChaCha20Poly1305Tag, hex: string): ChaCha20Poly1305Tag =
  fromHexDigest[ChaCha20Poly1305Tag](hex, ChaCha20Poly1305TagLen)

proc fromHexKey*(hex: string): ChaCha20Poly1305Key =
  fromHexDigest[ChaCha20Poly1305Key](hex, ChaCha20Poly1305KeyLen)

proc fromHexNonce*(hex: string): ChaCha20Poly1305Nonce =
  fromHexDigest[ChaCha20Poly1305Nonce](hex, ChaCha20Poly1305NonceLen)

proc fromHexTag*(hex: string): ChaCha20Poly1305Tag =
  fromHexDigest[ChaCha20Poly1305Tag](hex, ChaCha20Poly1305TagLen)

proc raiseIfError(status: cint) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: null input with data")
  of RustCryptoErrInvalidKeyLength:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: invalid key length")
  of RustCryptoErrInvalidNonceLength:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: invalid nonce length")
  of RustCryptoErrInvalidTagLength:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: invalid tag length")
  of RustCryptoErrAuthenticationFailed:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: authentication failed")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_chacha20poly1305 failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_chacha20poly1305 failed: unexpected status " & $status,
    )

proc chacha20poly1305Encrypt*(
    key: ChaCha20Poly1305Key,
    nonce: ChaCha20Poly1305Nonce,
    plaintext: openArray[byte],
    aad: openArray[byte],
  ): tuple[ciphertext: ChaCha20Poly1305Ciphertext, tag: ChaCha20Poly1305Tag] =
  var ciphertext = newSeq[byte](plaintext.len)
  var tag: ChaCha20Poly1305Tag
  let status = chacha20Poly1305EncryptRaw(
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
  raiseIfError(status)
  (ciphertext, tag)

proc chacha20poly1305Decrypt*(
    key: ChaCha20Poly1305Key,
    nonce: ChaCha20Poly1305Nonce,
    ciphertext: openArray[byte],
    tag: ChaCha20Poly1305Tag,
    aad: openArray[byte],
  ): ChaCha20Poly1305Plaintext =
  var plaintext = newSeq[byte](ciphertext.len)
  let status = chacha20Poly1305DecryptRaw(
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
  raiseIfError(status)
  plaintext
