import ./ffi
import ./common

type
  Blake2b512Digest* = array[Blake2b512DigestLen, byte]
  Blake2s256Digest* = array[Blake2s256DigestLen, byte]

proc fromHexBlake2b512*(_: type Blake2b512Digest, hex: string): Blake2b512Digest =
  fromHexDigest[Blake2b512Digest](hex, Blake2b512DigestLen)

proc fromHexBlake2s256*(_: type Blake2s256Digest, hex: string): Blake2s256Digest =
  fromHexDigest[Blake2s256Digest](hex, Blake2s256DigestLen)

proc raiseIfError(status: cint; operation: string) =
  if status != RustCryptoOk:
    raise newException(ValueError, operation & " failed with status " & $status)

proc blake2b512*(message: string): Blake2b512Digest =
  var output: Blake2b512Digest
  let status = blake2b512Raw(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_blake2b_512")
  output

proc blake2b512Hex*(message: string): string =
  digestToHex(Blake2b512Digest, blake2b512(message))

proc blake2s256*(message: string): Blake2s256Digest =
  var output: Blake2s256Digest
  let status = blake2s256Raw(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(status, "rustcrypto_blake2s_256")
  output

proc blake2s256Hex*(message: string): string =
  digestToHex(Blake2s256Digest, blake2s256(message))
