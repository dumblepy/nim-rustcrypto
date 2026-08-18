import std/posix

import ./ffi

proc bytesPtr*(data: string): ptr uint8 =
  ## Convert a string to a byte pointer. Returns `nil` for an empty string.
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc bytesPtr*(data: openArray[byte]): ptr uint8 =
  ## Convert a byte slice to a byte pointer. Returns `nil` for an empty slice.
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc urandomBytes*[N: static[int]](): array[N, byte] =
  ## Read exactly `N` bytes from `/dev/urandom`.
  let fd = open("/dev/urandom", O_RDONLY)
  if fd < 0:
    raise newException(OSError, "failed to open /dev/urandom: " & $strerror(errno))
  defer:
    discard close(fd)

  var offset = 0
  while offset < N:
    let bytesRead = read(fd, addr result[offset], N - offset)
    if bytesRead < 0:
      if errno == EINTR:
        continue
      raise newException(OSError, "failed to read /dev/urandom: " & $strerror(errno))
    if bytesRead == 0:
      raise newException(OSError, "unexpected EOF while reading /dev/urandom")
    offset += bytesRead

proc digestToHex*[T](_: typedesc[T], digest: openArray[byte]): string =
  ## Convert a byte slice to a hexadecimal string.
  const hexDigits = "0123456789abcdef"
  result = newString(digest.len * 2)

  for i, value in digest:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

proc bytesToHexString*(bytes: openArray[byte]): string =
  ## Convert an arbitrary byte slice to a lowercase hexadecimal string.
  digestToHex(byte, bytes)

proc hexNibble(ch: char): int =
  ## Convert a single hexadecimal character to an integer.
  case ch
  of '0'..'9':
    ord(ch) - ord('0')
  of 'a'..'f':
    ord(ch) - ord('a') + 10
  of 'A'..'F':
    ord(ch) - ord('A') + 10
  else:
    raise newException(ValueError, "invalid hex digit")

proc fromHexDigest*[T](hex: string, digestLen: static[int]): T =
  ## Convert a hexadecimal string to a fixed-size byte array.
  doAssert hex.len == digestLen * 2

  var output: T
  for i in 0 ..< digestLen:
    let hi = hexNibble(hex[2 * i])
    let lo = hexNibble(hex[2 * i + 1])
    output[i] = byte((hi shl 4) or lo)

  output

proc raiseRustCryptoStatus*(status: cint; operation: string) =
  ## Raise a consistent ValueError for non-zero RustCrypto status codes.
  if status != RustCryptoOk:
    raise newException(ValueError, operation & " failed with status " & $status)

template hashOneShot*(
    rawProc: untyped,
    message: string,
    output: untyped,
    operation: string,
  ): untyped =
  ## Invoke a hash FFI proc with the common string-to-buffer pattern.
  let status = rawProc(
    bytesPtr(message),
    csize_t(message.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseRustCryptoStatus(status, operation)
