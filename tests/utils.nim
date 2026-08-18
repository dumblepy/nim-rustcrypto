import rustcrypto/algorithm/ffi
import rustcrypto/algorithm/common
import rustcrypto/algorithm/secp256k1

export ffi
export common

proc hexOf*(bytes: openArray[byte]): string =
  const hexDigits = "0123456789abcdef"
  result = newString(bytes.len * 2)
  for i, value in bytes:
    let byteValue = int(value)
    result[2 * i] = hexDigits[byteValue shr 4]
    result[2 * i + 1] = hexDigits[byteValue and 0x0F]

proc bytesFromHex*(hex: string): seq[byte] =
  doAssert hex.len mod 2 == 0

  proc nibble(ch: char): byte =
    case ch
    of '0'..'9':
      byte(ord(ch) - ord('0'))
    of 'a'..'f':
      byte(ord(ch) - ord('a') + 10)
    of 'A'..'F':
      byte(ord(ch) - ord('A') + 10)
    else:
      raise newException(ValueError, "invalid hex digit")

  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte((nibble(hex[2 * i]) shl 4) or nibble(hex[2 * i + 1]))

proc bytesFromString*(text: string): seq[byte] =
  result = newSeq[byte](text.len)
  for i, ch in text:
    result[i] = byte(ord(ch))

proc basePointSecretKey*(): Secp256k1SecretKey =
  result = default(Secp256k1SecretKey)
  result[Secp256k1SecretKeyLen - 1] = 1

const
  Rsa2048PrivateKeyDerFixture* = staticRead("../rustcrypto-ffi/tests/fixtures/rsa2048-private-key.der")
  Rsa2048PublicKeyDerFixture* = staticRead("../rustcrypto-ffi/tests/fixtures/rsa2048-public-key.der")
  Rsa2048CertDerFixture* = staticRead("../rustcrypto-ffi/tests/fixtures/rsa2048-cert.der")
  Rsa2048CertPemFixture* = staticRead("../rustcrypto-ffi/tests/fixtures/rsa2048-cert.pem")
