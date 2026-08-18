import ./ffi
import ./common

type
  Sha3_256Digest* = array[Sha3_256DigestLen, byte]
  Keccak256Digest* = array[Keccak256DigestLen, byte]

proc fromHexSha3_256*(_: type Sha3_256Digest, hex: string): Sha3_256Digest =
  fromHexDigest[Sha3_256Digest](hex, Sha3_256DigestLen)

proc fromHexKeccak256*(_: type Keccak256Digest, hex: string): Keccak256Digest =
  fromHexDigest[Keccak256Digest](hex, Keccak256DigestLen)

proc sha3_256*(message: string): Sha3_256Digest =
  var output: Sha3_256Digest
  hashOneShot(sha3_256Raw, message, output, "rustcrypto_sha3_256")
  output

proc sha3_256Hex*(message: string): string =
  digestToHex(Sha3_256Digest, sha3_256(message))

proc keccak256*(message: string): Keccak256Digest =
  var output: Keccak256Digest
  hashOneShot(keccak256Raw, message, output, "rustcrypto_keccak_256")
  output

proc keccak256Hex*(message: string): string =
  digestToHex(Keccak256Digest, keccak256(message))
