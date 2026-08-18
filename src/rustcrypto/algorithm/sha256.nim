import ./ffi
import ./ecdsa_common
import ./secp256k1
import ./common

type
  Sha256Digest* = array[SHA256DigestLen, byte]

proc fromHex*(_: type Sha256Digest, hex: string): Sha256Digest =
  fromHexDigest[Sha256Digest](hex, SHA256DigestLen)

proc sha256*(message: string): Sha256Digest =
  var output: Sha256Digest
  hashOneShot(sha256Raw, message, output, "rustcrypto_sha256")
  output

proc sha256Hex*(message: string): string =
  digestToHex(Sha256Digest, sha256(message))

proc secp256k1EcdsaSignSha256*(
    message: string,
    secretKey: secp256k1.Secp256k1SecretKey,
  ): secp256k1.Secp256k1Signature =
  secp256k1EcdsaSignMessage(
    secp256k1EcdsaSignSha256Raw,
    message,
    secretKey,
    "rustcrypto_secp256k1_ecdsa_sign_sha256",
  )

proc secp256k1EcdsaVerifySha256*(
    message: string,
    publicKey: secp256k1.Secp256k1CompressedPublicKey,
    signature: secp256k1.Secp256k1Signature,
  ): bool =
  secp256k1EcdsaVerifyMessage(
    secp256k1EcdsaVerifySha256Raw,
    message,
    publicKey,
    signature,
    ffi.Secp256k1PublicKeyFormatCompressed,
    "rustcrypto_secp256k1_ecdsa_verify_sha256",
  )

proc secp256k1EcdsaVerifySha256*(
    message: string,
    publicKey: secp256k1.Secp256k1UncompressedPublicKey,
    signature: secp256k1.Secp256k1Signature,
  ): bool =
  secp256k1EcdsaVerifyMessage(
    secp256k1EcdsaVerifySha256Raw,
    message,
    publicKey,
    signature,
    ffi.Secp256k1PublicKeyFormatUncompressed,
    "rustcrypto_secp256k1_ecdsa_verify_sha256",
  )
