import ./algorithm/sha256
import ./algorithm/secp256k1
import ./algorithm/schnorr

type
  Bitcoin* = object
  BitcoinMessageSignature* = array[65, byte]
  BitcoinEcdsaSignature* = Secp256k1Signature
  BitcoinSchnorrSignature* = SchnorrSignature
  BitcoinXOnlyPublicKey* = SchnorrPublicKey
  BitcoinMessageHash* = Sha256Digest
  BitcoinNetwork* = enum
    bitcoinMainnet,
    bitcoinTestnet,
    bitcoinRegtest

const
  BitcoinSignedMessagePrefix = "Bitcoin Signed Message:\n"
  BitcoinRecoverableSignatureLen = 65
  BitcoinRawSignatureLen = 64

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc compactSize(value: int): string =
  let n = uint64(value)
  if n < 0xfd'u64:
    result = newString(1)
    result[0] = char(n)
  elif n <= 0xffff'u64:
    result = newString(3)
    result[0] = char(0xfd)
    result[1] = char(n and 0xff)
    result[2] = char((n shr 8) and 0xff)
  elif n <= 0xffff_ffff'u64:
    result = newString(5)
    result[0] = char(0xfe)
    result[1] = char(n and 0xff)
    result[2] = char((n shr 8) and 0xff)
    result[3] = char((n shr 16) and 0xff)
    result[4] = char((n shr 24) and 0xff)
  else:
    result = newString(9)
    result[0] = char(0xff)
    for i in 0 ..< 8:
      result[1 + i] = char((n shr (8 * i)) and 0xff)

proc hash256*(T: type Bitcoin, data: openArray[byte]): BitcoinMessageHash =
  let first = sha256(bytesToString(data))
  sha256(bytesToString(first))

proc taggedHash*(T: type Bitcoin, tag: string, message: openArray[byte]): BitcoinMessageHash =
  let tagHash = sha256(tag)
  let tagHashBytes = bytesToString(tagHash)
  sha256(tagHashBytes & tagHashBytes & bytesToString(message))

proc messageHash*(T: type Bitcoin, message: string): BitcoinMessageHash =
  let payload = char(BitcoinSignedMessagePrefix.len) &
    BitcoinSignedMessagePrefix &
    compactSize(message.len) &
    message
  let first = sha256(payload)
  sha256(bytesToString(first))

proc bitcoinRecoverableToCompact(signature: Secp256k1RecoverableSignature): BitcoinMessageSignature =
  let recoveryId = signature[BitcoinRecoverableSignatureLen - 1]
  if recoveryId > 3:
    raise newException(ValueError, "bitcoin recoverable signature has invalid recovery id")

  result[0] = byte(31 + recoveryId)
  for i in 0 ..< BitcoinRawSignatureLen:
    result[1 + i] = signature[i]

proc bitcoinCompactToRecoverable(signature: BitcoinMessageSignature): Secp256k1RecoverableSignature =
  let header = signature[0]
  if header < 31 or header > 34:
    raise newException(ValueError, "bitcoin message signature has invalid header")

  result[BitcoinRecoverableSignatureLen - 1] = header - 31
  for i in 0 ..< BitcoinRawSignatureLen:
    result[i] = signature[1 + i]

proc signMessage*(T: type Bitcoin, message: string, secretKey: Secp256k1SecretKey): BitcoinMessageSignature =
  let digest = messageHash(T, message)
  bitcoinRecoverableToCompact(Secp256k1.signRecoverable(digest, secretKey))

proc verifyMessage*(
    T: type Bitcoin,
    message: string,
    publicKey: Secp256k1CompressedPublicKey,
    signature: BitcoinMessageSignature,
  ): bool =
  let digest = messageHash(T, message)
  Secp256k1.verifyRecoverable(digest, publicKey, bitcoinCompactToRecoverable(signature))

proc signDigestEcdsa*(
    T: type Bitcoin,
    digest: BitcoinMessageHash,
    secretKey: Secp256k1SecretKey,
  ): BitcoinEcdsaSignature =
  Secp256k1.sign(digest, secretKey)

proc verifyDigestEcdsa*(
    T: type Bitcoin,
    digest: BitcoinMessageHash,
    publicKey: Secp256k1CompressedPublicKey,
    signature: BitcoinEcdsaSignature,
  ): bool =
  Secp256k1.verify(digest, publicKey, signature)

proc signTaprootDigest*(
    T: type Bitcoin,
    digest: BitcoinMessageHash,
    secretKey: SchnorrSecretKey,
  ): BitcoinSchnorrSignature =
  Schnorr.sign(digest, secretKey)

proc verifyTaprootDigest*(
    T: type Bitcoin,
    digest: BitcoinMessageHash,
    publicKey: BitcoinXOnlyPublicKey,
    signature: BitcoinSchnorrSignature,
  ): bool =
  Schnorr.verify(digest, publicKey, signature)
