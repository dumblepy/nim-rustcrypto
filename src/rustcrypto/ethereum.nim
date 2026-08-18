import ./algorithm/ffi
import ./algorithm/common
import ./algorithm/sha3
import ./algorithm/secp256k1

type
  Ethereum* = object
  EthereumAddress* = array[20, byte]
  EthereumHash* = array[32, byte]
  EthereumSignature* = object
    r*: array[32, byte]
    s*: array[32, byte]
    v*: byte
  EthereumChainId* = uint64

const EthereumRecoverableSignatureLen = 65

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc to0xHex(data: openArray[byte]): string =
  "0x" & bytesToHexString(data)

# proc cptr(data: string): ptr uint8 =
#   if data.len == 0:
#     nil
#   else:
#     cast[ptr uint8](unsafeAddr data[0])

proc cptr(data: openArray[byte]): ptr uint8 =
  if data.len == 0:
    nil
  else:
    cast[ptr uint8](unsafeAddr data[0])

proc keccak256Bytes(data: openArray[byte]): EthereumHash =
  keccak256(bytesToString(data))

proc keccak256*(T: type Ethereum, data: openArray[byte]): EthereumHash =
  keccak256Bytes(data)

proc addressFromPublicKey(publicKey: Secp256k1UncompressedPublicKey): EthereumAddress =
  if publicKey[0] != 0x04:
    raise newException(ValueError, "ethereum address requires an uncompressed SEC1 public key")

  let digest = keccak256Bytes(publicKey[1 ..< publicKey.len])
  for i in 0 ..< result.len:
    result[i] = digest[digest.len - result.len + i]

proc address*(T: type Ethereum, publicKey: Secp256k1UncompressedPublicKey): EthereumAddress =
  addressFromPublicKey(publicKey)

proc `$`*(value: EthereumAddress): string =
  to0xHex(value)

proc personalMessageDigest(message: string): EthereumHash =
  keccak256("\x19Ethereum Signed Message:\n" & $message.len & message)

proc personalMessageHash*(T: type Ethereum, message: string): EthereumHash =
  personalMessageDigest(message)

proc typedDataDigest(domainSeparator: EthereumHash; structHash: EthereumHash): EthereumHash =
  keccak256("\x19\x01" & bytesToString(domainSeparator) & bytesToString(structHash))

proc typedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
  ): EthereumHash =
  typedDataDigest(domainSeparator, structHash)

proc signatureFromRecoverable(
    signature: Secp256k1RecoverableSignature,
    chainId: EthereumChainId,
  ): EthereumSignature =
  let recoveryId = signature[EthereumRecoverableSignatureLen - 1]
  let parity = recoveryId and 1
  let vValue =
    if chainId == 0:
      27'u64 + uint64(parity)
    else:
      35'u64 + chainId * 2'u64 + uint64(parity)

  if vValue > high(byte).uint64:
    raise newException(ValueError, "ethereum recovery id is too large to encode in v")

  result.v = byte(vValue)
  for i in 0 ..< 32:
    result.r[i] = signature[i]
    result.s[i] = signature[32 + i]

proc `$`*(value: EthereumSignature): string =
  var bytes = newSeq[byte](EthereumRecoverableSignatureLen)
  for i in 0 ..< 32:
    bytes[i] = value.r[i]
    bytes[32 + i] = value.s[i]
  bytes[64] = value.v
  to0xHex(bytes)

proc recoverableSignatureFromEthereum(
    signature: EthereumSignature,
  ): tuple[signature: Secp256k1RecoverableSignature, valid: bool] =
  if signature.v == 27'u8 or signature.v == 28'u8:
    let parity = signature.v - 27
    for i in 0 ..< 32:
      result.signature[i] = signature.r[i]
      result.signature[32 + i] = signature.s[i]
    result.signature[64] = parity
    result.valid = true
  elif signature.v >= 35:
    let parity = signature.v and 1
    for i in 0 ..< 32:
      result.signature[i] = signature.r[i]
      result.signature[32 + i] = signature.s[i]
    result.signature[64] = parity
    result.valid = true
  else:
    result.valid = false

proc matchesRecoverableSignatureAddress(
    digest: EthereumHash,
    expectedAddress: EthereumAddress,
    signature: EthereumSignature,
  ): bool =
  let recovered = recoverableSignatureFromEthereum(signature)
  if not recovered.valid:
    return false

  for candidate in [0'u8, 1'u8, 2'u8, 3'u8]:
    var trial = recovered.signature
    trial[64] = candidate
    var recoveredPublicKey: Secp256k1UncompressedPublicKey
    let status = secp256k1EcdsaRecoverPublicKeyRaw(
      cptr(digest),
      csize_t(digest.len),
      cptr(trial),
      csize_t(trial.len),
      cast[ptr uint8](addr recoveredPublicKey[0]),
      csize_t(recoveredPublicKey.len),
      Secp256k1PublicKeyFormatUncompressed,
    )
    case status
    of RustCryptoOk:
      if addressFromPublicKey(recoveredPublicKey) == expectedAddress:
        return true
    of RustCryptoErrVerificationFailed:
      discard
    of RustCryptoErrNullOutput,
       RustCryptoErrOutputTooShort,
       RustCryptoErrNullInputWithData,
       RustCryptoErrInvalidMessageDigest,
       RustCryptoErrInvalidSignature,
       RustCryptoErrInvalidPublicKeyFormat,
       RustCryptoErrPanic:
      raise newException(
        ValueError,
        "rustcrypto_secp256k1_ecdsa_recover_public_key failed: " & $status,
      )
    else:
      raise newException(
        ValueError,
        "rustcrypto_secp256k1_ecdsa_recover_public_key failed: unexpected status " & $status,
      )

  false

proc signPersonalMessage*(
    T: type Ethereum,
    message: string,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  signatureFromRecoverable(Secp256k1.signRecoverable(personalMessageDigest(message), secretKey), chainId)

proc verifyPersonalMessage*(
    T: type Ethereum,
    message: string,
    walletAddress: EthereumAddress,
    signature: EthereumSignature,
  ): bool =
  if not recoverableSignatureFromEthereum(signature).valid:
    raise newException(ValueError, "ethereum signature has an unsupported v value")
  matchesRecoverableSignatureAddress(personalMessageDigest(message), walletAddress, signature)

proc signTypedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    secretKey: Secp256k1SecretKey,
    chainId: EthereumChainId = 0,
  ): EthereumSignature =
  signatureFromRecoverable(
    Secp256k1.signRecoverable(typedDataDigest(domainSeparator, structHash), secretKey),
    chainId,
  )

proc verifyTypedDataHash*(
    T: type Ethereum,
    domainSeparator: EthereumHash,
    structHash: EthereumHash,
    walletAddress: EthereumAddress,
    signature: EthereumSignature,
  ): bool =
  if not recoverableSignatureFromEthereum(signature).valid:
    raise newException(ValueError, "ethereum signature has an unsupported v value")
  matchesRecoverableSignatureAddress(
    typedDataDigest(domainSeparator, structHash),
    walletAddress,
    signature,
  )
