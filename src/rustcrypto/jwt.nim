import std/json
import std/strutils

import ./algorithm/common
import ./algorithm/ffi
import ./algorithm/ed25519
import ./algorithm/hmac
import ./algorithm/p256
import ./algorithm/rsa

type
  Jwt* = object
  Jwk* = object
    kty*: string
    crv*: string
    k*: string
    x*: string
    y*: string
    d*: string
    n*: string
    e*: string
    privateDer*: string
    publicDer*: string
  JwtAlgorithm* = enum
    jwtHS256,
    jwtES256,
    jwtEdDSA,
    jwtRS256,
    jwtPS256
  JwtCompact* = string
  JwtHeaderJson* = string
  JwtClaimsJson* = string
  JwtSecret* = seq[byte]

const
  JwtEcdsaSignatureLen = 64
  JwtEd25519SignatureLen = 64

proc toJsonNode(jwk: Jwk): JsonNode

proc `$`*(jwk: Jwk): string =
  let node = toJsonNode(jwk)
  $node

proc base64UrlEncode(data: openArray[byte]): string
proc base64UrlEncode(data: string): string
proc base64UrlDecode(data: string): seq[byte]
proc buildSigningInput(headerJson: string; claimsJson: string): string
proc buildCompactToken(signingInput: string; signature: openArray[byte]): JwtCompact
proc splitCompactToken(token: string): tuple[header, claims, signature: string]
proc compactSignatureBytes(tokenSignature: string): seq[byte]
proc verifyCompactAlg(tokenHeaderPart: string; expectedAlg: string; operation: string): bool
proc sameBytes(actual: seq[byte]; expected: openArray[byte]): bool

proc toJsonNode(jwk: Jwk): JsonNode =
  result = newJObject()
  if jwk.kty.len > 0:
    result["kty"] = %jwk.kty
  if jwk.crv.len > 0:
    result["crv"] = %jwk.crv
  if jwk.k.len > 0:
    result["k"] = %jwk.k
  if jwk.x.len > 0:
    result["x"] = %jwk.x
  if jwk.y.len > 0:
    result["y"] = %jwk.y
  if jwk.d.len > 0:
    result["d"] = %jwk.d
  if jwk.n.len > 0:
    result["n"] = %jwk.n
  if jwk.e.len > 0:
    result["e"] = %jwk.e
  if jwk.privateDer.len > 0:
    result["private_der"] = %jwk.privateDer
  if jwk.publicDer.len > 0:
    result["public_der"] = %jwk.publicDer

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

proc stringToBytes(data: string): seq[byte] =
  result = newSeq[byte](data.len)
  for i, ch in data:
    result[i] = byte(ord(ch))

proc jwtAlgorithmName(algorithm: JwtAlgorithm): string =
  case algorithm
  of jwtHS256:
    "HS256"
  of jwtES256:
    "ES256"
  of jwtEdDSA:
    "EdDSA"
  of jwtRS256:
    "RS256"
  of jwtPS256:
    "PS256"

proc jwtHeaderJson(algorithm: JwtAlgorithm): string =
  $(%*{
    "alg": jwtAlgorithmName(algorithm),
    "typ": "JWT",
  })

proc jwtPayloadJson(payload: JsonNode): string =
  $payload

proc jwtHeaderJson(header: JsonNode): string =
  $header

proc fixedArrayFromBytes*[T](data: openArray[byte]): T =
  doAssert data.len == result.len
  for i in 0 ..< data.len:
    result[i] = data[i]

proc bytesFromBase64Url(value: string): seq[byte] =
  if value.len == 0:
    return @[]
  base64UrlDecode(value)

proc octJwkFromSecret(secret: openArray[byte]): Jwk =
  result.kty = "oct"
  result.k = base64UrlEncode(secret)

proc octJwkFromSecret(secret: string): Jwk =
  octJwkFromSecret(stringToBytes(secret))

proc ecJwkFromSecret(secretKey: P256SecretKey): Jwk =
  let publicKey = P256.publicKeyUncompressed(secretKey)
  result.kty = "EC"
  result.crv = "P-256"
  result.x = base64UrlEncode(publicKey[1 .. 32])
  result.y = base64UrlEncode(publicKey[33 .. 64])
  result.d = base64UrlEncode(secretKey)

proc ecJwkFromPublicKey(publicKey: openArray[byte]): Jwk =
  if publicKey.len != 65 or publicKey[0] != 0x04:
    raise newException(ValueError, "EC JWK requires an uncompressed SEC1 public key")
  result.kty = "EC"
  result.crv = "P-256"
  result.x = base64UrlEncode(publicKey[1 .. 32])
  result.y = base64UrlEncode(publicKey[33 .. 64])

proc ecSecretKeyFromJwk(jwk: Jwk): P256SecretKey =
  if jwk.kty != "EC" or jwk.crv != "P-256":
    raise newException(ValueError, "JWT ES256 requires an EC P-256 JWK")
  let bytes = bytesFromBase64Url(jwk.d)
  if bytes.len != P256SecretKeyLen:
    raise newException(ValueError, "JWT ES256 JWK has invalid private key length")
  result = fixedArrayFromBytes[P256SecretKey](bytes)

proc ecPublicKeyFromJwk(jwk: Jwk): P256UncompressedPublicKey =
  if jwk.kty != "EC" or jwk.crv != "P-256":
    raise newException(ValueError, "JWT ES256 requires an EC P-256 JWK")
  let x = bytesFromBase64Url(jwk.x)
  let y = bytesFromBase64Url(jwk.y)
  if x.len != 32 or y.len != 32:
    raise newException(ValueError, "JWT ES256 JWK has invalid public key length")
  result[0] = 0x04
  for i in 0 ..< 32:
    result[1 + i] = x[i]
    result[33 + i] = y[i]

proc okpJwkFromSecret(secretKey: Ed25519SecretKey): Jwk =
  let publicKey = Ed25519.publicKey(secretKey)
  result.kty = "OKP"
  result.crv = "Ed25519"
  result.x = base64UrlEncode(publicKey)
  result.d = base64UrlEncode(secretKey)

proc okpJwkFromPublicKey(publicKey: Ed25519PublicKey): Jwk =
  result.kty = "OKP"
  result.crv = "Ed25519"
  result.x = base64UrlEncode(publicKey)

proc okpSecretKeyFromJwk(jwk: Jwk): Ed25519SecretKey =
  if jwk.kty != "OKP" or jwk.crv != "Ed25519":
    raise newException(ValueError, "JWT EdDSA requires an OKP Ed25519 JWK")
  let bytes = bytesFromBase64Url(jwk.d)
  if bytes.len != Ed25519PrivateKeyLen:
    raise newException(ValueError, "JWT EdDSA JWK has invalid private key length")
  result = fixedArrayFromBytes[Ed25519SecretKey](bytes)

proc okpPublicKeyFromJwk(jwk: Jwk): Ed25519PublicKey =
  if jwk.kty != "OKP" or jwk.crv != "Ed25519":
    raise newException(ValueError, "JWT EdDSA requires an OKP Ed25519 JWK")
  let bytes = bytesFromBase64Url(jwk.x)
  if bytes.len != Ed25519PublicKeyLen:
    raise newException(ValueError, "JWT EdDSA JWK has invalid public key length")
  result = fixedArrayFromBytes[Ed25519PublicKey](bytes)

proc generateSecretKey*(T: type Jwt, algorithm: JwtAlgorithm): Jwk =
  case algorithm
  of jwtHS256:
    octJwkFromSecret(urandomBytes[32]())
  of jwtES256:
    ecJwkFromSecret(P256.generateSecretKey())
  of jwtEdDSA:
    okpJwkFromSecret(Ed25519.generateSecretKey())
  of jwtRS256, jwtPS256:
    raise newException(ValueError, "JWT RSA key generation is not supported yet")

proc secretKey*(T: type Jwt, secret: string): Jwk =
  octJwkFromSecret(secret)

proc publicKey*(T: type Jwt, secretKey: Jwk): Jwk =
  case secretKey.kty
  of "oct":
    result = Jwk(kty: "oct", k: secretKey.k)
  of "EC":
    result = ecJwkFromPublicKey(ecPublicKeyFromJwk(secretKey))
  of "OKP":
    result = okpJwkFromPublicKey(okpPublicKeyFromJwk(secretKey))
  of "RSA":
    if secretKey.publicDer.len == 0:
      raise newException(ValueError, "JWT RSA public key derivation is not available from a private JWK without public_der")
    result = Jwk(kty: "RSA", n: secretKey.n, e: secretKey.e, publicDer: secretKey.publicDer)
  else:
    raise newException(ValueError, "unsupported JWK key type: " & secretKey.kty)

proc sign*(
    T: type Jwt,
    algorithm: JwtAlgorithm,
    payload: JsonNode,
    secretKey: Jwk,
  ): JwtCompact =
  var header = newJObject()
  header["alg"] = %jwtAlgorithmName(algorithm)
  header["typ"] = %"JWT"
  sign(T, algorithm, header, payload, secretKey)

proc sign*(
    T: type Jwt,
    algorithm: JwtAlgorithm,
    header: JsonNode,
    payload: JsonNode,
    secretKey: Jwk,
  ): JwtCompact =
  let headerJson = jwtHeaderJson(header)
  let expectedAlg = jwtAlgorithmName(algorithm)
  let parsedHeader = parseJson(headerJson)
  if parsedHeader.kind != JObject or not parsedHeader.hasKey("alg") or parsedHeader["alg"].kind != JString:
    raise newException(ValueError, "JWT header must contain a string alg field")
  if parsedHeader["alg"].getStr() != expectedAlg:
    raise newException(ValueError, "JWT header alg does not match the selected algorithm")
  let signingInput = buildSigningInput(headerJson, jwtPayloadJson(payload))
  case algorithm
  of jwtHS256:
    if secretKey.kty != "oct":
      raise newException(ValueError, "JWT HS256 requires an oct JWK")
    let mac = hmacSha256(bytesToString(bytesFromBase64Url(secretKey.k)), signingInput)
    buildCompactToken(signingInput, mac)
  of jwtES256:
    let secret = ecSecretKeyFromJwk(secretKey)
    let signature = P256.sign(signingInput, secret)
    buildCompactToken(signingInput, signature)
  of jwtEdDSA:
    let secret = okpSecretKeyFromJwk(secretKey)
    let signature = Ed25519.sign(signingInput, secret)
    buildCompactToken(signingInput, signature)
  of jwtRS256:
    if secretKey.privateDer.len == 0:
      raise newException(ValueError, "JWT RS256 requires a private_der JWK field")
    let signature = Rsa.pkcs1v15SignSha256(signingInput, bytesFromBase64Url(secretKey.privateDer))
    buildCompactToken(signingInput, signature)
  of jwtPS256:
    if secretKey.privateDer.len == 0:
      raise newException(ValueError, "JWT PS256 requires a private_der JWK field")
    let signature = Rsa.pssSignSha256(signingInput, bytesFromBase64Url(secretKey.privateDer))
    buildCompactToken(signingInput, signature)

proc verify*(
    T: type Jwt,
    algorithm: JwtAlgorithm,
    publicKey: Jwk,
    token: JwtCompact,
  ): bool =
  let parts = splitCompactToken(token)
  let expectedAlg = jwtAlgorithmName(algorithm)
  if not verifyCompactAlg(parts.header, expectedAlg, "Jwt.verify"):
    return false

  let signingInput = parts.header & "." & parts.claims
  let signature = compactSignatureBytes(parts.signature)
  case algorithm
  of jwtHS256:
    if publicKey.kty != "oct":
      raise newException(ValueError, "JWT HS256 requires an oct JWK")
    let expected = hmacSha256(bytesToString(bytesFromBase64Url(publicKey.k)), signingInput)
    return sameBytes(signature, expected)
  of jwtES256:
    let public = ecPublicKeyFromJwk(publicKey)
    if signature.len != JwtEcdsaSignatureLen:
      raise newException(ValueError, "Jwt.verify failed: invalid signature length")
    let fixedSignature = fixedArrayFromBytes[P256Signature](signature)
    return P256.verify(signingInput, public, fixedSignature)
  of jwtEdDSA:
    let public = okpPublicKeyFromJwk(publicKey)
    if signature.len != JwtEd25519SignatureLen:
      raise newException(ValueError, "Jwt.verify failed: invalid signature length")
    var fixedSignature: Ed25519Signature
    for i in 0 ..< JwtEd25519SignatureLen:
      fixedSignature[i] = signature[i]
    return Ed25519.verify(signingInput, public, fixedSignature)
  of jwtRS256:
    if publicKey.publicDer.len == 0:
      raise newException(ValueError, "JWT RS256 requires a public_der JWK field")
    return Rsa.pkcs1v15VerifySha256(signingInput, bytesFromBase64Url(publicKey.publicDer), signature)
  of jwtPS256:
    if publicKey.publicDer.len == 0:
      raise newException(ValueError, "JWT PS256 requires a public_der JWK field")
    return Rsa.pssVerifySha256(signingInput, bytesFromBase64Url(publicKey.publicDer), signature)

proc decode*(T: type Jwt, token: JwtCompact): JsonNode =
  let parts = splitCompactToken(token)
  parseJson(bytesToString(base64UrlDecode(parts.claims)))

proc headerAlgFromJson(headerJson: string): string =
  let node = parseJson(headerJson)
  if node.kind != JObject or not node.hasKey("alg") or node["alg"].kind != JString:
    raise newException(ValueError, "JWT header must contain a string alg field")
  node["alg"].getStr()

proc headerAlgMatches(tokenHeaderJson: string; expectedAlg: string; operation: string): bool =
  let headerAlg = headerAlgFromJson(tokenHeaderJson)
  if headerAlg == "none":
    raise newException(ValueError, operation & " failed: alg none is not supported")
  headerAlg == expectedAlg

proc base64UrlValue(ch: char): int =
  case ch
  of 'A'..'Z':
    ord(ch) - ord('A')
  of 'a'..'z':
    ord(ch) - ord('a') + 26
  of '0'..'9':
    ord(ch) - ord('0') + 52
  of '-':
    62
  of '_':
    63
  else:
    -1

proc base64UrlEncode(data: openArray[byte]): string =
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  result = newStringOfCap((data.len * 4 + 2) div 3)
  var i = 0
  while i < data.len:
    let b0 = uint32(data[i])
    let b1 = if i + 1 < data.len: uint32(data[i + 1]) else: 0'u32
    let b2 = if i + 2 < data.len: uint32(data[i + 2]) else: 0'u32
    let triple = (b0 shl 16) or (b1 shl 8) or b2

    result.add(alphabet[int((triple shr 18) and 0x3f)])
    result.add(alphabet[int((triple shr 12) and 0x3f)])
    if i + 1 < data.len:
      result.add(alphabet[int((triple shr 6) and 0x3f)])
    if i + 2 < data.len:
      result.add(alphabet[int(triple and 0x3f)])

    i += 3

proc base64UrlEncode(data: string): string =
  base64UrlEncode(stringToBytes(data))

proc base64UrlDecode(data: string): seq[byte] =
  if data.len mod 4 == 1:
    raise newException(ValueError, "invalid base64url length")

  var buffer: uint32 = 0
  var bits = 0
  result = @[]

  for ch in data:
    let value = base64UrlValue(ch)
    if value < 0:
      raise newException(ValueError, "invalid base64url character")

    buffer = (buffer shl 6) or uint32(value)
    bits += 6

    while bits >= 8:
      bits -= 8
      result.add(byte((buffer shr bits) and 0xff))
      if bits > 0:
        buffer = buffer and ((uint32(1) shl bits) - 1)
      else:
        buffer = 0

  if bits > 0 and buffer != 0:
    raise newException(ValueError, "invalid base64url padding")

proc buildSigningInput(headerJson: string; claimsJson: string): string =
  base64UrlEncode(headerJson) & "." & base64UrlEncode(claimsJson)

proc splitCompactToken(token: string): tuple[header, claims, signature: string] =
  let first = token.find('.')
  let last = token.rfind('.')
  if first <= 0 or last <= first or last == token.len - 1:
    raise newException(ValueError, "invalid JWS compact serialization")

  result.header = token[0 ..< first]
  result.claims = token[first + 1 ..< last]
  result.signature = token[last + 1 ..< token.len]

proc buildCompactToken(signingInput: string; signature: openArray[byte]): JwtCompact =
  signingInput & "." & base64UrlEncode(signature)

proc compactSignatureBytes(tokenSignature: string): seq[byte] =
  base64UrlDecode(tokenSignature)

proc verifyCompactAlg(tokenHeaderPart: string; expectedAlg: string; operation: string): bool =
  let headerJson = bytesToString(base64UrlDecode(tokenHeaderPart))
  headerAlgMatches(headerJson, expectedAlg, operation)

proc sameBytes(actual: seq[byte]; expected: openArray[byte]): bool =
  if actual.len != expected.len:
    return false
  for i in 0 ..< actual.len:
    if actual[i] != expected[i]:
      return false
  true
