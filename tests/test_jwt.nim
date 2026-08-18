import std/base64
import std/json
import std/strutils
import std/random
import unittest

import ./utils
import rustcrypto/jwt

proc toBase64Url(data: string): string =
  result = base64.encode(data)
  result = result.replace("+", "-").replace("/", "_")
  while result.len > 0 and result[^1] == '=':
    result.setLen(result.len - 1)

proc randomString(maxLen: int): string =
  let length = rand(maxLen)
  result = newString(length)
  for i in 0 ..< length:
    result[i] = char(rand(255))

suite "jwt":
  test "random string secret can be converted to an oct JWK":
    randomize(0)

    let payload = %*{
      "sub": 1234567890,
      "name": "John Doe",
      "admin": true
    }
    let secret = randomString(100)
    let secretKey = Jwt.secretKey(secret)
    let secretJwk = parseJson($secretKey)
    let token = Jwt.sign(jwtHS256, payload, secretKey)

    check secretJwk["kty"].getStr() == "oct"
    check secretJwk["k"].getStr() == toBase64Url(secret)
    check Jwt.verify(jwtHS256, Jwt.publicKey(secretKey), token)
    check Jwt.decode(token) == payload

  test "marker type API round-trips with JWKs":
    let payload = %*{
      "sub": 1234567890,
      "name": "John Doe",
      "admin": true
    }

    let hsSecret = Jwt.generateSecretKey(jwtHS256)
    let hsPublic = Jwt.publicKey(hsSecret)
    let hsToken = Jwt.sign(jwtHS256, payload, hsSecret)
    let hsJwk = parseJson($hsSecret)
    let hsPublicJwk = parseJson($hsPublic)

    check hsJwk["kty"].getStr() == "oct"
    check not hsJwk.hasKey("d")
    check hsPublicJwk == hsJwk
    check Jwt.verify(jwtHS256, hsPublic, hsToken)
    check Jwt.decode(hsToken) == payload

    let esSecret = Jwt.generateSecretKey(jwtES256)
    let esPublic = Jwt.publicKey(esSecret)
    let esToken = Jwt.sign(jwtES256, payload, esSecret)
    let esJwk = parseJson($esSecret)
    let esPublicJwk = parseJson($esPublic)

    check esJwk["kty"].getStr() == "EC"
    check esJwk["crv"].getStr() == "P-256"
    check esJwk.hasKey("d")
    check not esPublicJwk.hasKey("d")
    check Jwt.verify(jwtES256, esPublic, esToken)
    check Jwt.decode(esToken) == payload

    let edSecret = Jwt.generateSecretKey(jwtEdDSA)
    let edPublic = Jwt.publicKey(edSecret)
    let edToken = Jwt.sign(jwtEdDSA, payload, edSecret)
    let edJwk = parseJson($edSecret)
    let edPublicJwk = parseJson($edPublic)

    check edJwk["kty"].getStr() == "OKP"
    check edJwk["crv"].getStr() == "Ed25519"
    check edJwk.hasKey("d")
    check not edPublicJwk.hasKey("d")
    check Jwt.verify(jwtEdDSA, edPublic, edToken)
    check Jwt.decode(edToken) == payload

    let rsSecret = Jwk(
      kty: "RSA",
      privateDer: toBase64Url(Rsa2048PrivateKeyDerFixture),
      publicDer: toBase64Url(Rsa2048PublicKeyDerFixture),
    )
    let rsPublic = Jwt.publicKey(rsSecret)
    let rsToken = Jwt.sign(jwtRS256, payload, rsSecret)
    let rsPublicJwk = parseJson($rsPublic)

    check rsPublicJwk["kty"].getStr() == "RSA"
    check rsPublicJwk.hasKey("public_der")
    check not rsPublicJwk.hasKey("private_der")
    check Jwt.verify(jwtRS256, rsPublic, rsToken)
    check Jwt.decode(rsToken) == payload

    let psToken = Jwt.sign(jwtPS256, payload, rsSecret)
    check Jwt.verify(jwtPS256, rsPublic, psToken)
    check Jwt.decode(psToken) == payload
