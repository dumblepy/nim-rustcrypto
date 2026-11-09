import unittest
import std/strutils
import ./utils
import ../../src/rustcrypto/algorithm/bn254

const
  FrModulusHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
  FrModulusMinusOneHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"

suite "bn254":
  test "fr accepts canonical values":
    check Bn254.isCanonicalFr(fromHexFr("00" & "00".repeat(31)))
    let one = fromHexFr("00".repeat(31) & "01")
    check Bn254.isCanonicalFr(one)
    check Bn254.isCanonicalFr(fromHexFr(FrModulusMinusOneHex))

  test "fr rejects modulus and larger values":
    check not Bn254.isCanonicalFr(fromHexFr(FrModulusHex))
    check not Bn254.isCanonicalFr(fromHexFr("ff".repeat(32)))
    check not Bn254.isCanonicalFr(fromHexFr("40" & "00".repeat(31)))

  test "fr hex round trip":
    let value = fromHexFr("0000000000000000000000000000000000000000000000000000000000000009")
    check value.frToHex == "0000000000000000000000000000000000000000000000000000000000000009"

  test "g1 and g2 validation rejects garbage and accepts infinity":
    var infinityG1: Bn254G1
    var infinityG2: Bn254G2
    check Bn254.isValidG1(infinityG1)
    check Bn254.isValidG2(infinityG2)

    for i in 0 ..< infinityG1.len:
      infinityG1[i] = 0xff
    for i in 0 ..< infinityG2.len:
      infinityG2[i] = 0xff
    check not Bn254.isValidG1(infinityG1)
    check not Bn254.isValidG2(infinityG2)
