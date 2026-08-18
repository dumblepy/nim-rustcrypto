import unittest

import ./utils
import rustcrypto/algorithm/secp256k1
import rustcrypto/ethereum

proc bytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, value in data:
    result[i] = char(value)

suite "ethereum":
  test "address derivation matches the keccak tail of the uncompressed public key":
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let digest = Ethereum.keccak256(publicKey[1 ..< publicKey.len])
    var expected: EthereumAddress
    for i in 0 ..< expected.len:
      expected[i] = digest[digest.len - expected.len + i]

    check Ethereum.address(publicKey) == expected
    check $Ethereum.address(publicKey) == "0x" & hexOf(expected)

  test "personal message hashing matches the EIP-191 composition":
    let message = "abc"
    let expected = Ethereum.keccak256(
      bytesFromString("\x19Ethereum Signed Message:\n" & $message.len & message)
    )

    check Ethereum.personalMessageHash(message) == expected

  test "typed data hashing matches the EIP-712 composition":
    let domain = fromHexDigest[EthereumHash](
      "1111111111111111111111111111111111111111111111111111111111111111",
      32,
    )
    let structHash = fromHexDigest[EthereumHash](
      "2222222222222222222222222222222222222222222222222222222222222222",
      32,
    )
    let expected = Ethereum.keccak256(
      bytesFromString("\x19\x01" & bytesToString(domain) & bytesToString(structHash))
    )

    check Ethereum.typedDataHash(domain, structHash) == expected

  test "personal message signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let walletAddress = Ethereum.address(publicKey)
    echo "walletAddress: " & $walletAddress
    let signature = Ethereum.signPersonalMessage("abc", secretKey)
    echo "signature: " & $signature

    check signature.v == 27'u8 or signature.v == 28'u8
    check Ethereum.verifyPersonalMessage("abc", walletAddress, signature)
    check not Ethereum.verifyPersonalMessage("abd", walletAddress, signature)

    let signature155 = Ethereum.signPersonalMessage("abc", secretKey, 1)
    check signature155.v == 37'u8 or signature155.v == 38'u8
    check Ethereum.verifyPersonalMessage("abc", walletAddress, signature155)

  test "typed data signing and verification round-trip":
    let secretKey = basePointSecretKey()
    let publicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let walletAddress = Ethereum.address(publicKey)
    let domain = fromHexDigest[EthereumHash](
      "1111111111111111111111111111111111111111111111111111111111111111",
      32,
    )
    let structHash = fromHexDigest[EthereumHash](
      "2222222222222222222222222222222222222222222222222222222222222222",
      32,
    )
    let signature = Ethereum.signTypedDataHash(domain, structHash, secretKey, 5)

    check signature.v == 45'u8 or signature.v == 46'u8
    check Ethereum.verifyTypedDataHash(domain, structHash, walletAddress, signature)

    let tamperedStruct = fromHexDigest[EthereumHash](
      "3333333333333333333333333333333333333333333333333333333333333333",
      32,
    )
    check not Ethereum.verifyTypedDataHash(domain, tamperedStruct, walletAddress, signature)

  test "marker type API round-trips":
    let secretKey = Secp256k1.generateSecretKey()
    let publicKey = Secp256k1.publicKeyUncompressed(secretKey)
    let domain = fromHexDigest[EthereumHash](
      "1111111111111111111111111111111111111111111111111111111111111111",
      32,
    )
    let structHash = fromHexDigest[EthereumHash](
      "2222222222222222222222222222222222222222222222222222222222222222",
      32,
    )
    let walletAddress = Ethereum.address(publicKey)
    let personalSignature = Ethereum.signPersonalMessage("abc", secretKey)
    let typedSignature = Ethereum.signTypedDataHash(domain, structHash, secretKey)

    check Ethereum.keccak256(bytesFromString("abc")) == Ethereum.keccak256(bytesFromString("abc"))
    check Ethereum.address(publicKey) == Ethereum.address(publicKey)
    check Ethereum.personalMessageHash("abc") == Ethereum.personalMessageHash("abc")
    check Ethereum.typedDataHash(domain, structHash) == Ethereum.typedDataHash(domain, structHash)
    check Ethereum.verifyPersonalMessage("abc", walletAddress, personalSignature)
    check Ethereum.verifyTypedDataHash(domain, structHash, walletAddress, typedSignature)

  test "stringification uses 0x-prefixed lowercase hex":
    let address = fromHexDigest[EthereumAddress](
      "00112233445566778899aabbccddeeff00112233",
      20,
    )
    var signature = EthereumSignature(
      r: fromHexDigest[array[32, byte]](
        "1111111111111111111111111111111111111111111111111111111111111111",
        32,
      ),
      s: fromHexDigest[array[32, byte]](
        "2222222222222222222222222222222222222222222222222222222222222222",
        32,
      ),
      v: 27'u8,
    )

    check $address == "0x00112233445566778899aabbccddeeff00112233"
    check $signature ==
      "0x111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221b"
