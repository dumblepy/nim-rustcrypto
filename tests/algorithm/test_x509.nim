import unittest

import ./utils
import ../../src/rustcrypto/algorithm/rsa
import ../../src/rustcrypto/algorithm/x509

suite "x509":
  test "certificate validates and round-trips between PEM and DER":
    let certDer = x509CertFromPem(Rsa2048CertPemFixture)

    check x509CertValidateDer(certDer)
    check x509CertToPem(certDer) == Rsa2048CertPemFixture

  test "certificate metadata is extracted from the fixture":
    let certDer = x509CertFromPem(Rsa2048CertPemFixture)
    let spki = x509CertSubjectPublicKeyInfoDer(certDer)

    check hexOf(x509CertSignatureAlgorithmOid(certDer)) == "06092a864886f70d01010b"
    check x509CertSubjectDer(certDer) == x509CertIssuerDer(certDer)
    check Rsa.publicKeyFromSpkiDer(spki) == spki
    check Rsa.publicKeyToSpkiDer(spki) == spki

  test "validate rejects malformed DER":
    check not x509CertValidateDer(bytesFromHex("3000"))

  test "raw PEM decoder rejects short output buffers":
    var output = newSeq[byte](Rsa2048PublicKeyDerFixture.len - 1)
    var writtenLen: csize_t

    let status = x509CertFromPemRaw(
      bytesPtr(Rsa2048CertPemFixture),
      csize_t(Rsa2048CertPemFixture.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw certificate-to-PEM encoder rejects short output buffers":
    let certDer = x509CertFromPem(Rsa2048CertPemFixture)
    var output = newString(Rsa2048CertPemFixture.len - 1)
    var writtenLen: csize_t

    let status = x509CertToPemRaw(
      bytesPtr(certDer),
      csize_t(certDer.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort

  test "raw subject public key info extraction rejects short output buffers":
    let certDer = x509CertFromPem(Rsa2048CertPemFixture)
    var output = newSeq[byte](Rsa2048PublicKeyDerFixture.len - 1)
    var writtenLen: csize_t

    let status = x509CertSubjectPublicKeyInfoDerRaw(
      bytesPtr(certDer),
      csize_t(certDer.len),
      bytesPtr(output),
      csize_t(output.len),
      addr writtenLen,
    )

    check status == RustCryptoErrOutputTooShort
