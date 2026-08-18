import ./ffi
import ./common

type
  X509CertDer* = seq[byte]
  X509CertPem* = string
  X509SubjectPublicKeyInfoDer* = seq[byte]
  X509SignatureAlgorithmOidDer* = seq[byte]
  X509NameDer* = seq[byte]

proc raiseIfError(status: cint; operation: string) =
  case status
  of RustCryptoOk:
    discard
  of RustCryptoErrNullOutput:
    raise newException(ValueError, operation & " failed: null output")
  of RustCryptoErrOutputTooShort:
    raise newException(ValueError, operation & " failed: output too short")
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, operation & " failed: null input with data")
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, operation & " failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, operation & " failed: invalid parameter")
  of RustCryptoErrInvalidCertificate:
    raise newException(ValueError, operation & " failed: invalid certificate")
  of RustCryptoErrPanic:
    raise newException(ValueError, operation & " failed: panic")
  else:
    raise newException(ValueError, operation & " failed: unexpected status " & $status)

proc validateStatus(status: cint): bool =
  case status
  of RustCryptoOk:
    true
  of RustCryptoErrInvalidCertificate:
    false
  of RustCryptoErrNullInputWithData:
    raise newException(ValueError, "rustcrypto_x509_cert_validate_der failed: null input with data")
  of RustCryptoErrInvalidLength:
    raise newException(ValueError, "rustcrypto_x509_cert_validate_der failed: invalid length")
  of RustCryptoErrInvalidParameter:
    raise newException(ValueError, "rustcrypto_x509_cert_validate_der failed: invalid parameter")
  of RustCryptoErrPanic:
    raise newException(ValueError, "rustcrypto_x509_cert_validate_der failed: panic")
  else:
    raise newException(
      ValueError,
      "rustcrypto_x509_cert_validate_der failed: unexpected status " & $status,
    )

proc x509CertValidateDer*(der: openArray[byte]): bool =
  let status = x509CertValidateDerRaw(
    bytesPtr(der),
    csize_t(der.len),
  )
  validateStatus(status)

proc x509CertFromPem*(pem: string): X509CertDer =
  var output = newSeq[byte](X509CertDerMaxLen)
  var writtenLen: csize_t
  let status = x509CertFromPemRaw(
    bytesPtr(pem),
    csize_t(pem.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_from_pem")
  output.setLen(int(writtenLen))
  output

proc x509CertToPem*(der: openArray[byte]): X509CertPem =
  var output = newString(X509CertPemMaxLen)
  var writtenLen: csize_t
  let status = x509CertToPemRaw(
    bytesPtr(der),
    csize_t(der.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_to_pem")
  output.setLen(int(writtenLen))
  output

proc x509CertSubjectPublicKeyInfoDer*(der: openArray[byte]): X509SubjectPublicKeyInfoDer =
  var output = newSeq[byte](X509CertDerMaxLen)
  var writtenLen: csize_t
  let status = x509CertSubjectPublicKeyInfoDerRaw(
    bytesPtr(der),
    csize_t(der.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_subject_public_key_info_der")
  output.setLen(int(writtenLen))
  output

proc x509CertSignatureAlgorithmOid*(der: openArray[byte]): X509SignatureAlgorithmOidDer =
  var output = newSeq[byte](32)
  var writtenLen: csize_t
  let status = x509CertSignatureAlgorithmOidRaw(
    bytesPtr(der),
    csize_t(der.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_signature_algorithm_oid")
  output.setLen(int(writtenLen))
  output

proc x509CertSubjectDer*(der: openArray[byte]): X509NameDer =
  var output = newSeq[byte](X509CertDerMaxLen)
  var writtenLen: csize_t
  let status = x509CertSubjectDerRaw(
    bytesPtr(der),
    csize_t(der.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_subject_der")
  output.setLen(int(writtenLen))
  output

proc x509CertIssuerDer*(der: openArray[byte]): X509NameDer =
  var output = newSeq[byte](X509CertDerMaxLen)
  var writtenLen: csize_t
  let status = x509CertIssuerDerRaw(
    bytesPtr(der),
    csize_t(der.len),
    bytesPtr(output),
    csize_t(output.len),
    addr writtenLen,
  )
  raiseIfError(status, "rustcrypto_x509_cert_issuer_der")
  output.setLen(int(writtenLen))
  output
