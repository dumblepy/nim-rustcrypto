use crate::{
    RUSTCRYPTO_ERR_INVALID_CERTIFICATE, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_OK, X509_CERT_DER_MAX_LEN, aead_common,
};
use core::ffi::c_int;
use pem_rfc7468::{Error, LineEnding, decode, encode, encoded_len};
use std::panic::{AssertUnwindSafe, catch_unwind};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

fn map_pem_error(err: Error) -> c_int {
    match err {
        Error::Length => RUSTCRYPTO_ERR_INVALID_LENGTH,
        _ => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

fn certificate_bytes<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    aead_common::optional_input(input, input_len)
}

fn validate_certificate_der(der: &[u8]) -> c_int {
    match Certificate::from_der(der) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_CERTIFICATE,
    }
}

fn encode_pem(der: &[u8], output: *mut u8, output_len: usize, written_len: *mut usize) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let required_len = match encoded_len("CERTIFICATE", LineEnding::LF, der) {
        Ok(len) => len,
        Err(err) => return map_pem_error(err),
    };

    let output = match aead_common::output_buffer(output, output_len, required_len) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let encoded = match encode("CERTIFICATE", LineEnding::LF, der, output) {
        Ok(encoded) => encoded,
        Err(err) => return map_pem_error(err),
    };

    unsafe {
        *written_len = encoded.len();
    }

    RUSTCRYPTO_OK
}

pub(crate) fn validate_der_impl(der: *const u8, der_len: usize) -> c_int {
    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    validate_certificate_der(der)
}

pub(crate) fn from_pem_impl(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let pem = match certificate_bytes(pem, pem_len) {
        Ok(pem) => pem,
        Err(err) => return err,
    };

    let mut der = [0u8; X509_CERT_DER_MAX_LEN];
    let (label, decoded) = match decode(pem, &mut der) {
        Ok(result) => result,
        Err(err) => return map_pem_error(err),
    };

    if label != "CERTIFICATE" {
        return RUSTCRYPTO_ERR_INVALID_CERTIFICATE;
    }

    let status = validate_certificate_der(decoded);
    if status != RUSTCRYPTO_OK {
        return status;
    }

    let output = match aead_common::output_buffer(output, output_len, decoded.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(decoded);
    unsafe {
        *written_len = decoded.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn to_pem_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };

    let status = validate_certificate_der(der);
    if status != RUSTCRYPTO_OK {
        return status;
    }

    encode_pem(der, output, output_len, written_len)
}

pub(crate) fn subject_public_key_info_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let cert = match Certificate::from_der(der) {
        Ok(cert) => cert,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_CERTIFICATE,
    };
    let spki = match cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(spki) => spki,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let output = match aead_common::output_buffer(output, output_len, spki.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&spki);
    unsafe {
        *written_len = spki.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn signature_algorithm_oid_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let cert = match Certificate::from_der(der) {
        Ok(cert) => cert,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_CERTIFICATE,
    };
    let oid = match cert.signature_algorithm.oid.to_der() {
        Ok(oid) => oid,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let output = match aead_common::output_buffer(output, output_len, oid.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&oid);
    unsafe {
        *written_len = oid.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn subject_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let cert = match Certificate::from_der(der) {
        Ok(cert) => cert,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_CERTIFICATE,
    };
    let subject = match cert.tbs_certificate.subject.to_der() {
        Ok(subject) => subject,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let output = match aead_common::output_buffer(output, output_len, subject.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&subject);
    unsafe {
        *written_len = subject.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn issuer_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let der = match certificate_bytes(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let cert = match Certificate::from_der(der) {
        Ok(cert) => cert,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_CERTIFICATE,
    };
    let issuer = match cert.tbs_certificate.issuer.to_der() {
        Ok(issuer) => issuer,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let output = match aead_common::output_buffer(output, output_len, issuer.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&issuer);
    unsafe {
        *written_len = issuer.len();
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_validate_der(der: *const u8, der_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_der_impl(der, der_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_from_pem(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        from_pem_impl(pem, pem_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_to_pem(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        to_pem_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_subject_public_key_info_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        subject_public_key_info_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_signature_algorithm_oid(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        signature_algorithm_oid_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_subject_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        subject_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_x509_cert_issuer_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        issuer_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RSA_PUBLIC_KEY_DER_MAX_LEN, RUSTCRYPTO_ERR_INVALID_CERTIFICATE, RUSTCRYPTO_OK};

    const RSA_2048_CERT_DER: &[u8] = include_bytes!("../tests/fixtures/rsa2048-cert.der");
    const RSA_2048_CERT_PEM: &[u8] = include_bytes!("../tests/fixtures/rsa2048-cert.pem");

    #[test]
    fn validate_der_rejects_empty_input() {
        let status = validate_der_impl(core::ptr::null(), 0);
        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_CERTIFICATE);
    }

    #[test]
    fn certificate_round_trip_from_pem_matches_der() {
        let mut der = [0u8; crate::X509_CERT_DER_MAX_LEN];
        let mut written = 0usize;
        let status = from_pem_impl(
            RSA_2048_CERT_PEM.as_ptr(),
            RSA_2048_CERT_PEM.len(),
            der.as_mut_ptr(),
            der.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(&der[..written], RSA_2048_CERT_DER);
    }

    #[test]
    fn certificate_to_pem_round_trip_matches_fixture() {
        let mut pem = [0u8; crate::X509_CERT_PEM_MAX_LEN];
        let mut written = 0usize;
        let status = to_pem_impl(
            RSA_2048_CERT_DER.as_ptr(),
            RSA_2048_CERT_DER.len(),
            pem.as_mut_ptr(),
            pem.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(&pem[..written], RSA_2048_CERT_PEM);
    }

    #[test]
    fn certificate_subject_public_key_info_matches_rsa_public_key_fixture() {
        let mut output = [0u8; RSA_PUBLIC_KEY_DER_MAX_LEN];
        let mut written = 0usize;
        let status = subject_public_key_info_der_impl(
            RSA_2048_CERT_DER.as_ptr(),
            RSA_2048_CERT_DER.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut normalized = [0u8; RSA_PUBLIC_KEY_DER_MAX_LEN];
        let mut normalized_written = 0usize;
        let status = crate::rsa::public_key_from_spki_der_impl(
            output.as_ptr(),
            written,
            normalized.as_mut_ptr(),
            normalized.len(),
            &mut normalized_written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert!(normalized_written > 0);
    }

    #[test]
    fn certificate_signature_algorithm_oid_is_rsa_encryption_oid() {
        let mut output = [0u8; 16];
        let mut written = 0usize;
        let status = signature_algorithm_oid_der_impl(
            RSA_2048_CERT_DER.as_ptr(),
            RSA_2048_CERT_DER.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert!(!output[..written].is_empty());
    }

    #[test]
    fn subject_der_rejects_invalid_der() {
        let der = [0u8, 1, 2, 3];
        let mut output = [0u8; 16];
        let mut written = 0usize;
        let status = subject_der_impl(
            der.as_ptr(),
            der.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_CERTIFICATE);
    }
}
