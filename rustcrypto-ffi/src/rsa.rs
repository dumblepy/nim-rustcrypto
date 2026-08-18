#[cfg(target_arch = "wasm32")]
use crate::RUSTCRYPTO_ERR_RANDOM_FAILED;
use crate::{
    RUSTCRYPTO_ERR_DECRYPTION_FAILED, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
#[cfg(not(target_arch = "wasm32"))]
use rand_core::OsRng;
#[cfg(not(target_arch = "wasm32"))]
use rsa::pss::SigningKey as PssSigningKey;
#[cfg(not(target_arch = "wasm32"))]
use rsa::signature::hazmat::RandomizedPrehashSigner;
use rsa::{
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{
        Signature as Pkcs1v15Signature, SigningKey as Pkcs1v15SigningKey,
        VerifyingKey as Pkcs1v15VerifyingKey,
    },
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    sha2::{Digest, Sha256},
    signature::{
        SignatureEncoding,
        hazmat::{PrehashSigner, PrehashVerifier},
    },
    traits::PublicKeyParts,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn optional_label<'a>(label: *const u8, label_len: usize) -> Result<Option<&'a [u8]>, c_int> {
    if label_len == 0 {
        Ok(None)
    } else if label.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(Some(unsafe {
            core::slice::from_raw_parts(label, label_len)
        }))
    }
}

fn utf8_label<'a>(label: *const u8, label_len: usize) -> Result<Option<&'a str>, c_int> {
    let label = optional_label(label, label_len)?;
    match label {
        None => Ok(None),
        Some(label) => match core::str::from_utf8(label) {
            Ok(label) if label.is_empty() => Ok(None),
            Ok(label) => Ok(Some(label)),
            Err(_) => Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        },
    }
}

fn private_key_bytes<'a>(der: *const u8, der_len: usize) -> Result<&'a [u8], c_int> {
    aead_common::optional_input(der, der_len)
}

fn public_key_bytes<'a>(der: *const u8, der_len: usize) -> Result<&'a [u8], c_int> {
    aead_common::optional_input(der, der_len)
}

fn parse_private_key(der: *const u8, der_len: usize) -> Result<RsaPrivateKey, c_int> {
    let der = private_key_bytes(der, der_len)?;
    RsaPrivateKey::from_pkcs8_der(der).map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

fn parse_public_key(der: *const u8, der_len: usize) -> Result<RsaPublicKey, c_int> {
    let der = public_key_bytes(der, der_len)?;
    RsaPublicKey::from_public_key_der(der).map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

fn map_sign_verify_error(err: rsa::errors::Error) -> c_int {
    match err {
        rsa::errors::Error::Verification => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        rsa::errors::Error::MessageTooLong => RUSTCRYPTO_ERR_INVALID_LENGTH,
        rsa::errors::Error::InvalidArguments
        | rsa::errors::Error::InvalidPadLen
        | rsa::errors::Error::LabelTooLong
        | rsa::errors::Error::Pkcs1(_)
        | rsa::errors::Error::Pkcs8(_)
        | rsa::errors::Error::InvalidPrime
        | rsa::errors::Error::InvalidModulus
        | rsa::errors::Error::InvalidExponent
        | rsa::errors::Error::InvalidCoefficient
        | rsa::errors::Error::ModulusTooLarge
        | rsa::errors::Error::PublicExponentTooSmall
        | rsa::errors::Error::PublicExponentTooLarge
        | rsa::errors::Error::NprimesTooSmall
        | rsa::errors::Error::TooFewPrimes
        | rsa::errors::Error::Internal => RUSTCRYPTO_ERR_INVALID_PARAMETER,
        rsa::errors::Error::InputNotHashed => RUSTCRYPTO_ERR_INVALID_PARAMETER,
        rsa::errors::Error::Decryption => RUSTCRYPTO_ERR_DECRYPTION_FAILED,
        _ => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn map_encrypt_error(err: rsa::errors::Error) -> c_int {
    match err {
        rsa::errors::Error::MessageTooLong => RUSTCRYPTO_ERR_INVALID_LENGTH,
        rsa::errors::Error::Decryption => RUSTCRYPTO_ERR_DECRYPTION_FAILED,
        _ => map_sign_verify_error(err),
    }
}

fn map_decrypt_error(err: rsa::errors::Error) -> c_int {
    match err {
        rsa::errors::Error::Decryption
        | rsa::errors::Error::InvalidPadLen
        | rsa::errors::Error::LabelTooLong => RUSTCRYPTO_ERR_DECRYPTION_FAILED,
        rsa::errors::Error::MessageTooLong => RUSTCRYPTO_ERR_INVALID_LENGTH,
        _ => map_sign_verify_error(err),
    }
}

fn digest_message(message: *const u8, message_len: usize) -> Result<[u8; 32], c_int> {
    let message = aead_common::optional_input(message, message_len)?;
    let digest = Sha256::digest(message);
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn derive_pss_signature(private_key: &RsaPrivateKey, digest: &[u8]) -> Result<PssSignature, c_int> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (private_key, digest);
        return Err(crate::RUSTCRYPTO_ERR_RANDOM_FAILED);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let signing_key = PssSigningKey::<Sha256>::new(private_key.clone());
        signing_key
            .sign_prehash_with_rng(&mut OsRng, digest)
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
    }
}

fn verify_pss_signature(
    public_key: &RsaPublicKey,
    digest: &[u8],
    signature: &PssSignature,
) -> Result<(), c_int> {
    let verifying_key = PssVerifyingKey::<Sha256>::new(public_key.clone());
    verifying_key
        .verify_prehash(digest, signature)
        .map_err(|_| RUSTCRYPTO_ERR_VERIFICATION_FAILED)
}

fn derive_pkcs1v15_signature(
    private_key: &RsaPrivateKey,
    digest: &[u8],
) -> Result<Pkcs1v15Signature, c_int> {
    let signing_key = Pkcs1v15SigningKey::<Sha256>::new(private_key.clone());
    signing_key
        .sign_prehash(digest)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

fn verify_pkcs1v15_signature(
    public_key: &RsaPublicKey,
    digest: &[u8],
    signature: &Pkcs1v15Signature,
) -> Result<(), c_int> {
    let verifying_key = Pkcs1v15VerifyingKey::<Sha256>::new(public_key.clone());
    verifying_key
        .verify_prehash(digest, signature)
        .map_err(|_| RUSTCRYPTO_ERR_VERIFICATION_FAILED)
}

fn write_der(output: *mut u8, output_len: usize, written_len: *mut usize, der: &[u8]) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let output = match aead_common::output_buffer(output, output_len, der.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(der);
    unsafe {
        *written_len = der.len();
    }
    RUSTCRYPTO_OK
}

fn normalize_private_key_der(private_key: &RsaPrivateKey) -> Result<Vec<u8>, c_int> {
    private_key
        .to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

fn normalize_public_key_der(public_key: &RsaPublicKey) -> Result<Vec<u8>, c_int> {
    public_key
        .to_public_key_der()
        .map(|doc| doc.as_ref().to_vec())
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

pub(crate) fn private_key_to_pkcs8_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    let private_key = match parse_private_key(der, der_len) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };
    let der = match normalize_private_key_der(&private_key) {
        Ok(der) => der,
        Err(err) => return err,
    };
    write_der(output, output_len, written_len, &der)
}

pub(crate) fn private_key_from_pkcs8_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    private_key_to_pkcs8_der_impl(der, der_len, output, output_len, written_len)
}

pub(crate) fn public_key_to_spki_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    let public_key = match parse_public_key(der, der_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };
    let der = match normalize_public_key_der(&public_key) {
        Ok(der) => der,
        Err(err) => return err,
    };
    write_der(output, output_len, written_len, &der)
}

pub(crate) fn public_key_from_spki_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    public_key_to_spki_der_impl(der, der_len, output, output_len, written_len)
}

pub(crate) fn rsa_pss_sign_sha256_impl(
    message: *const u8,
    message_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    let private_key = match parse_private_key(private_key_der, private_key_der_len) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };
    let signature = match derive_pss_signature(&private_key, &message_digest) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    let signature_bytes = signature.to_bytes();
    let required_len = private_key.size();
    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };
    output.copy_from_slice(signature_bytes.as_ref());
    unsafe {
        *written_len = signature_bytes.as_ref().len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn rsa_pss_verify_sha256_impl(
    message: *const u8,
    message_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    let public_key = match parse_public_key(public_key_der, public_key_der_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };
    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        public_key.size(),
        crate::RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    let signature = match PssSignature::try_from(signature) {
        Ok(signature) => signature,
        Err(_) => return crate::RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };
    match verify_pss_signature(&public_key, &message_digest, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

pub(crate) fn rsa_pkcs1v15_sign_sha256_impl(
    message: *const u8,
    message_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    let private_key = match parse_private_key(private_key_der, private_key_der_len) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };
    let signature = match derive_pkcs1v15_signature(&private_key, &message_digest) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    let signature_bytes = signature.to_bytes();
    let required_len = private_key.size();
    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };
    output.copy_from_slice(signature_bytes.as_ref());
    unsafe {
        *written_len = signature_bytes.as_ref().len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn rsa_pkcs1v15_verify_sha256_impl(
    message: *const u8,
    message_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    let public_key = match parse_public_key(public_key_der, public_key_der_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };
    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        public_key.size(),
        crate::RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    let signature = match Pkcs1v15Signature::try_from(signature) {
        Ok(signature) => signature,
        Err(_) => return crate::RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };
    match verify_pkcs1v15_signature(&public_key, &message_digest, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

pub(crate) fn rsa_oaep_sha256_encrypt_impl(
    plaintext: *const u8,
    plaintext_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    label: *const u8,
    label_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let plaintext = match aead_common::optional_input(plaintext, plaintext_len) {
        Ok(plaintext) => plaintext,
        Err(err) => return err,
    };
    let public_key = match parse_public_key(public_key_der, public_key_der_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };
    let label = match utf8_label(label, label_len) {
        Ok(label) => label,
        Err(err) => return err,
    };

    #[cfg(target_arch = "wasm32")]
    {
        let _ = (plaintext, public_key, label, output_len);
        return RUSTCRYPTO_ERR_RANDOM_FAILED;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let padding = match label {
            Some(label) => Oaep::new_with_label::<Sha256, _>(label),
            None => Oaep::new::<Sha256>(),
        };
        let ciphertext = match public_key.encrypt(&mut OsRng, padding, plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(err) => return map_encrypt_error(err),
        };

        let output = match aead_common::output_buffer(output, output_len, ciphertext.len()) {
            Ok(output) => output,
            Err(err) => return err,
        };
        output.copy_from_slice(&ciphertext);
        unsafe {
            *written_len = ciphertext.len();
        }
        RUSTCRYPTO_OK
    }
}

pub(crate) fn rsa_oaep_sha256_decrypt_impl(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    label: *const u8,
    label_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let ciphertext = match aead_common::optional_input(ciphertext, ciphertext_len) {
        Ok(ciphertext) => ciphertext,
        Err(err) => return err,
    };
    let private_key = match parse_private_key(private_key_der, private_key_der_len) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };
    let label = match utf8_label(label, label_len) {
        Ok(label) => label,
        Err(err) => return err,
    };
    let padding = match label {
        Some(label) => Oaep::new_with_label::<Sha256, _>(label),
        None => Oaep::new::<Sha256>(),
    };
    let plaintext = match private_key.decrypt(padding, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(err) => return map_decrypt_error(err),
    };
    let output = match aead_common::output_buffer(output, output_len, plaintext.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&plaintext);
    unsafe {
        *written_len = plaintext.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn rsa_pkcs1v15_encrypt_impl(
    plaintext: *const u8,
    plaintext_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let plaintext = match aead_common::optional_input(plaintext, plaintext_len) {
        Ok(plaintext) => plaintext,
        Err(err) => return err,
    };
    let public_key = match parse_public_key(public_key_der, public_key_der_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (plaintext, public_key, output_len);
        return RUSTCRYPTO_ERR_RANDOM_FAILED;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let ciphertext = match public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(err) => return map_encrypt_error(err),
        };
        let output = match aead_common::output_buffer(output, output_len, ciphertext.len()) {
            Ok(output) => output,
            Err(err) => return err,
        };
        output.copy_from_slice(&ciphertext);
        unsafe {
            *written_len = ciphertext.len();
        }
        RUSTCRYPTO_OK
    }
}

pub(crate) fn rsa_pkcs1v15_decrypt_impl(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let ciphertext = match aead_common::optional_input(ciphertext, ciphertext_len) {
        Ok(ciphertext) => ciphertext,
        Err(err) => return err,
    };
    let private_key = match parse_private_key(private_key_der, private_key_der_len) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };
    let plaintext = match private_key.decrypt(Pkcs1v15Encrypt, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(err) => return map_decrypt_error(err),
    };
    let output = match aead_common::output_buffer(output, output_len, plaintext.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&plaintext);
    unsafe {
        *written_len = plaintext.len();
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_private_key_to_pkcs8_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_to_pkcs8_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_private_key_from_pkcs8_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_from_pkcs8_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_public_key_to_spki_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_to_spki_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_public_key_from_spki_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_spki_der_impl(der, der_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pss_sign_sha256(
    message: *const u8,
    message_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pss_sign_sha256_impl(
            message,
            message_len,
            private_key_der,
            private_key_der_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pss_verify_sha256(
    message: *const u8,
    message_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pss_verify_sha256_impl(
            message,
            message_len,
            public_key_der,
            public_key_der_len,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pkcs1v15_sign_sha256(
    message: *const u8,
    message_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pkcs1v15_sign_sha256_impl(
            message,
            message_len,
            private_key_der,
            private_key_der_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pkcs1v15_verify_sha256(
    message: *const u8,
    message_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pkcs1v15_verify_sha256_impl(
            message,
            message_len,
            public_key_der,
            public_key_der_len,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_oaep_sha256_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    label: *const u8,
    label_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_oaep_sha256_encrypt_impl(
            plaintext,
            plaintext_len,
            public_key_der,
            public_key_der_len,
            label,
            label_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_oaep_sha256_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    label: *const u8,
    label_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_oaep_sha256_decrypt_impl(
            ciphertext,
            ciphertext_len,
            private_key_der,
            private_key_der_len,
            label,
            label_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pkcs1v15_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    public_key_der: *const u8,
    public_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pkcs1v15_encrypt_impl(
            plaintext,
            plaintext_len,
            public_key_der,
            public_key_der_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_rsa_pkcs1v15_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key_der: *const u8,
    private_key_der_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        rsa_pkcs1v15_decrypt_impl(
            ciphertext,
            ciphertext_len,
            private_key_der,
            private_key_der_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RSA_PRIVATE_KEY_DER_MAX_LEN, RSA_PUBLIC_KEY_DER_MAX_LEN, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        RUSTCRYPTO_OK,
    };

    const RSA_2048_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../tests/fixtures/rsa2048-private-key.der");
    const RSA_2048_PUBLIC_KEY_DER: &[u8] =
        include_bytes!("../tests/fixtures/rsa2048-public-key.der");

    #[test]
    fn private_key_der_round_trip_normalizes_example() {
        let mut output = [0u8; RSA_PRIVATE_KEY_DER_MAX_LEN];
        let mut written = 0usize;
        let status = private_key_to_pkcs8_der_impl(
            RSA_2048_PRIVATE_KEY_DER.as_ptr(),
            RSA_2048_PRIVATE_KEY_DER.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert!(!output[..written].is_empty());
    }

    #[test]
    fn public_key_der_round_trip_normalizes_example() {
        let mut output = [0u8; RSA_PUBLIC_KEY_DER_MAX_LEN];
        let mut written = 0usize;
        let status = public_key_to_spki_der_impl(
            RSA_2048_PUBLIC_KEY_DER.as_ptr(),
            RSA_2048_PUBLIC_KEY_DER.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert!(!output[..written].is_empty());
    }

    #[test]
    fn pss_verify_rejects_tampered_signature() {
        let message = b"abc";
        let mut signature = [0u8; 256];
        let mut written = 0usize;
        let status = rsa_pss_sign_sha256_impl(
            message.as_ptr(),
            message.len(),
            RSA_2048_PRIVATE_KEY_DER.as_ptr(),
            RSA_2048_PRIVATE_KEY_DER.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        signature[0] ^= 0x01;
        let status = rsa_pss_verify_sha256_impl(
            message.as_ptr(),
            message.len(),
            RSA_2048_PUBLIC_KEY_DER.as_ptr(),
            RSA_2048_PUBLIC_KEY_DER.len(),
            signature.as_ptr(),
            written,
        );
        assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }

    #[test]
    fn oaep_round_trip_with_label() {
        let message = b"abc";
        let label = b"label";
        let mut ciphertext = [0u8; 256];
        let mut written = 0usize;
        let status = rsa_oaep_sha256_encrypt_impl(
            message.as_ptr(),
            message.len(),
            RSA_2048_PUBLIC_KEY_DER.as_ptr(),
            RSA_2048_PUBLIC_KEY_DER.len(),
            label.as_ptr(),
            label.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut plaintext = [0u8; 256];
        let mut plaintext_written = 0usize;
        let status = rsa_oaep_sha256_decrypt_impl(
            ciphertext.as_ptr(),
            written,
            RSA_2048_PRIVATE_KEY_DER.as_ptr(),
            RSA_2048_PRIVATE_KEY_DER.len(),
            label.as_ptr(),
            label.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut plaintext_written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(&plaintext[..plaintext_written], message);
    }

    #[test]
    fn short_output_buffer_is_rejected() {
        let message = b"abc";
        let mut signature = [0u8; 8];
        let mut written = 0usize;
        let status = rsa_pkcs1v15_sign_sha256_impl(
            message.as_ptr(),
            message.len(),
            RSA_2048_PRIVATE_KEY_DER.as_ptr(),
            RSA_2048_PRIVATE_KEY_DER.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
