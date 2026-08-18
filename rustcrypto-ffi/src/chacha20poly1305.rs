use crate::{
    CHACHA20POLY1305_KEY_LEN, CHACHA20POLY1305_NONCE_LEN, CHACHA20POLY1305_TAG_LEN,
    RUSTCRYPTO_ERR_AUTHENTICATION_FAILED, RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_TAG_LENGTH, RUSTCRYPTO_OK, aead_common,
};
use ::chacha20poly1305::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use ::chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn chacha20poly1305_key(bytes: &[u8]) -> Key {
    bytes.iter().copied().collect()
}

fn chacha20poly1305_nonce(bytes: &[u8]) -> Nonce {
    bytes.iter().copied().collect()
}

fn chacha20poly1305_tag(bytes: &[u8]) -> Tag {
    bytes.iter().copied().collect()
}

pub(crate) fn encrypt_impl(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    tag: *mut u8,
    tag_len: usize,
) -> c_int {
    let key = match aead_common::fixed_input(
        key,
        key_len,
        CHACHA20POLY1305_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        CHACHA20POLY1305_NONCE_LEN,
        RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
    ) {
        Ok(nonce) => nonce.to_vec(),
        Err(err) => return err,
    };

    let aad = match aead_common::optional_input(aad, aad_len) {
        Ok(aad) => aad.to_vec(),
        Err(err) => return err,
    };

    let plaintext = match aead_common::optional_input(plaintext, plaintext_len) {
        Ok(plaintext) => plaintext.to_vec(),
        Err(err) => return err,
    };

    let ciphertext = match aead_common::output_buffer(ciphertext, ciphertext_len, plaintext_len) {
        Ok(ciphertext) => ciphertext,
        Err(err) => return err,
    };

    let tag = match aead_common::output_buffer(tag, tag_len, CHACHA20POLY1305_TAG_LEN) {
        Ok(tag) => tag,
        Err(err) => return err,
    };

    let key = chacha20poly1305_key(&key);
    let nonce = chacha20poly1305_nonce(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    ciphertext.copy_from_slice(&plaintext);

    let tag_bytes = match cipher.encrypt_in_place_detached(&nonce, &aad, ciphertext) {
        Ok(tag_bytes) => tag_bytes,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    tag.copy_from_slice(&tag_bytes);
    RUSTCRYPTO_OK
}

pub(crate) fn decrypt_impl(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext: *mut u8,
    plaintext_len: usize,
) -> c_int {
    let key = match aead_common::fixed_input(
        key,
        key_len,
        CHACHA20POLY1305_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        CHACHA20POLY1305_NONCE_LEN,
        RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
    ) {
        Ok(nonce) => nonce.to_vec(),
        Err(err) => return err,
    };

    let aad = match aead_common::optional_input(aad, aad_len) {
        Ok(aad) => aad.to_vec(),
        Err(err) => return err,
    };

    let ciphertext = match aead_common::optional_input(ciphertext, ciphertext_len) {
        Ok(ciphertext) => ciphertext.to_vec(),
        Err(err) => return err,
    };

    let tag = match aead_common::fixed_input(
        tag,
        tag_len,
        CHACHA20POLY1305_TAG_LEN,
        RUSTCRYPTO_ERR_INVALID_TAG_LENGTH,
    ) {
        Ok(tag) => tag.to_vec(),
        Err(err) => return err,
    };

    let plaintext = match aead_common::output_buffer(plaintext, plaintext_len, ciphertext_len) {
        Ok(plaintext) => plaintext,
        Err(err) => return err,
    };

    let key = chacha20poly1305_key(&key);
    let nonce = chacha20poly1305_nonce(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    plaintext.copy_from_slice(&ciphertext);

    let tag = chacha20poly1305_tag(&tag);
    match cipher.decrypt_in_place_detached(&nonce, &aad, plaintext, &tag) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_AUTHENTICATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_chacha20poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    tag: *mut u8,
    tag_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        encrypt_impl(
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext,
            ciphertext_len,
            tag,
            tag_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_chacha20poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext: *mut u8,
    plaintext_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        decrypt_impl(
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            tag,
            tag_len,
            plaintext,
            plaintext_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}
