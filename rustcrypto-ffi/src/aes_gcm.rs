use crate::{
    AES256GCM_KEY_LEN, AES256GCM_NONCE_LEN, AES256GCM_TAG_LEN,
    RUSTCRYPTO_ERR_AUTHENTICATION_FAILED, RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_TAG_LENGTH, RUSTCRYPTO_OK, aead_common,
};
use ::aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit as AeadKeyInit};
use ::aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

type Aes256GcmKey = Key<Aes256Gcm>;
type Aes256GcmNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;
type Aes256GcmTag = Tag<<Aes256Gcm as AeadCore>::TagSize>;

fn aes256gcm_key(bytes: &[u8]) -> Aes256GcmKey {
    bytes.iter().copied().collect()
}

fn aes256gcm_nonce(bytes: &[u8]) -> Aes256GcmNonce {
    bytes.iter().copied().collect()
}

fn aes256gcm_tag(bytes: &[u8]) -> Aes256GcmTag {
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
        AES256GCM_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        AES256GCM_NONCE_LEN,
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

    let tag = match aead_common::output_buffer(tag, tag_len, AES256GCM_TAG_LEN) {
        Ok(tag) => tag,
        Err(err) => return err,
    };

    let key = aes256gcm_key(&key);
    let nonce = aes256gcm_nonce(&nonce);
    let cipher = Aes256Gcm::new(&key);
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
        AES256GCM_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
    ) {
        Ok(key) => key.to_vec(),
        Err(err) => return err,
    };

    let nonce = match aead_common::fixed_input(
        nonce,
        nonce_len,
        AES256GCM_NONCE_LEN,
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
        AES256GCM_TAG_LEN,
        RUSTCRYPTO_ERR_INVALID_TAG_LENGTH,
    ) {
        Ok(tag) => tag.to_vec(),
        Err(err) => return err,
    };

    let plaintext = match aead_common::output_buffer(plaintext, plaintext_len, ciphertext_len) {
        Ok(plaintext) => plaintext,
        Err(err) => return err,
    };

    let key = aes256gcm_key(&key);
    let nonce = aes256gcm_nonce(&nonce);
    let cipher = Aes256Gcm::new(&key);
    plaintext.copy_from_slice(&ciphertext);

    let tag = aes256gcm_tag(&tag);
    match cipher.decrypt_in_place_detached(&nonce, &aad, plaintext, &tag) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_AUTHENTICATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_aes256gcm_encrypt(
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
pub extern "C" fn rustcrypto_aes256gcm_decrypt(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_AUTHENTICATION_FAILED, RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
    };

    fn hex_bytes(hex: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        }

        assert_eq!(hex.len() % 2, 0);
        let bytes = hex.as_bytes();
        let mut output = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            output.push((nibble(bytes[index]) << 4) | nibble(bytes[index + 1]));
            index += 2;
        }
        output
    }

    fn digest_hex(bytes: &[u8]) -> String {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(char::from(HEX_DIGITS[(byte >> 4) as usize]));
            output.push(char::from(HEX_DIGITS[(byte & 0x0f) as usize]));
        }
        output
    }

    #[test]
    fn encrypt_matches_nist_vector() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; AES256GCM_TAG_LEN];

        let status = rustcrypto_aes256gcm_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            tag.as_mut_ptr(),
            tag.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&ciphertext),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        assert_eq!(digest_hex(&tag), "76fc6ece0f4e1768cddf8853bb2d551b");
    }

    #[test]
    fn decrypt_matches_nist_vector() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ciphertext = hex_bytes(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        let tag = hex_bytes("76fc6ece0f4e1768cddf8853bb2d551b");
        let mut plaintext = vec![0u8; ciphertext.len()];

        let status = rustcrypto_aes256gcm_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            tag.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&plaintext),
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
    }

    #[test]
    fn decrypt_rejects_tampered_tag() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ciphertext = hex_bytes(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        let mut tag = hex_bytes("76fc6ece0f4e1768cddf8853bb2d551b");
        let mut plaintext = vec![0u8; ciphertext.len()];
        tag[0] ^= 0x01;

        let status = rustcrypto_aes256gcm_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            tag.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_AUTHENTICATION_FAILED);
    }

    #[test]
    fn encrypt_rejects_short_output_buffer() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let mut ciphertext = vec![0u8; plaintext.len() - 1];
        let mut tag = [0u8; AES256GCM_TAG_LEN];

        let status = rustcrypto_aes256gcm_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            tag.as_mut_ptr(),
            tag.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn encrypt_rejects_invalid_key_length() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308");
        let nonce = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; AES256GCM_TAG_LEN];

        let status = rustcrypto_aes256gcm_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            tag.as_mut_ptr(),
            tag.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
    }
}
