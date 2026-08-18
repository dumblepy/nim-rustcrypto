use crate::{
    HKDF_SHA256_MAX_OKM_LEN, HKDF_SHA256_PRK_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PRK_LENGTH, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_OK,
};
use ::hkdf::Hkdf;
use ::sha2::Sha256;
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn hkdf_optional_slice<'a>(input: *const u8, input_len: usize) -> Result<Option<&'a [u8]>, c_int> {
    if input_len == 0 {
        Ok(None)
    } else if input.is_null() {
        Err(crate::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(Some(unsafe {
            core::slice::from_raw_parts(input, input_len)
        }))
    }
}

fn hkdf_input_slice<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    if input_len == 0 {
        Ok(&[])
    } else if input.is_null() {
        Err(crate::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { core::slice::from_raw_parts(input, input_len) })
    }
}

fn hkdf_prk_slice<'a>(prk: *const u8, prk_len: usize) -> Result<&'a [u8], c_int> {
    if prk_len < HKDF_SHA256_PRK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PRK_LENGTH);
    }

    if prk.is_null() {
        Err(crate::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { core::slice::from_raw_parts(prk, prk_len) })
    }
}

pub(crate) fn hkdf_extract_impl(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < HKDF_SHA256_PRK_LEN {
        return crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let salt = match hkdf_optional_slice(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };
    let ikm = match hkdf_input_slice(ikm, ikm_len) {
        Ok(ikm) => ikm,
        Err(err) => return err,
    };

    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    let output = unsafe { core::slice::from_raw_parts_mut(output, HKDF_SHA256_PRK_LEN) };
    output.copy_from_slice(prk.as_ref());
    RUSTCRYPTO_OK
}

pub(crate) fn hkdf_expand_impl(
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len > HKDF_SHA256_MAX_OKM_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    let prk = match hkdf_prk_slice(prk, prk_len) {
        Ok(prk) => prk,
        Err(err) => return err,
    };
    let info = match hkdf_input_slice(info, info_len) {
        Ok(info) => info,
        Err(err) => return err,
    };

    let hkdf = match Hkdf::<Sha256>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PRK_LENGTH,
    };

    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    match hkdf.expand(info, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_LENGTH,
    }
}

pub(crate) fn hkdf_derive_impl(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len > HKDF_SHA256_MAX_OKM_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    let salt = match hkdf_optional_slice(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };
    let ikm = match hkdf_input_slice(ikm, ikm_len) {
        Ok(ikm) => ikm,
        Err(err) => return err,
    };
    let info = match hkdf_input_slice(info, info_len) {
        Ok(info) => info,
        Err(err) => return err,
    };

    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    match hkdf.expand(info, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_LENGTH,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_extract(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_extract_impl(salt, salt_len, ikm, ikm_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_expand(
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_expand_impl(prk, prk_len, info, info_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hkdf_sha256_derive(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hkdf_derive_impl(
            salt, salt_len, ikm, ikm_len, info, info_len, output, output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HKDF_SHA256_MAX_OKM_LEN, HKDF_SHA256_PRK_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
        RUSTCRYPTO_ERR_INVALID_PRK_LENGTH, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_OK,
    };

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
    fn hkdf_sha256_extract_matches_rfc_5869_case_1_prk() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let mut output = [0u8; HKDF_SHA256_PRK_LEN];

        let status = rustcrypto_hkdf_sha256_extract(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
    }

    #[test]
    fn hkdf_sha256_expand_rejects_short_prk() {
        let prk = [0x07u8; HKDF_SHA256_PRK_LEN - 1];
        let info = [0xf0u8; 10];
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_expand(
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PRK_LENGTH);
    }

    #[test]
    fn hkdf_sha256_derive_rejects_invalid_length() {
        let ikm = [0x0bu8; 22];
        let mut output = [0u8; 1];

        let status = rustcrypto_hkdf_sha256_derive(
            core::ptr::null(),
            0,
            ikm.as_ptr(),
            ikm.len(),
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            HKDF_SHA256_MAX_OKM_LEN + 1,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn hkdf_sha256_derive_rejects_null_ikm_with_data() {
        let mut output = [0u8; 42];

        let status = rustcrypto_hkdf_sha256_derive(
            core::ptr::null(),
            0,
            core::ptr::null(),
            1,
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
}
