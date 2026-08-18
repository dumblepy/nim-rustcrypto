use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK, aead_common,
};
use ::scrypt::{Params, scrypt as scrypt_derive};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

const SCRYPT_MAX_DERIVED_KEY_LEN: u64 = (u32::MAX as u64) * 32;

fn validate_n(n: usize) -> Result<u8, c_int> {
    if n < 2 || !n.is_power_of_two() {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    Ok(n.trailing_zeros() as u8)
}

fn validate_rs(r: usize, p: usize) -> Result<(u32, u32), c_int> {
    if r == 0 || p == 0 {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    if r > u32::MAX as usize || p > u32::MAX as usize {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    Ok((r as u32, p as u32))
}

pub(crate) fn scrypt_impl(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    n: usize,
    r: usize,
    p: usize,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if derived_len == 0 || (derived_len as u64) > SCRYPT_MAX_DERIVED_KEY_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    if output_len < derived_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let password = match aead_common::optional_input(password, password_len) {
        Ok(password) => password,
        Err(err) => return err,
    };
    let salt = match aead_common::optional_input(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };

    let log_n = match validate_n(n) {
        Ok(log_n) => log_n,
        Err(err) => return err,
    };
    let (r, p) = match validate_rs(r, p) {
        Ok(params) => params,
        Err(err) => return err,
    };
    let params = match Params::new(log_n, r, p) {
        Ok(params) => params,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    let output = unsafe { slice::from_raw_parts_mut(output, derived_len) };
    match scrypt_derive(password, salt, &params, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_scrypt(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    n: usize,
    r: usize,
    p: usize,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        scrypt_impl(
            password,
            password_len,
            salt,
            salt_len,
            n,
            r,
            p,
            output,
            output_len,
            derived_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
    };

    fn hex_of(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", byte).expect("write to string");
        }
        hex
    }

    #[test]
    fn derive_matches_known_vector_for_empty_inputs() {
        let mut output = [0u8; 64];
        let status = scrypt_impl(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            16,
            1,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            hex_of(&output),
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442".to_owned()
                + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        );
    }

    #[test]
    fn derive_matches_known_vector_for_password_and_salt() {
        let password = b"password";
        let salt = b"NaCl";
        let mut output = [0u8; 64];

        let status = scrypt_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1024,
            8,
            16,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            hex_of(&output),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162".to_owned()
                + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        );
    }

    #[test]
    fn derive_matches_known_vector_for_longer_password() {
        let password = b"pleaseletmein";
        let salt = b"SodiumChloride";
        let mut output = [0u8; 64];

        let status = scrypt_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            16384,
            8,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            hex_of(&output),
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2".to_owned()
                + "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
        );
    }

    #[test]
    fn derive_rejects_non_power_of_two_n() {
        let mut output = [0u8; 64];
        let status = scrypt_impl(
            b"password".as_ptr(),
            8,
            b"salt".as_ptr(),
            4,
            1000,
            1,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn derive_rejects_zero_output_length() {
        let mut output = [0u8; 1];
        let status = scrypt_impl(
            b"password".as_ptr(),
            8,
            b"salt".as_ptr(),
            4,
            16,
            1,
            1,
            output.as_mut_ptr(),
            output.len(),
            0,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn derive_rejects_short_output_buffer() {
        let mut output = [0u8; 63];
        let status = scrypt_impl(
            b"password".as_ptr(),
            8,
            b"salt".as_ptr(),
            4,
            16,
            1,
            1,
            output.as_mut_ptr(),
            output.len(),
            64,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
