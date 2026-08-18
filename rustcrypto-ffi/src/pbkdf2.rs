use crate::{
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

pub(crate) fn pbkdf2_hmac_sha256_impl(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if iterations == 0 {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
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

    let output = unsafe { slice::from_raw_parts_mut(output, derived_len) };
    pbkdf2_hmac::<Sha256>(password, salt, iterations, output);
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_pbkdf2_hmac_sha256(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        pbkdf2_hmac_sha256_impl(
            password,
            password_len,
            salt,
            salt_len,
            iterations,
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
    use crate::{RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_OUTPUT};

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

    #[test]
    fn derives_the_known_sha256_vector() {
        let password = b"password";
        let salt = b"salt";
        let mut output = [0u8; 32];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
                .as_slice()
        );
    }

    #[test]
    fn derives_the_known_two_round_vector() {
        let password = b"password";
        let salt = b"salt";
        let mut output = [0u8; 32];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            2,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
                .as_slice()
        );
    }

    #[test]
    fn derives_the_known_long_vector() {
        let password = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let mut output = [0u8; 40];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4096,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes(
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
            )
            .as_slice()
        );
    }

    #[test]
    fn derives_from_empty_password_and_salt() {
        let mut output = [0u8; 32];

        let status = pbkdf2_hmac_sha256_impl(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad")
                .as_slice()
        );
    }

    #[test]
    fn derives_with_empty_password_and_empty_salt_bytes() {
        let password = b"password";
        let mut output = [0u8; 32];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            b"".as_ptr(),
            0,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("c1232f10f62715fda06ae7c0a2037ca19b33cf103b727ba56d870c11f290a2ab")
                .as_slice()
        );
    }

    #[test]
    fn rejects_zero_iterations() {
        let password = b"password";
        let salt = b"salt";
        let mut output = [0u8; 32];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            0,
            output.as_mut_ptr(),
            output.len(),
            32,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn rejects_short_output_buffer() {
        let password = b"password";
        let salt = b"salt";
        let mut output = [0u8; 31];

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            output.as_mut_ptr(),
            output.len(),
            32,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn rejects_null_output() {
        let password = b"password";
        let salt = b"salt";

        let status = pbkdf2_hmac_sha256_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            core::ptr::null_mut(),
            32,
            32,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }
}
