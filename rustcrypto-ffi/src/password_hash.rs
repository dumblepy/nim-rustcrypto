use crate::{
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use password_hash::phc::PasswordHash;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

fn parse_password_hash(input: *const u8, input_len: usize) -> Result<PasswordHash, c_int> {
    let input = match aead_common::optional_input(input, input_len) {
        Ok(input) => input,
        Err(err) => return Err(err),
    };

    let input = match core::str::from_utf8(input) {
        Ok(input) => input,
        Err(_) => return Err(RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT),
    };

    PasswordHash::new(input).map_err(|_| RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT)
}

pub(crate) fn validate_impl(input: *const u8, input_len: usize) -> c_int {
    match parse_password_hash(input, input_len) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

pub(crate) fn canonicalize_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    let password_hash = match parse_password_hash(input, input_len) {
        Ok(password_hash) => password_hash,
        Err(err) => return err,
    };

    let canonical = password_hash.to_string();
    let canonical_bytes = canonical.as_bytes();
    if output_len < canonical_bytes.len() {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let output = unsafe { slice::from_raw_parts_mut(output, canonical_bytes.len()) };
    output.copy_from_slice(canonical_bytes);

    unsafe {
        *written_len = canonical_bytes.len();
    }

    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_password_hash_validate(input: *const u8, input_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_impl(input, input_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_password_hash_canonicalize(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        canonicalize_impl(input, input_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
    };

    #[test]
    fn validate_accepts_known_argon2_phc_string() {
        let phc = "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ";

        let status = validate_impl(phc.as_ptr(), phc.len());

        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn validate_accepts_known_scrypt_phc_string() {
        let phc = "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0";

        let status = validate_impl(phc.as_ptr(), phc.len());

        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn canonicalize_round_trips_known_argon2_phc_string() {
        let phc = "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ";
        let mut output = [0u8; 96];
        let mut written_len = 0usize;

        let status = canonicalize_impl(
            phc.as_ptr(),
            phc.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, phc.len());
        assert_eq!(&output[..written_len], phc.as_bytes());
    }

    #[test]
    fn canonicalize_round_trips_known_scrypt_phc_string() {
        let phc = "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0";
        let mut output = [0u8; 96];
        let mut written_len = 0usize;

        let status = canonicalize_impl(
            phc.as_ptr(),
            phc.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, phc.len());
        assert_eq!(&output[..written_len], phc.as_bytes());
    }

    #[test]
    fn canonicalize_rejects_invalid_phc_string() {
        let phc = "argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ";
        let mut output = [0u8; 96];
        let mut written_len = 0usize;

        let status = canonicalize_impl(
            phc.as_ptr(),
            phc.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT);
    }

    #[test]
    fn canonicalize_rejects_short_output_buffer() {
        let phc = "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ";
        let mut output = [0u8; 10];
        let mut written_len = 0usize;

        let status = canonicalize_impl(
            phc.as_ptr(),
            phc.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
