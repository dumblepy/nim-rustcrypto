use crate::{
    BCRYPT_HASH_LEN, BCRYPT_MAX_COST, BCRYPT_MIN_COST, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_RANDOM_FAILED,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use ::bcrypt::{BcryptError, HashParts, non_truncating_hash_bytes, non_truncating_verify};
use core::ffi::c_int;
use core::str::FromStr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

fn map_bcrypt_error(err: BcryptError) -> c_int {
    match err {
        BcryptError::CostNotAllowed(_) => RUSTCRYPTO_ERR_INVALID_PARAMETER,
        BcryptError::InvalidHash(_) => RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
        BcryptError::Rand(_) => RUSTCRYPTO_ERR_RANDOM_FAILED,
        BcryptError::Truncation(_) => RUSTCRYPTO_ERR_INVALID_LENGTH,
    }
}

fn parse_hash(hash: *const u8, hash_len: usize) -> Result<HashParts, c_int> {
    let hash = aead_common::optional_input(hash, hash_len)?;
    let hash =
        core::str::from_utf8(hash).map_err(|_| RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT)?;
    let parsed =
        HashParts::from_str(hash).map_err(|_| RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT)?;

    if parsed.get_cost() < BCRYPT_MIN_COST || parsed.get_cost() > BCRYPT_MAX_COST {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    Ok(parsed)
}

pub(crate) fn hash_password_impl(
    password: *const u8,
    password_len: usize,
    cost: u32,
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

    let password = match aead_common::optional_input(password, password_len) {
        Ok(password) => password,
        Err(err) => return err,
    };

    let hash = match non_truncating_hash_bytes(password, cost) {
        Ok(hash) => hash,
        Err(err) => return map_bcrypt_error(err),
    };

    if output_len < BCRYPT_HASH_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let output = unsafe { slice::from_raw_parts_mut(output, BCRYPT_HASH_LEN) };
    output.copy_from_slice(&hash);

    unsafe {
        *written_len = BCRYPT_HASH_LEN;
    }

    RUSTCRYPTO_OK
}

pub(crate) fn verify_password_impl(
    password: *const u8,
    password_len: usize,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    let password = match aead_common::optional_input(password, password_len) {
        Ok(password) => password,
        Err(err) => return err,
    };
    let hash = match aead_common::optional_input(hash, hash_len) {
        Ok(hash) => hash,
        Err(err) => return err,
    };
    let hash = match core::str::from_utf8(hash) {
        Ok(hash) => hash,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    };

    match non_truncating_verify(password, hash) {
        Ok(true) => RUSTCRYPTO_OK,
        Ok(false) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        Err(err) => map_bcrypt_error(err),
    }
}

pub(crate) fn validate_hash_impl(hash: *const u8, hash_len: usize) -> c_int {
    match parse_hash(hash, hash_len) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

pub(crate) fn cost_impl(hash: *const u8, hash_len: usize, cost: *mut u32) -> c_int {
    if cost.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    let parsed = match parse_hash(hash, hash_len) {
        Ok(parsed) => parsed,
        Err(err) => return err,
    };

    unsafe {
        *cost = parsed.get_cost();
    }

    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_hash_password(
    password: *const u8,
    password_len: usize,
    cost: u32,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hash_password_impl(
            password,
            password_len,
            cost,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_verify_password(
    password: *const u8,
    password_len: usize,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_password_impl(password, password_len, hash, hash_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_validate_hash(hash: *const u8, hash_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_hash_impl(hash, hash_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_cost(
    hash: *const u8,
    hash_len: usize,
    cost: *mut u32,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| cost_impl(hash, hash_len, cost)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
        RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    };

    const KNOWN_HASH: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

    #[test]
    fn verify_accepts_known_bcrypt_hash() {
        let password = b"correctbatteryhorsestapler";

        let status = verify_password_impl(
            password.as_ptr(),
            password.len(),
            KNOWN_HASH.as_ptr(),
            KNOWN_HASH.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn verify_returns_verification_failed_for_wrong_password() {
        let password = b"wrong";

        let status = verify_password_impl(
            password.as_ptr(),
            password.len(),
            KNOWN_HASH.as_ptr(),
            KNOWN_HASH.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }

    #[test]
    fn hash_password_generates_verifiable_two_b_hash() {
        let password = b"password";
        let mut output = [0u8; BCRYPT_HASH_LEN];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            BCRYPT_MIN_COST,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, BCRYPT_HASH_LEN);
        assert_eq!(&output[..4], b"$2b$");

        let status = verify_password_impl(
            password.as_ptr(),
            password.len(),
            output.as_ptr(),
            written_len,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn hash_password_rejects_invalid_cost() {
        let password = b"password";
        let mut output = [0u8; BCRYPT_HASH_LEN];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            BCRYPT_MIN_COST - 1,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn hash_password_rejects_truncating_password() {
        let password = [b'x'; 72];
        let mut output = [0u8; BCRYPT_HASH_LEN];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            BCRYPT_MIN_COST,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn hash_password_rejects_short_output_buffer() {
        let password = b"password";
        let mut output = [0u8; 10];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            BCRYPT_MIN_COST,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn validate_hash_rejects_malformed_hash() {
        let hash = b"not-bcrypt";

        let status = validate_hash_impl(hash.as_ptr(), hash.len());

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT);
    }

    #[test]
    fn cost_reads_work_factor() {
        let mut cost = 0u32;

        let status = cost_impl(KNOWN_HASH.as_ptr(), KNOWN_HASH.len(), &mut cost);

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(cost, 4);
    }
}
