use crate::{
    ARGON2ID_MAX_HASH_LEN, ARGON2ID_MIN_HASH_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use ::argon2::password_hash::SaltString;
use ::argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

fn build_argon2id_ctx(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    hash_len: usize,
) -> Result<Argon2<'static>, c_int> {
    if hash_len < ARGON2ID_MIN_HASH_LEN || hash_len > ARGON2ID_MAX_HASH_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    let params = match Params::new(m_cost, t_cost, p_cost, Some(hash_len)) {
        Ok(params) => params,
        Err(_) => return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
    };

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn hash_password_impl(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    hash_len: usize,
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
    let salt = match aead_common::optional_input(salt, salt_len) {
        Ok(salt) => salt,
        Err(err) => return err,
    };

    let ctx = match build_argon2id_ctx(m_cost, t_cost, p_cost, hash_len) {
        Ok(ctx) => ctx,
        Err(err) => return err,
    };

    let salt = match SaltString::encode_b64(salt) {
        Ok(salt) => salt,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    let password_hash = match ctx.hash_password(password, &salt) {
        Ok(password_hash) => password_hash,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    let phc = password_hash.to_string();
    let required_len = phc.len();
    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let output = unsafe { slice::from_raw_parts_mut(output, required_len) };
    output.copy_from_slice(phc.as_bytes());

    unsafe {
        *written_len = required_len;
    }

    RUSTCRYPTO_OK
}

pub(crate) fn verify_password_impl(
    password: *const u8,
    password_len: usize,
    phc: *const u8,
    phc_len: usize,
) -> c_int {
    let password = match aead_common::optional_input(password, password_len) {
        Ok(password) => password,
        Err(err) => return err,
    };
    let phc = match aead_common::optional_input(phc, phc_len) {
        Ok(phc) => phc,
        Err(err) => return err,
    };

    let phc = match core::str::from_utf8(phc) {
        Ok(phc) => phc,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    };

    let parsed = match PasswordHash::new(phc) {
        Ok(parsed) => parsed,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT,
    };

    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT;
    }

    match Argon2::default().verify_password(password, &parsed) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_argon2id_hash_password(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    hash_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hash_password_impl(
            password,
            password_len,
            salt,
            salt_len,
            m_cost,
            t_cost,
            p_cost,
            hash_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_argon2id_verify_password(
    password: *const u8,
    password_len: usize,
    phc: *const u8,
    phc_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_password_impl(password, password_len, phc, phc_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
    };

    #[test]
    fn hash_password_matches_known_phc_vector() {
        let password = b"password";
        let salt = b"somesalt";
        let mut output = [0u8; 128];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            65536,
            2,
            1,
            32,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            core::str::from_utf8(&output[..written_len]).unwrap(),
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
        );
    }

    #[test]
    fn hash_password_rejects_short_output_buffer() {
        let password = b"password";
        let salt = b"somesalt";
        let mut output = [0u8; 16];
        let mut written_len = 0usize;

        let status = hash_password_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            65536,
            2,
            1,
            32,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn verify_password_accepts_known_phc_vector() {
        let password = b"password";
        let phc = b"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        let status =
            verify_password_impl(password.as_ptr(), password.len(), phc.as_ptr(), phc.len());

        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let password = b"wrongpassword";
        let phc = b"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        let status =
            verify_password_impl(password.as_ptr(), password.len(), phc.as_ptr(), phc.len());

        assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }

    #[test]
    fn verify_password_rejects_invalid_phc() {
        let password = b"password";
        let phc = b"argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        let status =
            verify_password_impl(password.as_ptr(), password.len(), phc.as_ptr(), phc.len());

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PASSWORD_HASH_FORMAT);
    }
}
