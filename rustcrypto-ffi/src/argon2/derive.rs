use crate::{
    ARGON2ID_MAX_HASH_LEN, ARGON2ID_MIN_HASH_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_OK, aead_common,
};
use ::argon2::{Algorithm, Argon2, Params, Version};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

fn build_argon2id_ctx(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    hash_len: Option<usize>,
) -> Result<Argon2<'static>, c_int> {
    let params = match Params::new(m_cost, t_cost, p_cost, hash_len) {
        Ok(params) => params,
        Err(_) => return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
    };

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn derive_impl(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if derived_len < ARGON2ID_MIN_HASH_LEN || derived_len > ARGON2ID_MAX_HASH_LEN {
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

    let ctx = match build_argon2id_ctx(m_cost, t_cost, p_cost, None) {
        Ok(ctx) => ctx,
        Err(err) => return err,
    };

    let output = unsafe { slice::from_raw_parts_mut(output, derived_len) };
    match ctx.hash_password_into(password, salt, output) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_argon2id_derive(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output: *mut u8,
    output_len: usize,
    derived_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        derive_impl(
            password,
            password_len,
            salt,
            salt_len,
            m_cost,
            t_cost,
            p_cost,
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
    use crate::{RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_OK};

    fn hex_of(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", byte).expect("write to string");
        }
        hex
    }

    #[test]
    fn derive_matches_rfc_9106_known_vector() {
        let password = b"password";
        let salt = b"somesalt";
        let mut output = [0u8; 32];

        let status = derive_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            65536,
            2,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            hex_of(&output),
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        );
    }

    #[test]
    fn derive_rejects_too_short_output() {
        let password = b"password";
        let salt = b"somesalt";
        let mut output = [0u8; 3];

        let status = derive_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            65536,
            2,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn derive_rejects_invalid_parameters() {
        let password = b"password";
        let salt = b"somesalt";
        let mut output = [0u8; 32];

        let status = derive_impl(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            7,
            2,
            1,
            output.as_mut_ptr(),
            output.len(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
}
