use crate::{RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_RANDOM_FAILED};
use core::ffi::c_int;

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_hash_password(
    _password: *const u8,
    _password_len: usize,
    _cost: u32,
    _output: *mut u8,
    _output_len: usize,
    _written_len: *mut usize,
) -> c_int {
    RUSTCRYPTO_ERR_RANDOM_FAILED
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_verify_password(
    _password: *const u8,
    _password_len: usize,
    _hash: *const u8,
    _hash_len: usize,
) -> c_int {
    RUSTCRYPTO_ERR_INVALID_PARAMETER
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_validate_hash(_hash: *const u8, _hash_len: usize) -> c_int {
    RUSTCRYPTO_ERR_INVALID_PARAMETER
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bcrypt_cost(
    _hash: *const u8,
    _hash_len: usize,
    _cost: *mut u32,
) -> c_int {
    RUSTCRYPTO_ERR_INVALID_PARAMETER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RUSTCRYPTO_ERR_INVALID_PARAMETER;

    #[test]
    fn wasm_stub_returns_error_codes() {
        assert_eq!(
            rustcrypto_bcrypt_validate_hash(core::ptr::null(), 0),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
    }
}
