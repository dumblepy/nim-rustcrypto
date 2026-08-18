#![allow(dead_code)]

use crate::{
    RUSTCRYPTO_ERR_INVALID_KEY_LENGTH, RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_TAG_LENGTH,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
};
use core::ffi::c_int;
use core::slice;

pub(crate) fn optional_input<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    if input_len == 0 {
        Ok(&[])
    } else if input.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { slice::from_raw_parts(input, input_len) })
    }
}

pub(crate) fn fixed_input<'a>(
    input: *const u8,
    input_len: usize,
    expected_len: usize,
    invalid_length_error: c_int,
) -> Result<&'a [u8], c_int> {
    if input_len != expected_len {
        Err(invalid_length_error)
    } else if input.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA)
    } else {
        Ok(unsafe { slice::from_raw_parts(input, input_len) })
    }
}

pub(crate) fn output_buffer<'a>(
    output: *mut u8,
    output_len: usize,
    required_len: usize,
) -> Result<&'a mut [u8], c_int> {
    if required_len == 0 {
        return Ok(unsafe {
            slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0)
        });
    }

    if output.is_null() {
        Err(RUSTCRYPTO_ERR_NULL_OUTPUT)
    } else if output_len < required_len {
        Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT)
    } else {
        Ok(unsafe { slice::from_raw_parts_mut(output, required_len) })
    }
}

pub(crate) fn validate_aead_parameters(
    key_len: usize,
    expected_key_len: usize,
    nonce_len: usize,
    expected_nonce_len: usize,
    tag_len: usize,
    expected_tag_len: usize,
) -> c_int {
    if key_len != expected_key_len {
        return RUSTCRYPTO_ERR_INVALID_KEY_LENGTH;
    }

    if nonce_len != expected_nonce_len {
        return RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH;
    }

    if tag_len != expected_tag_len {
        return RUSTCRYPTO_ERR_INVALID_TAG_LENGTH;
    }

    RUSTCRYPTO_OK
}

pub(crate) fn validate_same_length_relation(left_len: usize, right_len: usize) -> c_int {
    if left_len == right_len {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_INVALID_PARAMETER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_KEY_LENGTH, RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH,
        RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_TAG_LENGTH, RUSTCRYPTO_OK,
    };

    #[test]
    fn optional_input_accepts_empty_input_via_null_pointer() {
        let input = optional_input(core::ptr::null(), 0).expect("empty input should be allowed");

        assert!(input.is_empty());
    }

    #[test]
    fn optional_input_rejects_null_pointer_when_length_is_non_zero() {
        let status = optional_input(core::ptr::null(), 1).unwrap_err();

        assert_eq!(status, crate::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn fixed_input_accepts_exact_length() {
        let input = [1u8, 2, 3, 4];
        let view = fixed_input(
            input.as_ptr(),
            input.len(),
            4,
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
        )
        .expect("exact length should pass");

        assert_eq!(view, &input);
    }

    #[test]
    fn fixed_input_rejects_null_pointer_when_length_matches() {
        let status =
            fixed_input(core::ptr::null(), 4, 4, RUSTCRYPTO_ERR_INVALID_PARAMETER).unwrap_err();

        assert_eq!(status, crate::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn fixed_input_rejects_wrong_length() {
        let input = [1u8, 2, 3, 4];
        let status = fixed_input(
            input.as_ptr(),
            input.len(),
            5,
            RUSTCRYPTO_ERR_INVALID_KEY_LENGTH,
        )
        .unwrap_err();

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
    }

    #[test]
    fn output_buffer_accepts_exact_length() {
        let mut output = [0u8; 4];
        let view =
            output_buffer(output.as_mut_ptr(), output.len(), 4).expect("exact length should pass");

        assert_eq!(view.len(), 4);
    }

    #[test]
    fn output_buffer_accepts_null_for_empty_output() {
        let view = output_buffer(core::ptr::null_mut(), 0, 0).expect("empty output should pass");

        assert!(view.is_empty());
    }

    #[test]
    fn output_buffer_rejects_null_output() {
        let status = output_buffer(core::ptr::null_mut(), 4, 4).unwrap_err();

        assert_eq!(status, crate::RUSTCRYPTO_ERR_NULL_OUTPUT);
    }

    #[test]
    fn output_buffer_rejects_short_output() {
        let mut output = [0u8; 3];
        let status = output_buffer(output.as_mut_ptr(), output.len(), 4).unwrap_err();

        assert_eq!(status, crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn validate_aead_parameters_distinguishes_length_errors() {
        assert_eq!(
            validate_aead_parameters(31, 32, 12, 12, 16, 16),
            RUSTCRYPTO_ERR_INVALID_KEY_LENGTH
        );
        assert_eq!(
            validate_aead_parameters(32, 32, 11, 12, 16, 16),
            RUSTCRYPTO_ERR_INVALID_NONCE_LENGTH
        );
        assert_eq!(
            validate_aead_parameters(32, 32, 12, 12, 15, 16),
            RUSTCRYPTO_ERR_INVALID_TAG_LENGTH
        );
    }

    #[test]
    fn validate_aead_parameters_reports_success_for_matching_lengths() {
        assert_eq!(RUSTCRYPTO_OK, 0);
        assert_eq!(
            validate_aead_parameters(32, 32, 12, 12, 16, 16),
            RUSTCRYPTO_OK
        );
    }

    #[test]
    fn validate_same_length_relation_reports_invalid_parameter_on_mismatch() {
        assert_eq!(
            validate_same_length_relation(16, 15),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
    }
}
