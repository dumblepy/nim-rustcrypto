use crate::{
    ED25519_PRIVATE_KEY_LEN, ED25519_PUBLIC_KEY_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use ed25519::pkcs8::{
    DecodePrivateKey, DecodePublicKey, Document, EncodePrivateKey, EncodePublicKey, KeypairBytes,
    PublicKeyBytes,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn raw_key<const N: usize>(
    input: *const u8,
    input_len: usize,
    invalid_length_error: c_int,
) -> Result<[u8; N], c_int> {
    let input = aead_common::fixed_input(input, input_len, N, invalid_length_error)?;
    let mut output = [0u8; N];
    output.copy_from_slice(input);
    Ok(output)
}

pub(crate) fn private_key_to_pkcs8_der_impl(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let private_key = match raw_key::<ED25519_PRIVATE_KEY_LEN>(
        private_key,
        private_key_len,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(private_key) => private_key,
        Err(err) => return err,
    };

    let keypair = KeypairBytes {
        secret_key: private_key,
        public_key: None,
    };

    let der = match keypair.to_pkcs8_der() {
        Ok(der) => der,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let der_bytes = der.as_bytes();
    let output = match aead_common::output_buffer(output, output_len, der_bytes.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(der_bytes);
    unsafe {
        *written_len = der_bytes.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn private_key_from_pkcs8_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let der = match aead_common::optional_input(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };

    let keypair = match KeypairBytes::from_pkcs8_der(der) {
        Ok(keypair) => keypair,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    let output = match aead_common::output_buffer(output, output_len, ED25519_PRIVATE_KEY_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(&keypair.secret_key);
    RUSTCRYPTO_OK
}

pub(crate) fn public_key_to_spki_der_impl(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let public_key = match raw_key::<ED25519_PUBLIC_KEY_LEN>(
        public_key,
        public_key_len,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };

    let public_key = PublicKeyBytes(public_key);
    let der: Document = match public_key.to_public_key_der() {
        Ok(der) => der,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let der_bytes = der.as_bytes();
    let output = match aead_common::output_buffer(output, output_len, der_bytes.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(der_bytes);
    unsafe {
        *written_len = der_bytes.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn public_key_from_spki_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let der = match aead_common::optional_input(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };

    let public_key = match PublicKeyBytes::from_public_key_der(der) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };

    let output = match aead_common::output_buffer(output, output_len, ED25519_PUBLIC_KEY_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };

    output.copy_from_slice(&public_key.to_bytes());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_to_pkcs8_der(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_to_pkcs8_der_impl(
            private_key,
            private_key_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_from_pkcs8_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_from_pkcs8_der_impl(der, der_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_to_spki_der(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_to_spki_der_impl(public_key, public_key_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_spki_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_spki_der_impl(der, der_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;

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
    fn private_key_to_pkcs8_der_matches_rfc_8410_example() {
        let private_key =
            hex_bytes("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
        let mut output = [0u8; crate::ED25519_PRIVATE_KEY_DER_MAX_LEN];
        let mut written_len = 0usize;

        let status = private_key_to_pkcs8_der_impl(
            private_key.as_ptr(),
            private_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, 48);
        assert_eq!(
            &output[..written_len],
            hex_bytes(
                "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
            )
        );
    }

    #[test]
    fn private_key_from_pkcs8_der_matches_rfc_8410_example() {
        let der = hex_bytes(
            "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
        );
        let mut output = [0u8; ED25519_PRIVATE_KEY_LEN];

        let status = private_key_from_pkcs8_der_impl(
            der.as_ptr(),
            der.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
                .as_slice()
        );
    }

    #[test]
    fn public_key_to_spki_der_matches_rfc_8410_example() {
        let public_key =
            hex_bytes("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        let mut output = [0u8; crate::ED25519_PUBLIC_KEY_DER_MAX_LEN];
        let mut written_len = 0usize;

        let status = public_key_to_spki_der_impl(
            public_key.as_ptr(),
            public_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, 44);
        assert_eq!(
            &output[..written_len],
            hex_bytes(
                "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
            )
        );
    }

    #[test]
    fn public_key_from_spki_der_matches_rfc_8410_example() {
        let der = hex_bytes(
            "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
        );
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = public_key_from_spki_der_impl(
            der.as_ptr(),
            der.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
                .as_slice()
        );
    }

    #[test]
    fn private_key_to_pkcs8_der_rejects_short_output_buffer() {
        let private_key =
            hex_bytes("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
        let mut output = [0u8; crate::ED25519_PRIVATE_KEY_DER_MAX_LEN - 1];
        let mut written_len = 0usize;

        let status = private_key_to_pkcs8_der_impl(
            private_key.as_ptr(),
            private_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn public_key_to_spki_der_rejects_short_output_buffer() {
        let public_key =
            hex_bytes("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        let mut output = [0u8; crate::ED25519_PUBLIC_KEY_DER_MAX_LEN - 1];
        let mut written_len = 0usize;

        let status = public_key_to_spki_der_impl(
            public_key.as_ptr(),
            public_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn private_key_from_pkcs8_der_rejects_malformed_der() {
        let der = hex_bytes("3000");
        let mut output = [0u8; ED25519_PRIVATE_KEY_LEN];

        let status = private_key_from_pkcs8_der_impl(
            der.as_ptr(),
            der.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn public_key_from_spki_der_rejects_malformed_der() {
        let der = hex_bytes("3000");
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = public_key_from_spki_der_impl(
            der.as_ptr(),
            der.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
}
