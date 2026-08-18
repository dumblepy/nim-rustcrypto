use crate::{
    ED25519_PRIVATE_KEY_DER_MAX_LEN, ED25519_PUBLIC_KEY_DER_MAX_LEN, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use pem_rfc7468::{Error, LineEnding, decode, encode, encoded_len};
use std::panic::{AssertUnwindSafe, catch_unwind};

const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";

fn map_pem_error(err: Error) -> c_int {
    match err {
        Error::Length => RUSTCRYPTO_ERR_INVALID_LENGTH,
        _ => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

fn encode_pem(
    label: &str,
    input: &[u8],
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let required_len = match encoded_len(label, LineEnding::LF, input) {
        Ok(len) => len,
        Err(err) => return map_pem_error(err),
    };

    let output = match aead_common::output_buffer(output, output_len, required_len) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let encoded = match encode(label, LineEnding::LF, input, output) {
        Ok(encoded) => encoded,
        Err(err) => return map_pem_error(err),
    };

    unsafe {
        *written_len = encoded.len();
    }

    RUSTCRYPTO_OK
}

fn decode_pem<'a>(
    pem: *const u8,
    pem_len: usize,
    label: &str,
    der: &'a mut [u8],
) -> Result<&'a [u8], c_int> {
    let pem = aead_common::optional_input(pem, pem_len)?;
    let (actual_label, decoded) = match decode(pem, der) {
        Ok(result) => result,
        Err(err) => return Err(map_pem_error(err)),
    };

    if actual_label != label {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    Ok(decoded)
}

pub(crate) fn private_key_to_pkcs8_pem_impl(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    let mut der = [0u8; ED25519_PRIVATE_KEY_DER_MAX_LEN];
    let mut der_len = 0usize;
    let status = super::pkcs8::private_key_to_pkcs8_der_impl(
        private_key,
        private_key_len,
        der.as_mut_ptr(),
        der.len(),
        &mut der_len,
    );

    if status != RUSTCRYPTO_OK {
        return status;
    }

    encode_pem(
        PRIVATE_KEY_LABEL,
        &der[..der_len],
        output,
        output_len,
        written_len,
    )
}

pub(crate) fn private_key_from_pkcs8_pem_impl(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let mut der = [0u8; ED25519_PRIVATE_KEY_DER_MAX_LEN];
    let der = match decode_pem(pem, pem_len, PRIVATE_KEY_LABEL, &mut der) {
        Ok(der) => der,
        Err(err) => return err,
    };

    if der.len() != ED25519_PRIVATE_KEY_DER_MAX_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    super::pkcs8::private_key_from_pkcs8_der_impl(der.as_ptr(), der.len(), output, output_len)
}

pub(crate) fn public_key_to_spki_pem_impl(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    let mut der = [0u8; ED25519_PUBLIC_KEY_DER_MAX_LEN];
    let mut der_len = 0usize;
    let status = super::pkcs8::public_key_to_spki_der_impl(
        public_key,
        public_key_len,
        der.as_mut_ptr(),
        der.len(),
        &mut der_len,
    );

    if status != RUSTCRYPTO_OK {
        return status;
    }

    encode_pem(
        PUBLIC_KEY_LABEL,
        &der[..der_len],
        output,
        output_len,
        written_len,
    )
}

pub(crate) fn public_key_from_spki_pem_impl(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let mut der = [0u8; ED25519_PUBLIC_KEY_DER_MAX_LEN];
    let der = match decode_pem(pem, pem_len, PUBLIC_KEY_LABEL, &mut der) {
        Ok(der) => der,
        Err(err) => return err,
    };

    if der.len() != ED25519_PUBLIC_KEY_DER_MAX_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    super::pkcs8::public_key_from_spki_der_impl(der.as_ptr(), der.len(), output, output_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_private_key_to_pkcs8_pem(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_to_pkcs8_pem_impl(
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
pub extern "C" fn rustcrypto_ed25519_private_key_from_pkcs8_pem(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_from_pkcs8_pem_impl(pem, pem_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_to_spki_pem(
    public_key: *const u8,
    public_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_to_spki_pem_impl(public_key, public_key_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_spki_pem(
    pem: *const u8,
    pem_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_spki_pem_impl(pem, pem_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ED25519_PRIVATE_KEY_LEN, ED25519_PRIVATE_KEY_PEM_MAX_LEN, ED25519_PUBLIC_KEY_LEN,
        ED25519_PUBLIC_KEY_PEM_MAX_LEN, RUSTCRYPTO_ERR_INVALID_PARAMETER,
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
    };

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
    fn private_key_to_pkcs8_pem_matches_rfc_7468_example() {
        let private_key =
            hex_bytes("17ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85");
        let mut output = [0u8; ED25519_PRIVATE_KEY_PEM_MAX_LEN];
        let mut written_len = 0usize;

        let status = private_key_to_pkcs8_pem_impl(
            private_key.as_ptr(),
            private_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, ED25519_PRIVATE_KEY_PEM_MAX_LEN);
        assert_eq!(
            core::str::from_utf8(&output[..written_len]).unwrap(),
            "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF\n\
-----END PRIVATE KEY-----\n"
        );
    }

    #[test]
    fn private_key_from_pkcs8_pem_matches_rfc_7468_example() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF\n\
-----END PRIVATE KEY-----";
        let mut output = [0u8; ED25519_PRIVATE_KEY_LEN];

        let status = private_key_from_pkcs8_pem_impl(
            pem.as_ptr(),
            pem.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("17ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85")
                .as_slice()
        );
    }

    #[test]
    fn public_key_to_spki_pem_matches_rfc_7468_example() {
        let public_key =
            hex_bytes("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        let mut output = [0u8; ED25519_PUBLIC_KEY_PEM_MAX_LEN];
        let mut written_len = 0usize;

        let status = public_key_to_spki_pem_impl(
            public_key.as_ptr(),
            public_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(written_len, ED25519_PUBLIC_KEY_PEM_MAX_LEN);
        assert_eq!(
            core::str::from_utf8(&output[..written_len]).unwrap(),
            "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----\n"
        );
    }

    #[test]
    fn public_key_from_spki_pem_matches_rfc_7468_example() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----";
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = public_key_from_spki_pem_impl(
            pem.as_ptr(),
            pem.len(),
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
    fn private_key_to_pkcs8_pem_rejects_short_output_buffer() {
        let private_key =
            hex_bytes("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
        let mut output = [0u8; ED25519_PRIVATE_KEY_PEM_MAX_LEN - 1];
        let mut written_len = 0usize;

        let status = private_key_to_pkcs8_pem_impl(
            private_key.as_ptr(),
            private_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn public_key_to_spki_pem_rejects_short_output_buffer() {
        let public_key =
            hex_bytes("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        let mut output = [0u8; ED25519_PUBLIC_KEY_PEM_MAX_LEN - 1];
        let mut written_len = 0usize;

        let status = public_key_to_spki_pem_impl(
            public_key.as_ptr(),
            public_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn private_key_from_pkcs8_pem_rejects_wrong_label() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF\n\
-----END PUBLIC KEY-----";
        let mut output = [0u8; ED25519_PRIVATE_KEY_LEN];

        let status = private_key_from_pkcs8_pem_impl(
            pem.as_ptr(),
            pem.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn public_key_from_spki_pem_rejects_invalid_base64() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
!CowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----";
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = public_key_from_spki_pem_impl(
            pem.as_ptr(),
            pem.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn private_key_from_pkcs8_pem_rejects_short_output_buffer() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF\n\
-----END PRIVATE KEY-----";
        let mut output = [0u8; ED25519_PRIVATE_KEY_LEN - 1];

        let status = private_key_from_pkcs8_pem_impl(
            pem.as_ptr(),
            pem.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn public_key_from_spki_pem_rejects_short_output_buffer() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----";
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN - 1];

        let status = public_key_from_spki_pem_impl(
            pem.as_ptr(),
            pem.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
