//! RFC 9180 Base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
use crate::status::*;
use core::{ffi::c_int, ptr, slice};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256 as Kem,
};
use rand_core::RngCore;
use zeroize::Zeroizing;
type Sk = <Kem as KemTrait>::PrivateKey;
type Pk = <Kem as KemTrait>::PublicKey;
const MAX: usize = 16 * 1024 * 1024;
const CONTEXT_MAX: usize = 1024 * 1024;

// Adapt rand_core 0.6's OS entropy source to hpke's 0.9 traits. If entropy fails,
// reject the entire operation before copying any result to caller memory.
fn random_fill(dest: &mut [u8]) -> Result<(), c_int> {
    #[cfg(test)]
    if let Some(value) = TEST_ENTROPY.with(|cell| *cell.borrow()) {
        let bytes = value.map_err(|_| RUSTCRYPTO_ERR_RANDOM_FAILED)?;
        if dest.len() != bytes.len() {
            return Err(RUSTCRYPTO_ERR_RANDOM_FAILED);
        }
        dest.copy_from_slice(&bytes);
        return Ok(());
    }
    rand_core::OsRng
        .try_fill_bytes(dest)
        .map_err(|_| RUSTCRYPTO_ERR_RANDOM_FAILED)
}
#[cfg(test)]
std::thread_local! {
    static TEST_ENTROPY: std::cell::RefCell<Option<Result<[u8;32],()>>> = const { std::cell::RefCell::new(None) };
}
struct OsRandom {
    failed: bool,
}
impl hpke::rand_core::RngCore for OsRandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if random_fill(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }
}
impl hpke::rand_core::CryptoRng for OsRandom {}
fn boundary(f: impl FnOnce() -> Result<(), c_int>) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map(|r| r.err().unwrap_or(RUSTCRYPTO_OK))
        .unwrap_or(RUSTCRYPTO_ERR_PANIC)
}
unsafe fn input<'a>(p: *const u8, len: usize, max: usize) -> Result<&'a [u8], c_int> {
    if len > max {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
    Ok(unsafe { slice::from_raw_parts(p, len) })
}
fn output(p: *mut u8, capacity: usize, required: usize) -> Result<(), c_int> {
    if capacity < required {
        return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
    if required > 0 && p.is_null() {
        return Err(RUSTCRYPTO_ERR_NULL_OUTPUT);
    }
    Ok(())
}
fn canonical(pk: &[u8]) -> Result<(), c_int> {
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if pk.iter().rev().cmp(prime.iter().rev()) != core::cmp::Ordering::Less {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT);
    }
    Ok(())
}
/// Caller provides a writable 32-byte secret buffer; on failure it is untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_hpke_generate_secret_key(
    out: *mut u8,
    out_len: usize,
) -> c_int {
    boundary(|| {
        output(out, out_len, 32)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        random_fill(secret.as_mut())?;
        unsafe {
            ptr::copy_nonoverlapping(secret.as_ptr(), out, 32);
        }
        Ok(())
    })
}
/// Derive the raw RFC 7748 public key from a 32-byte private key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_hpke_public_key(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    boundary(|| {
        if sk_len != 32 {
            return Err(RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
        }
        output(out, out_len, 32)?;
        let secret = Sk::from_bytes(unsafe { input(sk, sk_len, 32)? })
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_SECRET_KEY)?;
        let pk = Kem::sk_to_pk(&secret).to_bytes();
        unsafe {
            ptr::copy(pk.as_ptr(), out, 32);
        }
        Ok(())
    })
}
/// Single-shot Base mode. All buffers must be valid for their declared lengths.
/// Output is written only on success. Output may overlap inputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_hpke_seal(
    key: *const u8,
    key_len: usize,
    info: *const u8,
    info_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    boundary(|| {
        if key_len != 32 {
            return Err(RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
        }
        if plaintext_len > MAX {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        output(out, out_len, plaintext_len + 48)?;
        let key = unsafe { input(key, key_len, 32)? };
        canonical(key)?;
        let pk = Pk::from_bytes(key).map_err(|_| RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT)?;
        let info = unsafe { input(info, info_len, CONTEXT_MAX)? };
        let aad = unsafe { input(aad, aad_len, CONTEXT_MAX)? };
        let plaintext = unsafe { input(plaintext, plaintext_len, MAX)? };
        let mut rng = OsRandom { failed: false };
        let sealed = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
            &OpModeS::Base,
            &pk,
            info,
            plaintext,
            aad,
            &mut rng,
        );
        if rng.failed {
            return Err(RUSTCRYPTO_ERR_RANDOM_FAILED);
        }
        let (enc, ct) = sealed.map_err(|_| RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT)?;
        let mut wire = enc.to_bytes().to_vec();
        wire.extend_from_slice(&ct);
        unsafe {
            ptr::copy(wire.as_ptr(), out, wire.len());
        }
        Ok(())
    })
}
/// No unauthenticated plaintext is copied to caller memory, including on panic.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_hpke_open(
    key: *const u8,
    key_len: usize,
    info: *const u8,
    info_len: usize,
    aad: *const u8,
    aad_len: usize,
    sealed: *const u8,
    sealed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    boundary(|| {
        if key_len != 32 {
            return Err(RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
        }
        if !(48..=MAX + 48).contains(&sealed_len) {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        output(out, out_len, sealed_len - 48)?;
        let sk = Sk::from_bytes(unsafe { input(key, key_len, 32)? })
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_SECRET_KEY)?;
        let info = unsafe { input(info, info_len, CONTEXT_MAX)? };
        let aad = unsafe { input(aad, aad_len, CONTEXT_MAX)? };
        let wire = unsafe { input(sealed, sealed_len, MAX + 48)? };
        canonical(&wire[..32])?;
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&wire[..32])
            .map_err(|_| RUSTCRYPTO_ERR_AUTHENTICATION_FAILED)?;
        let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
        )
        .map_err(|_| RUSTCRYPTO_ERR_AUTHENTICATION_FAILED)?;
        let mut plaintext = Zeroizing::new(wire[32..wire.len() - 16].to_vec());
        let tag = hpke::aead::AeadTag::<ChaCha20Poly1305>::from_bytes(&wire[wire.len() - 16..])
            .map_err(|_| RUSTCRYPTO_ERR_AUTHENTICATION_FAILED)?;
        ctx.open_in_place_detached(&mut plaintext, aad, &tag)
            .map_err(|_| RUSTCRYPTO_ERR_AUTHENTICATION_FAILED)?;
        if !plaintext.is_empty() {
            unsafe {
                ptr::copy(plaintext.as_ptr(), out, plaintext.len());
            }
        }
        Ok(())
    })
}
#[cfg(test)]
#[path = "hpke_tests.rs"]
mod tests;

/// Wipe a caller-owned secret key without transferring its ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_hpke_clear_secret_key(key: *mut u8, key_len: usize) -> c_int {
    boundary(|| {
        if key_len != 32 {
            return Err(RUSTCRYPTO_ERR_INVALID_KEY_LENGTH);
        }
        output(key, key_len, 32)?;
        use zeroize::Zeroize;
        unsafe { slice::from_raw_parts_mut(key, key_len) }.zeroize();
        Ok(())
    })
}
