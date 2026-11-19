use crate::bulletproofs_r1cs::*;

fn boundary(f: impl FnOnce() -> Result<i32, Error>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => error as i32,
        Err(_) => Error::Internal as i32,
    }
}

// The caller must keep nonempty input ranges readable for the duration of the call.
unsafe fn input<'a>(ptr: *const u8, len: usize, limit: usize) -> Result<&'a [u8], Error> {
    if len > limit {
        return Err(Error::Limit);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || (ptr as usize).checked_add(len).is_none() {
        return Err(Error::Buffer);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_bulletproofs_r1cs_prove(
    circuit: *const u8,
    circuit_len: usize,
    public: *const u8,
    public_len: usize,
    witness: *const u8,
    witness_len: usize,
    blindings: *const u8,
    blindings_len: usize,
    context: *const u8,
    context_len: usize,
    output: *mut u8,
    capacity: usize,
) -> i32 {
    boundary(|| unsafe {
        let circuit =
            CircuitDefinition::from_bytes(input(circuit, circuit_len, MAX_CIRCUIT_BYTES)?)?;
        let needed = circuit.proof_len();
        if output.is_null() || capacity < needed || (output as usize).checked_add(needed).is_none()
        {
            return Err(Error::Buffer);
        }
        let proof = circuit.prove_with_blindings(
            PublicInputs(input(public, public_len, MAX_PUBLIC_INPUTS * 32)?),
            Witness(input(witness, witness_len, MAX_WITNESS * 32)?),
            Blindings(input(blindings, blindings_len, MAX_COMMITMENTS * 32)?),
            input(context, context_len, MAX_CONTEXT_BYTES)?,
        )?;
        std::ptr::copy_nonoverlapping(proof.as_ptr(), output, proof.len());
        Ok(proof.len() as i32)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_bulletproofs_r1cs_verify(
    circuit: *const u8,
    circuit_len: usize,
    public: *const u8,
    public_len: usize,
    context: *const u8,
    context_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    boundary(|| unsafe {
        let circuit =
            CircuitDefinition::from_bytes(input(circuit, circuit_len, MAX_CIRCUIT_BYTES)?)?;
        let valid = circuit.verify(
            PublicInputs(input(public, public_len, MAX_PUBLIC_INPUTS * 32)?),
            input(context, context_len, MAX_CONTEXT_BYTES)?,
            Proof(input(proof, proof_len, MAX_PROOF_BYTES)?),
        )?;
        Ok(i32::from(valid))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustcrypto_bulletproofs_r1cs_validate(
    kind: u32,
    bytes: *const u8,
    len: usize,
) -> i32 {
    boundary(|| unsafe {
        match kind {
            0 => validate_proof(Proof(input(bytes, len, MAX_PROOF_BYTES)?))?,
            1 => validate_public_inputs(PublicInputs(input(bytes, len, MAX_PUBLIC_INPUTS * 32)?))?,
            2 => validate_commitments(Commitments(input(bytes, len, MAX_COMMITMENTS * 32)?))?,
            3 => {
                CircuitDefinition::from_bytes(input(bytes, len, MAX_CIRCUIT_BYTES)?)?;
            }
            _ => return Err(Error::Encoding),
        }
        Ok(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null;

    #[test]
    fn invalid_ffi_buffers() {
        unsafe {
            assert_eq!(
                rustcrypto_bulletproofs_r1cs_validate(0, null(), 1),
                Error::Buffer as i32
            );
            assert_eq!(
                rustcrypto_bulletproofs_r1cs_validate(0, null(), 0),
                Error::Encoding as i32
            );
            assert_eq!(
                rustcrypto_bulletproofs_r1cs_validate(0, null(), usize::MAX),
                Error::Limit as i32
            );
            assert_eq!(
                rustcrypto_bulletproofs_r1cs_validate(0, usize::MAX as *const u8, 2),
                Error::Buffer as i32
            );
        }
    }

    #[test]
    fn proof_writes_only_within_caller_buffer() {
        // BPC1, zero public inputs, one witness, zero commitments, one row with three empty combinations.
        let circuit = b"BPC1\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0";
        let witness = [0u8; 32];
        let needed = CircuitDefinition::from_bytes(circuit).unwrap().proof_len();
        let mut output = vec![0xAA; needed + 2];
        let mut prove = |capacity| unsafe {
            rustcrypto_bulletproofs_r1cs_prove(
                circuit.as_ptr(),
                circuit.len(),
                null(),
                0,
                witness.as_ptr(),
                witness.len(),
                null(),
                0,
                null(),
                0,
                output.as_mut_ptr().add(1),
                capacity,
            )
        };
        assert_eq!(prove(needed - 1), Error::Buffer as i32);
        assert_eq!(prove(needed), needed as i32);
        assert_eq!(output[0], 0xAA);
        assert_eq!(output[needed + 1], 0xAA);
        let result = unsafe {
            rustcrypto_bulletproofs_r1cs_verify(
                circuit.as_ptr(),
                circuit.len(),
                null(),
                0,
                null(),
                0,
                output.as_ptr().add(1),
                needed,
            )
        };
        assert_eq!(result, 1);
    }
}
