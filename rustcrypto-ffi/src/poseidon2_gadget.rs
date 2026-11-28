//! R1CS gadget for Poseidon2/BN254.
//!
//! The gadget mirrors [`crate::poseidon2`] exactly: the same vendored
//! constants, round ordering, external/internal linear layers and the
//! Noir/Barretenberg sponge framing. Round constants and the internal
//! diagonal are used as constants (`FpVar::Constant`), so the gadget does not
//! allocate extra witness variables for them.

use crate::poseidon2::{POSEIDON2_BN254_MAX_INPUTS, POSEIDON2_BN254_RATE, constants::BN254_CONFIG};
use ark_bn254::Fr;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::r1cs::SynthesisError;

/// `x^5` S-box.
#[inline(always)]
fn s_box(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(x4 * x)
}

/// External 4×4 linear layer (Barretenberg's matrix).
#[inline(always)]
fn external_matrix(input: [FpVar<Fr>; 4]) -> [FpVar<Fr>; 4] {
    let t0 = &input[0] + &input[1];
    let t1 = &input[2] + &input[3];
    let two1 = &input[1] + &input[1];
    let t2 = &two1 + &t1;
    let two3 = &input[3] + &input[3];
    let t3 = &two3 + &t0;
    let two_t1 = &t1 + &t1;
    let four_t1 = &two_t1 + &two_t1;
    let t4 = &four_t1 + &t3;
    let two0 = &t0 + &t0;
    let four0 = &two0 + &two0;
    let t5 = &four0 + &t2;
    let t6 = &t3 + &t5;
    let t7 = &t2 + &t4;
    [t6, t5, t7, t4]
}

/// Internal linear layer: multiply by the diagonal, then add the state sum.
#[inline(always)]
fn internal_matrix(state: &mut [FpVar<Fr>; 4]) {
    let sum = state.iter().fold(FpVar::zero(), |acc, value| acc + value);
    for (value, diagonal) in state
        .iter_mut()
        .zip(BN254_CONFIG.internal_matrix_diagonal.iter())
    {
        let scaled = &*value * *diagonal;
        *value = scaled + &sum;
    }
}

#[inline(always)]
fn add_round_constants(state: &mut [FpVar<Fr>; 4], round: usize) {
    for (value, constant) in state
        .iter_mut()
        .zip(BN254_CONFIG.round_constant[round].iter())
    {
        *value += *constant;
    }
}

/// Permutes a width-4 R1CS state.
pub fn permute(state: [FpVar<Fr>; 4]) -> Result<[FpVar<Fr>; 4], SynthesisError> {
    let mut state = external_matrix(state);

    let rf_first = (BN254_CONFIG.rounds_f / 2) as usize;
    for round in 0..rf_first {
        add_round_constants(&mut state, round);
        for value in state.iter_mut() {
            let next = s_box(value)?;
            *value = next;
        }
        state = external_matrix(state);
    }

    let p_end = rf_first + BN254_CONFIG.rounds_p as usize;
    for round in rf_first..p_end {
        state[0] += BN254_CONFIG.round_constant[round][0];
        state[0] = s_box(&state[0])?;
        internal_matrix(&mut state);
    }

    let num_rounds = (BN254_CONFIG.rounds_f + BN254_CONFIG.rounds_p) as usize;
    for round in p_end..num_rounds {
        add_round_constants(&mut state, round);
        for value in state.iter_mut() {
            let next = s_box(value)?;
            *value = next;
        }
        state = external_matrix(state);
    }

    Ok(state)
}

/// Hashes field variables with the Noir/Barretenberg sponge.
///
/// `inputs.len()` must be `0..=12`. The final permutation is skipped exactly
/// when the length is a non-zero multiple of [`POSEIDON2_BN254_RATE`].
pub fn hash(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    if inputs.len() > POSEIDON2_BN254_MAX_INPUTS {
        return Err(SynthesisError::Unsatisfiable);
    }

    let len = inputs.len();
    let iv = Fr::from(len as u64) * Fr::from(1u128 << 64);
    let mut state = [
        FpVar::zero(),
        FpVar::zero(),
        FpVar::zero(),
        FpVar::Constant(iv),
    ];

    let full = len / POSEIDON2_BN254_RATE;
    for block in 0..full {
        state[0] = &state[0] + &inputs[block * POSEIDON2_BN254_RATE];
        state[1] = &state[1] + &inputs[block * POSEIDON2_BN254_RATE + 1];
        state[2] = &state[2] + &inputs[block * POSEIDON2_BN254_RATE + 2];
        state = permute(state)?;
    }

    for i in 0..(len % POSEIDON2_BN254_RATE) {
        state[i] = &state[i] + &inputs[full * POSEIDON2_BN254_RATE + i];
    }

    if len == 0 || len % POSEIDON2_BN254_RATE != 0 {
        state = permute(state)?;
    }

    Ok(state[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::{poseidon2_bn254_hash_impl, poseidon2_bn254_permute_impl};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;

    fn witness(cs: &ark_relations::r1cs::ConstraintSystemRef<Fr>, values: &[Fr]) -> Vec<FpVar<Fr>> {
        values
            .iter()
            .map(|value| FpVar::new_witness(cs.clone(), || Ok(*value)).unwrap())
            .collect()
    }

    #[test]
    fn gadget_hash_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let values = [Fr::from(1u64), Fr::from(2u64)];
        let vars = witness(&cs, &values);

        let out = hash(&vars).unwrap();
        let expected = FpVar::Constant(poseidon2_bn254_hash_impl(&values));
        out.enforce_equal(&expected).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn gadget_empty_hash_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let out = hash(&[]).unwrap();
        let expected = FpVar::Constant(poseidon2_bn254_hash_impl(&[]));
        out.enforce_equal(&expected).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn gadget_permute_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let values = [
            Fr::from(7u64),
            Fr::from(8u64),
            Fr::from(9u64),
            Fr::from(10u64),
        ];
        let vars = witness(&cs, &values);

        let native = poseidon2_bn254_permute_impl(values);
        let out = permute([
            vars[0].clone(),
            vars[1].clone(),
            vars[2].clone(),
            vars[3].clone(),
        ])
        .unwrap();
        for (value, expected) in out.iter().zip(native.iter()) {
            value.enforce_equal(&FpVar::Constant(*expected)).unwrap();
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn gadget_rejects_too_many_inputs() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<FpVar<Fr>> = (0..=POSEIDON2_BN254_MAX_INPUTS)
            .map(|i| FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64))).unwrap())
            .collect();
        assert!(matches!(hash(&vars), Err(SynthesisError::Unsatisfiable)));
    }
}
