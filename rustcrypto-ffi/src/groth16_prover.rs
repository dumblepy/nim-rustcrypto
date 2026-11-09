//! Circuit-bound Groth16/BN254 proving. See docs/adr/0070-groth16-prover.md.
use crate::{
    bn254::fr_from_be,
    groth16::{encode_proof, encode_vk},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::Field;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::*,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub const MAX_INPUTS: usize = 256;
pub const MAX_NODES: usize = 1024;
pub const MAX_CONSTRAINTS: usize = 32768;
pub const MAX_CIRCUIT_BYTES: usize = 65536;
pub const MAX_KEY_BYTES: usize = 16 * 1024 * 1024;
pub type Result<T> = core::result::Result<T, i32>;
const INVALID: i32 = crate::RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;

/// Slot index in a circuit: public inputs, private inputs, then one slot per operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire(pub u32);
#[derive(Clone, Debug)]
struct Op {
    tag: u8,
    aux: u8,
    args: Vec<Wire>,
    constant: [u8; 32],
}
/// Versioned, witness-independent circuit definition. Slot order is part of the ABI.
#[derive(Clone, Debug)]
pub struct Circuit {
    public: usize,
    private: usize,
    ops: Vec<Op>,
    cost: usize,
}
impl Circuit {
    pub fn new(public: usize, private: usize) -> Result<Self> {
        if public == 0 || public > MAX_INPUTS || private > MAX_INPUTS {
            return Err(INVALID);
        }
        Ok(Self {
            public,
            private,
            ops: vec![],
            cost: 0,
        })
    }
    pub fn public(&self, index: usize) -> Result<Wire> {
        if index >= self.public {
            return Err(INVALID);
        }
        Ok(Wire(index as u32))
    }
    pub fn private(&self, index: usize) -> Result<Wire> {
        if index >= self.private {
            return Err(INVALID);
        }
        Ok(Wire((self.public + index) as u32))
    }
    fn push(&mut self, tag: u8, aux: u8, args: &[Wire], constant: [u8; 32]) -> Result<Wire> {
        let next = self.public + self.private + self.ops.len();
        if self.ops.len() >= MAX_NODES || args.iter().any(|w| w.0 as usize >= next) {
            return Err(INVALID);
        }
        let cost = match (tag, args.len(), aux) {
            (0, 0, 0) => {
                fr_from_be(&constant)?;
                1
            }
            (1 | 2 | 3, 2, 0) => 2,
            (4, 1..=12, 0) => {
                let width = args.len() + 1;
                let partial = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65][args.len() - 1];
                3 * (8 * width + partial) + (8 + partial) * width + 8
            }
            (5, 1, 1..=128) => 768,
            (6, 3, 0) => 6,
            _ => return Err(INVALID),
        };
        if self.cost + cost > MAX_CONSTRAINTS {
            return Err(INVALID);
        }
        self.cost += cost;
        self.ops.push(Op {
            tag,
            aux,
            args: args.to_vec(),
            constant,
        });
        Ok(Wire(next as u32))
    }
    pub fn constant(&mut self, value: [u8; 32]) -> Result<Wire> {
        self.push(0, 0, &[], value)
    }
    pub fn add(&mut self, a: Wire, b: Wire) -> Result<Wire> {
        self.push(1, 0, &[a, b], [0; 32])
    }
    pub fn mul(&mut self, a: Wire, b: Wire) -> Result<Wire> {
        self.push(2, 0, &[a, b], [0; 32])
    }
    pub fn equal(&mut self, a: Wire, b: Wire) -> Result<()> {
        self.push(3, 0, &[a, b], [0; 32])?;
        Ok(())
    }
    pub fn poseidon(&mut self, inputs: &[Wire]) -> Result<Wire> {
        self.push(4, 0, inputs, [0; 32])
    }
    pub fn range(&mut self, value: Wire, bits: u8) -> Result<()> {
        self.push(5, bits, &[value], [0; 32])?;
        Ok(())
    }
    /// Enforces selector in {0,1}; 1 selects `yes`, 0 selects `no`.
    pub fn select(&mut self, selector: Wire, yes: Wire, no: Wire) -> Result<Wire> {
        self.push(6, 0, &[selector, yes, no], [0; 32])
    }
    /// Each summand and each running sum is bounded: field wraparound cannot satisfy it.
    pub fn bounded_sum(&mut self, values: &[Wire], bits: u8) -> Result<Wire> {
        if values.is_empty() {
            return Err(INVALID);
        }
        let mut sum = self.constant([0; 32])?;
        for &value in values {
            self.range(value, bits)?;
            sum = self.add(sum, value)?;
            self.range(sum, bits)?;
        }
        Ok(sum)
    }
    pub fn merkle_root(
        &mut self,
        leaf: Wire,
        siblings: &[Wire],
        directions: &[Wire],
    ) -> Result<Wire> {
        if siblings.len() != directions.len() || siblings.is_empty() || siblings.len() > 32 {
            return Err(INVALID);
        }
        let mut node = leaf;
        for (&sibling, &direction) in siblings.iter().zip(directions) {
            let left = self.select(direction, sibling, node)?;
            let right = self.select(direction, node, sibling)?;
            node = self.poseidon(&[left, right])?;
        }
        Ok(node)
    }
    /// Application domain is an explicit first input. Secret and context are constrained.
    pub fn prf(&mut self, domain: [u8; 32], secret: Wire, context: Wire) -> Result<Wire> {
        let domain = self.constant(domain)?;
        self.poseidon(&[domain, secret, context])
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"RCCIR01\0".to_vec();
        for n in [self.public, self.private, self.ops.len()] {
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        for op in &self.ops {
            out.extend_from_slice(&[op.tag, op.aux, op.args.len() as u8]);
            for arg in &op.args {
                out.extend_from_slice(&arg.0.to_be_bytes());
            }
            if op.tag == 0 {
                out.extend_from_slice(&op.constant);
            }
        }
        out
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CIRCUIT_BYTES {
            return Err(INVALID);
        }
        let mut r = Reader(bytes);
        if r.take(8)? != b"RCCIR01\0" {
            return Err(INVALID);
        }
        let mut circuit = Self::new(r.u32()?, r.u32()?)?;
        let count = r.u32()?;
        if count > MAX_NODES {
            return Err(INVALID);
        }
        for _ in 0..count {
            let header = r.take(3)?;
            let (tag, aux, n) = (header[0], header[1], header[2] as usize);
            if n > 12 {
                return Err(INVALID);
            }
            let mut args = Vec::with_capacity(n);
            for _ in 0..n {
                args.push(Wire(r.u32()? as u32));
            }
            let mut constant = [0; 32];
            if tag == 0 {
                constant.copy_from_slice(r.take(32)?);
            }
            circuit.push(tag, aux, &args, constant)?;
        }
        if !r.0.is_empty() {
            return Err(INVALID);
        }
        Ok(circuit)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(INVALID);
        }
        let (out, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(out)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| INVALID)?) as usize)
    }
    fn point<T: CanonicalDeserialize>(&mut self) -> Result<T> {
        T::deserialize_compressed(&mut self.0).map_err(|_| INVALID)
    }
    fn points<T: CanonicalDeserialize>(&mut self) -> Result<Vec<T>> {
        let n = self.u32()?;
        if n > 2 * MAX_CONSTRAINTS {
            return Err(INVALID);
        }
        // No attacker-specified unbounded allocation (including truncated encodings).
        if n > self.0.len() / 32 {
            return Err(INVALID);
        }
        (0..n).map(|_| self.point()).collect()
    }
}
fn materialize(value: FpVar<Fr>) -> core::result::Result<FpVar<Fr>, SynthesisError> {
    if value.is_constant() {
        return Ok(value);
    }
    let out = FpVar::new_witness(value.cs(), || value.value())?;
    out.enforce_equal(&value)?;
    Ok(out)
}
pub fn poseidon_gadget(inputs: &[FpVar<Fr>]) -> core::result::Result<FpVar<Fr>, SynthesisError> {
    if inputs.is_empty() || inputs.len() > 12 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let p = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(
        (inputs.len() + 1) as u8,
    )
    .map_err(|_| SynthesisError::Unsatisfiable)?;
    let width = inputs.len() + 1;
    let mut state = vec![FpVar::zero()];
    state.extend_from_slice(inputs);
    for round in 0..p.full_rounds + p.partial_rounds {
        for (i, v) in state.iter_mut().enumerate() {
            *v += p.ark[round * width + i];
        }
        let full = round < p.full_rounds / 2 || round >= p.full_rounds / 2 + p.partial_rounds;
        for (i, v) in state.iter_mut().enumerate() {
            if full || i == 0 {
                let square = v.square()?;
                *v = square.square()? * &*v;
            }
        }
        state = p
            .mds
            .iter()
            .map(|row| {
                materialize(
                    row.iter()
                        .zip(&state)
                        .fold(FpVar::zero(), |sum, (c, v)| sum + v * (*c)),
                )
            })
            .collect::<core::result::Result<Vec<_>, _>>()?;
    }
    Ok(state[0].clone())
}
#[derive(Clone)]
struct Assigned {
    circuit: Circuit,
    public: Vec<Fr>,
    private: Vec<Fr>,
}
impl Drop for Assigned {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}
impl ConstraintSynthesizer<Fr> for Assigned {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> core::result::Result<(), SynthesisError> {
        let mut slots = Vec::new();
        for i in 0..self.circuit.public {
            slots.push(FpVar::new_input(cs.clone(), || {
                self.public
                    .get(i)
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        for i in 0..self.circuit.private {
            slots.push(FpVar::new_witness(cs.clone(), || {
                self.private
                    .get(i)
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        for op in &self.circuit.ops {
            let a: Vec<_> = op
                .args
                .iter()
                .map(|w| slots[w.0 as usize].clone())
                .collect();
            let out = match op.tag {
                0 => FpVar::Constant(
                    fr_from_be(&op.constant).map_err(|_| SynthesisError::Unsatisfiable)?,
                ),
                1 => materialize(&a[0] + &a[1])?,
                2 => &a[0] * &a[1],
                3 => {
                    a[0].enforce_equal(&a[1])?;
                    a[0].clone()
                }
                4 => poseidon_gadget(&a)?,
                5 => {
                    let bits = a[0].to_bits_le()?;
                    for bit in &bits[op.aux as usize..] {
                        bit.enforce_equal(&Boolean::FALSE)?;
                    }
                    a[0].clone()
                }
                6 => {
                    (&a[0] * (&a[0] - Fr::ONE)).enforce_equal(&FpVar::zero())?;
                    materialize(&a[2] + &a[0] * (&a[1] - &a[2]))?
                }
                _ => return Err(SynthesisError::Unsatisfiable),
            };
            slots.push(out);
            if cs.num_constraints() > MAX_CONSTRAINTS {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        Ok(())
    }
}
// Wipe the assignment even when synthesis/constraint checking returns early or panics.
struct WipeAssignment(ConstraintSystemRef<Fr>);
impl Drop for WipeAssignment {
    fn drop(&mut self) {
        if let Some(mut inner) = self.0.borrow_mut() {
            inner.witness_assignment.zeroize();
        }
    }
}
fn secret_fields(bytes: &[u8], count: usize) -> Result<Vec<Fr>> {
    if bytes.len() != count * 32 {
        return Err(crate::RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut values = zeroize::Zeroizing::new(Vec::with_capacity(count));
    for chunk in bytes.chunks_exact(32) {
        values.push(fr_from_be(chunk)?);
    }
    Ok(core::mem::take(&mut *values))
}
fn fields(bytes: &[u8], count: usize) -> Result<Vec<Fr>> {
    if bytes.len() != count * 32 {
        return Err(crate::RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    bytes.chunks_exact(32).map(fr_from_be).collect()
}
fn write_point<T: CanonicalSerialize>(out: &mut Vec<u8>, value: &T) -> Result<()> {
    value.serialize_compressed(out).map_err(|_| INVALID)
}
fn write_points<T: CanonicalSerialize>(out: &mut Vec<u8>, values: &[T]) -> Result<()> {
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for v in values {
        write_point(out, v)?;
    }
    Ok(())
}
/// Circuit-specific single-party setup. Production requires a separately reviewed ceremony.
/// Caller RNG must be a fallible, securely seeded CSPRNG; never seed from a clock or user input.
pub fn setup<R: RngCore + CryptoRng>(circuit: &Circuit, rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let assigned = Assigned {
        circuit: circuit.clone(),
        public: vec![],
        private: vec![],
    };
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(assigned, rng)
        .map_err(|_| INVALID)?;
    let vk = encode_vk(&pk.vk);
    if crate::groth16::rustcrypto_groth16_bn254_vk_validate(vk.as_ptr(), vk.len()) != 0 {
        return Err(INVALID);
    }
    let definition = circuit.to_bytes();
    let mut out = b"RCPK01\0\0".to_vec();
    out.extend_from_slice(&(definition.len() as u32).to_be_bytes());
    out.extend_from_slice(&definition);
    write_point(&mut out, &pk.vk.alpha_g1)?;
    for v in [&pk.vk.beta_g2, &pk.vk.gamma_g2, &pk.vk.delta_g2] {
        write_point(&mut out, v)?;
    }
    write_points(&mut out, &pk.vk.gamma_abc_g1)?;
    write_point(&mut out, &pk.beta_g1)?;
    write_point(&mut out, &pk.delta_g1)?;
    for v in [&pk.a_query, &pk.b_g1_query] {
        write_points(&mut out, v)?;
    }
    write_points(&mut out, &pk.b_g2_query)?;
    for v in [&pk.h_query, &pk.l_query] {
        write_points(&mut out, v)?;
    }
    if out.len() > MAX_KEY_BYTES {
        return Err(INVALID);
    }
    Ok((out, vk))
}
fn load_key(bytes: &[u8], circuit: &Circuit) -> Result<ProvingKey<Bn254>> {
    if bytes.len() > MAX_KEY_BYTES {
        return Err(INVALID);
    }
    let mut r = Reader(bytes);
    if r.take(8)? != b"RCPK01\0\0" {
        return Err(INVALID);
    }
    let n = r.u32()?;
    if n > MAX_CIRCUIT_BYTES || r.take(n)? != circuit.to_bytes() {
        return Err(INVALID);
    }
    let vk = VerifyingKey {
        alpha_g1: r.point::<G1Affine>()?,
        beta_g2: r.point::<G2Affine>()?,
        gamma_g2: r.point()?,
        delta_g2: r.point()?,
        gamma_abc_g1: r.points()?,
    };
    let pk = ProvingKey {
        vk,
        beta_g1: r.point()?,
        delta_g1: r.point()?,
        a_query: r.points()?,
        b_g1_query: r.points()?,
        b_g2_query: r.points()?,
        h_query: r.points()?,
        l_query: r.points()?,
    };
    if !r.0.is_empty() || pk.vk.gamma_abc_g1.len() != circuit.public + 1 {
        return Err(INVALID);
    }
    let vk_bytes = encode_vk(&pk.vk);
    if crate::groth16::rustcrypto_groth16_bn254_vk_validate(vk_bytes.as_ptr(), vk_bytes.len()) != 0
    {
        return Err(INVALID);
    }
    Ok(pk)
}
/// Checks the full witness before proving; returns the existing verifier's 256-byte v1 proof.
pub fn prove<R: RngCore + CryptoRng>(
    circuit: &Circuit,
    key: &[u8],
    public: &[u8],
    private: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let assigned = Assigned {
        circuit: circuit.clone(),
        public: fields(public, circuit.public)?,
        private: secret_fields(private, circuit.private)?,
    };
    let cs = ConstraintSystem::new_ref();
    let wipe = WipeAssignment(cs.clone());
    assigned
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|_| INVALID)?;
    let satisfied = cs.is_satisfied().map_err(|_| INVALID)?;
    let (instances, witness, constraints) = (
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );
    drop(wipe);
    drop(cs);
    if !satisfied {
        return Err(crate::RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }
    let pk = load_key(key, circuit)?;
    let domain = (constraints + instances).next_power_of_two();
    if pk.a_query.len() != instances + witness
        || pk.b_g1_query.len() != instances + witness
        || pk.b_g2_query.len() != instances + witness
        || pk.l_query.len() != witness
        || pk.h_query.len() != domain - 1
    {
        return Err(INVALID);
    }
    let inputs = assigned.public.clone();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(assigned, &pk, rng)
        .map_err(|_| INVALID)?;
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, &inputs)
        .map_err(|_| INVALID)?
    {
        return Err(INVALID);
    }
    Ok(encode_proof(&proof))
}

/// ChaCha20 CSPRNG with zeroizing cipher state. Use a fresh 256-bit host entropy seed.
pub struct ProverRng(chacha20::ChaCha20);
impl ProverRng {
    pub fn from_entropy(seed: &[u8; 32]) -> Self {
        use chacha20::cipher::KeyIvInit;
        Self(chacha20::ChaCha20::new(seed.into(), (&[0u8; 12]).into()))
    }
}
impl CryptoRng for ProverRng {}
impl RngCore for ProverRng {
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
        self.try_fill_bytes(dest)
            .expect("ChaCha20 stream exhausted");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        use chacha20::cipher::StreamCipher;
        dest.fill(0);
        self.0.try_apply_keystream(dest).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}
/// Safe slice interface to the existing verifier; no circuit or key approval implied.
pub fn verify_v1(vk: &[u8], proof: &[u8], inputs: &[u8]) -> i32 {
    crate::groth16::rustcrypto_groth16_bn254_verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        inputs.as_ptr(),
        inputs.len(),
        inputs.len() / 32,
    )
}
