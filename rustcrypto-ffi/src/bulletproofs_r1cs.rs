//! Experimental one-phase Bulletproofs over a locally approved R1CS.
use bulletproofs::{
    BulletproofGens, PedersenGens,
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier},
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const PROFILE: &[u8] = b"bulletproofs-r1cs-ristretto255-v1";
const GENERATOR_PROFILE: &[u8] =
    b"zkcrypto-bulletproofs-v5.0.1/default-pedersen/chain-v1/n1024/parties1";
pub const CAPACITY: usize = 1024;
pub const MAX_ROWS: usize = 512;
pub const MAX_WITNESS: usize = 1024;
pub const MAX_PUBLIC_INPUTS: usize = 128;
pub const MAX_COMMITMENTS: usize = 64;
pub const MAX_CONTEXT_BYTES: usize = 1024;
pub const MAX_CIRCUIT_BYTES: usize = 256 * 1024;
pub const MAX_BODY_BYTES: usize = 1 + (13 + 2 * 10) * 32;
const HEADER_BYTES: usize = 42;
pub const MAX_PROOF_BYTES: usize = HEADER_BYTES + MAX_BODY_BYTES + MAX_COMMITMENTS * 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    Encoding = -1,
    Limit = -2,
    Count = -3,
    Unsatisfied = -4,
    Randomness = -5,
    Internal = -6,
    Buffer = -7,
}

type Result<T> = std::result::Result<T, Error>;
type ScalarBytes = [u8; 32];

pub struct PublicInputs<'a>(pub &'a [u8]);
pub struct Witness<'a>(pub &'a [u8]);
pub struct Blindings<'a>(pub &'a [u8]);
pub struct Proof<'a>(pub &'a [u8]);
pub struct Commitments<'a>(pub &'a [u8]);

type Combination = Vec<(usize, Scalar)>;

pub struct CircuitDefinition {
    id: [u8; 32],
    public: usize,
    witness: usize,
    committed: usize,
    rows: Vec<[Combination; 3]>,
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let (prefix, rest) = input.split_at_checked(len).ok_or(Error::Encoding)?;
    *input = rest;
    Ok(prefix)
}

fn read_u16(input: &mut &[u8]) -> Result<usize> {
    Ok(u16::from_le_bytes(take(input, 2)?.try_into().unwrap()).into())
}

fn scalar(bytes: &[u8]) -> Result<Scalar> {
    let bytes = Zeroizing::new(ScalarBytes::try_from(bytes).map_err(|_| Error::Encoding)?);
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::Encoding)
}

fn check_point(bytes: &[u8]) -> Result<()> {
    let point = CompressedRistretto(bytes.try_into().map_err(|_| Error::Encoding)?);
    if point.as_bytes() == &[0; 32] || point.decompress().is_none() {
        return Err(Error::Encoding);
    }
    Ok(())
}

pub fn validate_public_inputs(inputs: PublicInputs<'_>) -> Result<()> {
    validate_elements(inputs.0, MAX_PUBLIC_INPUTS, |bytes| {
        scalar(bytes).map(|_| ())
    })
}

pub fn validate_commitments(commitments: Commitments<'_>) -> Result<()> {
    validate_elements(commitments.0, MAX_COMMITMENTS, check_point)
}

fn validate_elements(
    bytes: &[u8],
    limit: usize,
    check: impl Fn(&[u8]) -> Result<()>,
) -> Result<()> {
    if bytes.len() > limit * 32 {
        return Err(Error::Limit);
    }
    if bytes.len() % 32 != 0 {
        return Err(Error::Encoding);
    }
    bytes.chunks_exact(32).try_for_each(check)
}

impl CircuitDefinition {
    /// Decode the verifier's local circuit definition. The proof carries only its hash.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CIRCUIT_BYTES {
            return Err(Error::Limit);
        }
        let mut input = bytes;
        if take(&mut input, 4)? != b"BPC1" {
            return Err(Error::Encoding);
        }
        let public = read_u16(&mut input)?;
        let witness = read_u16(&mut input)?;
        let committed = read_u16(&mut input)?;
        let count = read_u16(&mut input)?;
        if public > MAX_PUBLIC_INPUTS
            || witness > MAX_WITNESS
            || committed > MAX_COMMITMENTS
            || count > MAX_ROWS
            || count + (witness.saturating_sub(committed)).div_ceil(2) > CAPACITY
        {
            return Err(Error::Limit);
        }
        if count == 0 || witness == 0 || committed > witness {
            return Err(Error::Count);
        }
        let mut read_combination = || -> Result<Combination> {
            let count = read_u16(&mut input)?;
            if count > 1 + public + witness {
                return Err(Error::Count);
            }
            let mut terms = Vec::with_capacity(count);
            for _ in 0..count {
                let index = read_u16(&mut input)?;
                let coefficient = scalar(take(&mut input, 32)?)?;
                if index > public + witness
                    || coefficient == Scalar::ZERO
                    || terms.last().is_some_and(|&(previous, _)| previous >= index)
                {
                    return Err(Error::Encoding);
                }
                terms.push((index, coefficient));
            }
            Ok(terms)
        };
        let rows = (0..count)
            .map(|_| {
                Ok([
                    read_combination()?,
                    read_combination()?,
                    read_combination()?,
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        if !input.is_empty() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            id: Sha256::digest(bytes).into(),
            public,
            witness,
            committed,
            rows,
        })
    }

    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub fn multiplication_gates(&self) -> usize {
        self.rows.len() + (self.witness - self.committed).div_ceil(2)
    }

    pub fn proof_body_len(&self) -> usize {
        let rounds = self
            .multiplication_gates()
            .next_power_of_two()
            .trailing_zeros() as usize;
        1 + (13 + 2 * rounds) * 32
    }

    pub fn proof_len(&self) -> usize {
        HEADER_BYTES + self.proof_body_len() + self.committed * 32
    }

    pub fn encoded_generator_bytes(&self) -> usize {
        (2 + 2 * self.multiplication_gates().next_power_of_two()) * 32
    }

    fn transcript(&self, inputs: PublicInputs<'_>, context: &[u8]) -> Result<Transcript> {
        if context.len() > MAX_CONTEXT_BYTES {
            return Err(Error::Limit);
        }
        validate_public_inputs(PublicInputs(inputs.0))?;
        if inputs.0.len() != self.public * 32 {
            return Err(Error::Count);
        }

        let mut transcript = Transcript::new(PROFILE);
        transcript.append_u64(b"proof-system-version", 1);
        transcript.append_message(b"circuit-id", &self.id);
        transcript.append_message(
            b"generator-profile-hash",
            &Sha256::digest(GENERATOR_PROFILE),
        );
        transcript.append_message(b"application-context", context);
        transcript.append_message(b"public-inputs", inputs.0);
        transcript.append_u64(b"commitment-count", self.committed as u64);
        // The backend appends each commitment in order using Merlin's length-framed V label.
        Ok(transcript)
    }

    fn generators(&self) -> BulletproofGens {
        BulletproofGens::new(self.multiplication_gates().next_power_of_two(), 1)
    }

    fn constrain(
        &self,
        cs: &mut impl ConstraintSystem,
        public: &[Scalar],
        mut variables: Vec<Variable>,
        witness: Option<&[Scalar]>,
    ) -> Result<()> {
        for index in self.committed..self.witness {
            let assignment = witness.map(|values| values[index]);
            variables.push(cs.allocate(assignment).map_err(|_| Error::Internal)?);
        }
        let linear = |terms: &Combination| -> LinearCombination {
            terms
                .iter()
                .map(|&(index, coefficient)| {
                    if index <= self.public {
                        (Variable::One(), coefficient * public[index])
                    } else {
                        (variables[index - self.public - 1], coefficient)
                    }
                })
                .collect()
        };
        for [a, b, c] in &self.rows {
            let (_, _, out) = cs.multiply(linear(a), linear(b));
            cs.constrain(out - linear(c));
        }
        Ok(())
    }

    pub fn prove(
        &self,
        inputs: PublicInputs<'_>,
        witness: Witness<'_>,
        context: &[u8],
    ) -> Result<Vec<u8>> {
        self.prove_with_blindings(inputs, witness, Blindings(&[]), context)
    }

    pub fn prove_with_blindings(
        &self,
        inputs: PublicInputs<'_>,
        witness: Witness<'_>,
        blindings: Blindings<'_>,
        context: &[u8],
    ) -> Result<Vec<u8>> {
        let transcript = self.transcript(PublicInputs(inputs.0), context)?;
        if !blindings.0.is_empty() && blindings.0.len() != self.committed * 32 {
            return Err(Error::Count);
        }
        if witness.0.len() != self.witness * 32 {
            return Err(Error::Count);
        }
        let public = read_public(inputs)?;
        // Create the wiping guard before decoding so malformed witness values
        // also clear all assignments decoded earlier in the same request.
        let mut values = Zeroizing::new(Vec::with_capacity(self.witness));
        for bytes in witness.0.chunks_exact(32) {
            values.push(scalar(bytes)?);
        }
        let eval = |terms: &Combination| -> Scalar {
            terms
                .iter()
                .map(|&(index, coefficient)| {
                    coefficient
                        * if index <= self.public {
                            public[index]
                        } else {
                            values[index - self.public - 1]
                        }
                })
                .sum()
        };
        // Visit all rows before reporting an invalid witness.
        let mut satisfied = true;
        for [a, b, c] in &self.rows {
            satisfied &= eval(a) * eval(b) == eval(c);
        }
        if !satisfied {
            return Err(Error::Unsatisfied);
        }

        let pedersen = PedersenGens::default();
        let mut prover = Prover::new(&pedersen, transcript);
        let mut commitments = Vec::with_capacity(self.committed * 32);
        let mut variables = Vec::with_capacity(self.witness);
        for (index, value) in values.iter().take(self.committed).enumerate() {
            let mut blinding = if blindings.0.is_empty() {
                let mut randomness = Zeroizing::new([0; 64]);
                OsRng
                    .try_fill_bytes(&mut *randomness)
                    .map_err(|_| Error::Randomness)?;
                Scalar::from_bytes_mod_order_wide(&randomness)
            } else {
                scalar(&blindings.0[index * 32..(index + 1) * 32])?
            };
            if blinding == Scalar::ZERO {
                return Err(Error::Encoding);
            }
            let (commitment, variable) = prover.commit(*value, blinding);
            blinding.zeroize();
            commitments.extend_from_slice(commitment.as_bytes());
            variables.push(variable);
        }
        self.constrain(&mut prover, &public, variables, Some(&values))?;
        let body = prover
            .prove(&self.generators())
            .map_err(|_| Error::Internal)?
            .to_bytes();
        if body.len() != self.proof_body_len() {
            return Err(Error::Internal);
        }
        let mut proof = Vec::with_capacity(self.proof_len());
        proof.extend_from_slice(b"BPPF\x01\x01");
        proof.extend_from_slice(&self.id);
        proof.extend_from_slice(&(self.committed as u16).to_le_bytes());
        proof.extend_from_slice(&(body.len() as u16).to_le_bytes());
        proof.extend_from_slice(&body);
        proof.extend_from_slice(&commitments);
        decode(Proof(&proof))?;
        Ok(proof)
    }

    pub fn verify(
        &self,
        inputs: PublicInputs<'_>,
        context: &[u8],
        proof: Proof<'_>,
    ) -> Result<bool> {
        self.verify_statement(inputs, context, proof, None)
    }

    pub fn verify_with_commitments(
        &self,
        inputs: PublicInputs<'_>,
        context: &[u8],
        proof: Proof<'_>,
        expected: Commitments<'_>,
    ) -> Result<bool> {
        self.verify_statement(inputs, context, proof, Some(expected))
    }

    fn verify_statement(
        &self,
        inputs: PublicInputs<'_>,
        context: &[u8],
        proof: Proof<'_>,
        expected: Option<Commitments<'_>>,
    ) -> Result<bool> {
        let transcript = self.transcript(PublicInputs(inputs.0), context)?;
        let decoded = decode(proof)?;
        if decoded.id != self.id {
            return Ok(false);
        }
        if decoded.commitments.0.len() != self.committed * 32
            || decoded.body.len() != self.proof_body_len()
        {
            return Err(Error::Count);
        }
        if let Some(expected) = expected {
            validate_commitments(Commitments(expected.0))?;
            if expected.0.len() != self.committed * 32 {
                return Err(Error::Count);
            }
            if expected.0 != decoded.commitments.0 {
                return Ok(false);
            }
        }
        let mut verifier = Verifier::new(transcript);
        let variables = decoded
            .commitments
            .0
            .chunks_exact(32)
            .map(|bytes| verifier.commit(CompressedRistretto(bytes.try_into().unwrap())))
            .collect();
        self.constrain(&mut verifier, &read_public(inputs)?, variables, None)?;
        Ok(verifier
            .verify(&decoded.proof, &PedersenGens::default(), &self.generators())
            .is_ok())
    }
}

fn read_public(inputs: PublicInputs<'_>) -> Result<Vec<Scalar>> {
    std::iter::once(Ok(Scalar::ONE))
        .chain(inputs.0.chunks_exact(32).map(scalar))
        .collect()
}

struct Decoded<'a> {
    id: &'a [u8],
    body: &'a [u8],
    proof: R1CSProof,
    commitments: Commitments<'a>,
}

fn decode(proof: Proof<'_>) -> Result<Decoded<'_>> {
    let mut input = proof.0;
    if input.len() > MAX_PROOF_BYTES {
        return Err(Error::Limit);
    }
    if take(&mut input, 6)? != b"BPPF\x01\x01" {
        return Err(Error::Encoding);
    }
    let id = take(&mut input, 32)?;
    let count = read_u16(&mut input)?;
    let len = read_u16(&mut input)?;
    if count > MAX_COMMITMENTS || len > MAX_BODY_BYTES {
        return Err(Error::Limit);
    }
    let body = take(&mut input, len)?;
    let commitments = take(&mut input, count * 32)?;
    if !input.is_empty() || len < 417 || (len - 417) % 64 != 0 || body[0] != 0 {
        return Err(Error::Encoding);
    }
    validate_commitments(Commitments(commitments))?;
    let points = body[1..257]
        .chunks_exact(32)
        .chain(body[353..len - 64].chunks_exact(32));
    for point in points {
        check_point(point)?;
    }
    let proof = R1CSProof::from_bytes(body).map_err(|_| Error::Encoding)?;
    Ok(Decoded {
        id,
        body,
        proof,
        commitments: Commitments(commitments),
    })
}

pub fn validate_proof(proof: Proof<'_>) -> Result<()> {
    decode(proof).map(|_| ())
}

pub fn proof_commitments(proof: Proof<'_>) -> Result<Commitments<'_>> {
    Ok(decode(proof)?.commitments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulletproofs_r1cs_profile_vectors() {
        let pedersen = PedersenGens::default();
        let generators = BulletproofGens::new(1, 1);
        let first = generators.share(0).G(1).next().unwrap().compress();
        let definition = CircuitDefinition {
            id: [7; 32],
            public: 1,
            witness: 1,
            committed: 1,
            rows: vec![],
        };
        let transcript = definition
            .transcript(PublicInputs(&Scalar::ONE.to_bytes()), b"fixture")
            .unwrap();
        let mut prover = Prover::new(&pedersen, transcript);
        let (commitment, _) = prover.commit(Scalar::from(6u64), Scalar::from(2u64));
        let mut challenge = [0; 32];
        prover
            .transcript()
            .challenge_bytes(b"fixture-challenge", &mut challenge);
        for (value, expected) in [
            (
                pedersen.B.compress().to_bytes(),
                "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
            ),
            (
                pedersen.B_blinding.compress().to_bytes(),
                "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134",
            ),
            (
                first.to_bytes(),
                "fc3b25801422672a6a8d3adb5d8457d4301fe92324b4fc56ae934c8713ddfe2d",
            ),
            (
                commitment.to_bytes(),
                "389618c263c7d60e3297796e0176c99bdaa273e94ea8e442520e59a09bca0302",
            ),
            (
                challenge,
                "6dedf95c223a1db6918ac4998cf7c9b25511019ba4ce2c3c999dad19bc25358e",
            ),
        ] {
            let encoded = value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(encoded, expected);
        }
    }
}
