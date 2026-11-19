use curve25519_dalek::scalar::Scalar;

pub struct Fixture {
    pub circuit: Vec<u8>,
    pub public: Vec<u8>,
    pub witness: Vec<u8>,
}
type Terms = Vec<(u16, Scalar)>;
type Row = [Terms; 3];

fn var(index: u16) -> Terms {
    vec![(index, Scalar::ONE)]
}

fn equality(left: Terms, right: Terms) -> Row {
    [left, var(0), right]
}

fn fixture(public: &[u128], witness: &[u128], committed: u16, rows: &[Row]) -> Fixture {
    let mut circuit = b"BPC1".to_vec();
    for number in [
        public.len() as u16,
        witness.len() as u16,
        committed,
        rows.len() as u16,
    ] {
        circuit.extend(number.to_le_bytes());
    }
    for row in rows {
        for terms in row {
            circuit.extend((terms.len() as u16).to_le_bytes());
            for (index, coefficient) in terms {
                circuit.extend(index.to_le_bytes());
                circuit.extend(coefficient.to_bytes());
            }
        }
    }
    let encode = |values: &[u128]| {
        values
            .iter()
            .flat_map(|&value| Scalar::from(value).to_bytes())
            .collect()
    };
    Fixture {
        circuit,
        public: encode(public),
        witness: encode(witness),
    }
}

/// Two committed factors and a public product. Another public input binds the first factor.
pub fn multiplication() -> Fixture {
    fixture(
        &[42, 6],
        &[6, 7],
        2,
        &[[var(3), var(4), var(1)], equality(var(3), var(2))],
    )
}

fn range(
    index: u16,
    first_bit: u16,
    bits: u16,
    value: u128,
    rows: &mut Vec<Row>,
    witness: &mut Vec<u128>,
) {
    let mut sum = Vec::with_capacity(bits.into());
    for bit in 0..bits {
        let bit_index = first_bit + bit;
        rows.push([
            var(bit_index),
            vec![(0, -Scalar::ONE), (bit_index, Scalar::ONE)],
            vec![],
        ]);
        sum.push((bit_index, Scalar::from(1u128 << bit)));
        witness.push((value >> bit) & 1);
    }
    rows.push(equality(sum, var(index)));
}

pub fn ranged(bits: u16) -> Fixture {
    let value = 1u128 << (bits - 1);
    let mut rows = Vec::new();
    let mut witness = vec![value];
    range(1, 2, bits, value, &mut rows, &mut witness);
    fixture(&[], &witness, 1, &rows)
}

pub fn bounded_sum(bits: u16) -> Fixture {
    let mut rows = vec![equality(vec![(1, Scalar::ONE), (2, Scalar::ONE)], var(3))];
    let mut witness = vec![7, 9, 16];
    for (offset, value) in [7, 9, 16].into_iter().enumerate() {
        range(
            1 + offset as u16,
            4 + offset as u16 * bits,
            bits,
            value,
            &mut rows,
            &mut witness,
        );
    }
    fixture(&[], &witness, 2, &rows)
}
