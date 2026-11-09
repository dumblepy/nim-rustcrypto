//! Development single-party setup. No deterministic seeds and no bundled keys.
//! Run: cargo run --release --example groth16_prover_setup -- /tmp/groth16-demo
use rust_crypto_ffi::groth16_prover::{Circuit, setup};
use sha3::{Digest, Sha3_256};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .ok_or("output directory required; optional second argument: RCCIR01 circuit file")?;
    let c = if let Some(path) = args.next() {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((rust_crypto_ffi::groth16_prover::MAX_CIRCUIT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Circuit::from_bytes(&bytes).map_err(|e| format!("circuit: {e}"))?
    } else {
        // Without a file, generate only the documented square commitment demo.
        let mut c = Circuit::new(1, 1).map_err(|e| format!("circuit: {e}"))?;
        let secret = c.private(0).unwrap();
        let square = c.mul(secret, secret).unwrap();
        c.equal(square, c.public(0).unwrap()).unwrap();
        c
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    // OsRng errors must be handled before feeding the infallible arkworks RNG interface.
    use rand_core::RngCore;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand_core::OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|e| format!("entropy: {e}"))?;
    let mut rng = rust_crypto_ffi::groth16_prover::ProverRng::from_entropy(&seed);
    let (pk, vk) = setup(&c, &mut rng).map_err(|e| format!("setup: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    let mut manifest = String::from(
        "profile=groth16-bn254-rccir01-rcpk01\nsetup=development-single-party-NOT-PRODUCTION\n",
    );
    for (name, bytes) in [
        ("circuit.bin", c.to_bytes()),
        ("proving-key.bin", pk),
        ("verifying-key.bin", vk),
    ] {
        let path = std::path::Path::new(&dir).join(name);
        // Refuse accidental overwrite of an existing key distribution.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&bytes)?;
        let digest = Sha3_256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        manifest.push_str(&format!("{name}.sha3-256={digest}\n"));
    }
    std::fs::write(std::path::Path::new(&dir).join("manifest.txt"), manifest)?;
    Ok(())
}
