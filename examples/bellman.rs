use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};

use pairing::{bls12_381::Bls12, Engine};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Our own SHA-256d gadget. Input and output are in little-endian bit order.
fn sha256d<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
    let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

struct MyCircuit {
    preimage: Option<[u8; 80]>,
}

impl<E: Engine> Circuit<E> for MyCircuit {
    // Compute the values for the bits of the preimage. If we are verifying a proof,
    // we still need to create the same constraints, so we return an equivalent-size
    // Vec of None (indicating that the value of each bit is unknown).
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 80 * 8]
        };
        assert_eq!(bit_values.len(), 80 * 8);
        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = sha256d(cs.namespace(|| "SHA-256(preimage)"), &preimage_bits)?;

        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

fn main() {
    let params = {
        let c = MyCircuit { preimage: None };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    let pvk = groth16::prepare_verifying_key(&params.vk);

    let preimage = [42; 80]; // secret info.

    let hash = Sha256::digest(&Sha256::digest(&preimage));
    let c = MyCircuit {
        preimage: Some(preimage),
    };
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking::<Bls12>(&hash_bits);

    assert!(groth16::verify_proof(&pvk, &proof, &inputs).unwrap());

    println!("Hello, world!");
}
