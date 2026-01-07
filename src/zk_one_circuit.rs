//! The Longfellow ZK protocol, as applied to a single circuit.

pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use crate::{
        circuit::Circuit,
        fields::{ProofFieldElement, field2_128::Field2_128, fieldp128::FieldP128},
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        zk_one_circuit::{
            prover::{Proof, Prover},
            verifier::Verifier,
        },
    };
    use std::io::Cursor;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn test_vector_end_to_end<FE: ProofFieldElement>(
        test_vector: CircuitTestVector,
        circuit: Circuit<FE>,
    ) {
        // Here, we just load the test vector file to get the Ligero parameters,
        // and discard the proof. We generate a fresh proof, using real
        // randomness.
        let all_inputs: Vec<FE> = test_vector.valid_inputs();
        let public_inputs = &all_inputs[..circuit.num_public_inputs() - 1];
        let session_id = b"test";

        let prover = Prover::new(&circuit, *test_vector.ligero_parameters());
        let proof = prover.prove(session_id, &all_inputs).unwrap();

        let verifier = Verifier::new(&circuit, *test_vector.ligero_parameters());
        verifier.verify(public_inputs, &proof).unwrap();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b_end_to_end() {
        let (test_vector, circuit) = load_rfc();
        test_vector_end_to_end::<FieldP128>(test_vector, circuit);
    }

    #[ignore = "slow test"]
    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac_circuit_end_to_end() {
        let (test_vector, circuit) = load_mac();
        test_vector_end_to_end::<Field2_128>(test_vector, circuit);
    }

    #[ignore = "slow test"]
    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b_mutation() {
        let (test_vector, circuit) = load_rfc();
        let all_inputs: Vec<FieldP128> = test_vector.valid_inputs();
        let public_inputs = &all_inputs[..circuit.num_public_inputs() - 1];
        let session_id = b"testtesttesttesttesttesttesttest";

        let prover = Prover::new(&circuit, *test_vector.ligero_parameters());
        let proof = prover.prove(session_id, &all_inputs).unwrap();

        let mut encoded = Vec::new();
        proof.encode(&mut encoded).unwrap();

        let verifier = Verifier::new(&circuit, *test_vector.ligero_parameters());

        // Mutation testing: flip each bit in a proof, and confirm that it either fails to
        // deserialize or fails to verify.
        let mut decode_failure_count = 0;
        let mut verify_failure_count = 0;
        for byte_offset in 0..encoded.len() {
            println!("{byte_offset}/{}", encoded.len());
            for bit_offset in 0..8 {
                let mut modified = encoded.clone();
                modified[byte_offset] ^= 1 << bit_offset;

                let Ok(decoded) =
                    Proof::<FieldP128>::decode(&verifier, &mut Cursor::new(&modified))
                else {
                    decode_failure_count += 1;
                    continue;
                };
                verifier.verify(public_inputs, &decoded).unwrap_err();
                verify_failure_count += 1;
            }
        }
        println!("decoding failed {decode_failure_count} times");
        println!("verifying failed {verify_failure_count} times");
    }
}
