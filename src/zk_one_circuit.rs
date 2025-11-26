//! The Longfellow ZK protocol, as applied to a single circuit.

pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use crate::{
        decode_test_vector,
        fields::fieldp128::FieldP128,
        test_vector::CircuitTestVector,
        zk_one_circuit::{prover::Prover, verifier::Verifier},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b_end_to_end() {
        // Here, we just load the test vector file to get the Ligero parameters,
        // and discard the proof. We generate a fresh proof, using real
        // randomness.
        let (test_vector, circuit) =
            decode_test_vector!("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");
        let ligero_parameters = test_vector.ligero_parameters();
        let all_inputs: Vec<FieldP128> = test_vector.valid_inputs();
        let public_inputs = &all_inputs[..circuit.num_public_inputs() - 1];
        let session_id = b"test";

        let prover = Prover::new(&circuit, ligero_parameters.clone());
        let proof = prover.prove(session_id, &all_inputs).unwrap();

        let verifier = Verifier::new(&circuit, ligero_parameters);
        verifier.verify(public_inputs, &proof).unwrap();
    }
}
