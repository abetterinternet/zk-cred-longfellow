//! Ligero verifier, specified in [Section 4.5][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.5

use crate::{
    constraints::proof_constraints::{
        LinearConstraintLhsTerm, LinearConstraints, QuadraticConstraint,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::committer::LigeroCommitment,
};

use super::prover::LigeroProof;

pub fn ligero_verify<FE: CodecFieldElement + LagrangePolynomialFieldElement>(
    commitment: &LigeroCommitment,
    proof: &LigeroProof<FE>,
    linear_constraints: &LinearConstraints<FE>,
    quadratic_constraints: &[QuadraticConstraint],
) -> Result<(), anyhow::Error> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constraints::proof_constraints::quadratic_constraints, decode_test_vector,
        fields::fieldp128::FieldP128, ligero::TableauLayout, sumcheck::prover::SumcheckProof,
        test_vector::CircuitTestVector, transcript::Transcript, witness::WitnessLayout,
    };
    use std::io::Cursor;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = decode_test_vector!(
            "longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b",
            proofs,
        );

        let public_inputs = &test_vector.valid_inputs()[0..circuit.num_public_inputs()];

        let mut transcript = &mut Transcript::new(b"test").unwrap();

        let sumcheck_proof = SumcheckProof::<FieldP128>::decode(
            &circuit,
            &mut Cursor::new(test_vector.serialized_sumcheck_proof.as_slice()),
        )
        .unwrap();

        let quadratic_constraints = quadratic_constraints(&circuit);

        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            public_inputs,
            &mut transcript,
            &test_vector.ligero_commitment().unwrap(),
            &sumcheck_proof,
        )
        .unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let tableau_layout = TableauLayout::new(
            test_vector.ligero_parameters.as_ref().unwrap(),
            witness_layout.length(),
            quadratic_constraints.len(),
        );
        let ligero_proof = LigeroProof::<FieldP128>::decode(
            &tableau_layout,
            &mut Cursor::new(test_vector.serialized_ligero_proof.as_slice()),
        )
        .unwrap();

        ligero_verify(
            &test_vector.ligero_commitment().unwrap(),
            &ligero_proof,
            &linear_constraints,
            &quadratic_constraints,
        )
        .unwrap();
    }
}
