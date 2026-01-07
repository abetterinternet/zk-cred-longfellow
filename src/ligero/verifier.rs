//! Ligero verifier, specified in [Section 4.5][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.5

use crate::{
    constraints::proof_constraints::{LinearConstraints, QuadraticConstraint},
    fields::ProofFieldElement,
    ligero::{
        LigeroChallenges, LigeroCommitment,
        merkle::{MerkleTree, Node},
        prover::{LigeroProof, inner_product_vector},
        tableau::TableauLayout,
        write_hash_of_a, write_proof,
    },
    transcript::Transcript,
};
use anyhow::{Context, anyhow};
use sha2::{Digest, Sha256};

pub fn ligero_verify<FE: ProofFieldElement>(
    commitment: LigeroCommitment,
    proof: &LigeroProof<FE>,
    transcript: &mut Transcript,
    linear_constraints: &LinearConstraints<FE>,
    quadratic_constraints: &[QuadraticConstraint],
    layout: &TableauLayout,
) -> Result<(), anyhow::Error> {
    write_hash_of_a(transcript)?;

    let challenges = LigeroChallenges::generate(
        transcript,
        layout,
        linear_constraints.len(),
        quadratic_constraints.len(),
    )?;

    write_proof(
        transcript,
        &proof.low_degree_test_proof,
        &proof.dot_proof,
        &proof.quadratic_proof.0,
        &proof.quadratic_proof.1,
    )?;

    let requested_column_indices = transcript.generate_naturals_without_replacement(
        layout.num_columns() - layout.dblock(),
        layout.num_requested_columns(),
    );

    // Check that low degree test proof matches
    let mut want_low_degree_row =
        proof.tableau_columns[TableauLayout::low_degree_test_row()].clone();

    for (proof_row, challenge) in proof
        .tableau_columns
        .iter()
        .skip(layout.first_witness_row())
        .zip(challenges.low_degree_test_blind)
    {
        for (ldt_element, proof_element) in want_low_degree_row.iter_mut().zip(proof_row.iter()) {
            *ldt_element += challenge * proof_element;
        }
    }

    let context_block = FE::extend_precompute(layout.block_size(), layout.num_columns());
    let proof_low_degree_test_row = layout.gather(
        &FE::extend(&proof.low_degree_test_proof, &context_block),
        &requested_column_indices,
    );

    if want_low_degree_row != proof_low_degree_test_row {
        return Err(anyhow!("low degree test proof mismatch"));
    }

    // Check that dot product matches linear constraints
    let want_dot_product = linear_constraints
        .right_hand_side_terms()
        .iter()
        .zip(&challenges.linear_constraint_alphas)
        .fold(FE::ZERO, |sum, (rhs_term, alpha)| sum + *rhs_term * alpha);
    let proof_dot_product = proof
        .dot_proof
        .iter()
        // Skip the nreq random values at the start of the row. The proof only sums over the
        // witnesses.
        // Not documented in the specification.
        .skip(layout.num_requested_columns())
        .take(layout.witnesses_per_row())
        .fold(FE::ZERO, |sum, term| sum + term);
    if want_dot_product != proof_dot_product {
        return Err(anyhow!("dot product mismatch"));
    }

    let inner_product_vector = inner_product_vector(
        layout,
        linear_constraints,
        &challenges.linear_constraint_alphas,
        quadratic_constraints,
        &challenges.quadratic_constraint_alphas,
    )?;

    // Check that dot proof matches requested columns
    let mut want_dot_row = proof.tableau_columns[TableauLayout::dot_proof_row()].clone();
    let mut inner_product_vector_extended = Vec::with_capacity(layout.block_size());
    // inner_product_vector's length is divisible by witnesses_per_row
    for (products, tableau_row) in inner_product_vector
        .chunks(layout.witnesses_per_row())
        .zip(&proof.tableau_columns[layout.first_witness_row()..])
    {
        inner_product_vector_extended.truncate(0);
        inner_product_vector_extended.resize(layout.num_requested_columns(), FE::ZERO);
        inner_product_vector_extended.extend(products);

        let extended = FE::extend(&inner_product_vector_extended, &context_block);
        for ((want_dot_row_element, inner_product_element), tableau_element) in want_dot_row
            .iter_mut()
            .zip(layout.gather_iter(&extended, &requested_column_indices))
            .zip(tableau_row)
        {
            *want_dot_row_element += inner_product_element * tableau_element;
        }
    }

    let context_dblock = FE::extend_precompute(layout.dblock(), layout.num_columns());
    let proof_dot_row = layout.gather(
        &FE::extend(&proof.dot_proof, &context_dblock),
        &requested_column_indices,
    );

    if want_dot_row != proof_dot_row {
        return Err(anyhow!("dot proof mismatch"));
    }

    // Check that the quadratic proof matches
    let mut want_quadratic_test_row =
        proof.tableau_columns[TableauLayout::quadratic_test_row()].clone();

    let first_x_row = layout.first_quadratic_constraint_row();
    let first_y_row = first_x_row + layout.num_quadratic_triples();
    let first_z_row = first_y_row + layout.num_quadratic_triples();

    for (index, uquad) in challenges.quadratic_proof_blind.into_iter().enumerate() {
        let x_row = &proof.tableau_columns[first_x_row + index];
        let y_row = &proof.tableau_columns[first_y_row + index];
        let z_row = &proof.tableau_columns[first_z_row + index];

        // quadratic_proof += uquad[i] * (z[i] - x[i] * y[i])
        for (((proof_element, x_element), y_element), z_element) in want_quadratic_test_row
            .iter_mut()
            .zip(x_row)
            .zip(y_row)
            .zip(z_row)
        {
            *proof_element += uquad * (*z_element - *x_element * y_element);
        }
    }

    let proof_quadratic_test_row = layout.gather(
        &FE::extend(&proof.quadratic_proof(layout), &context_dblock),
        &requested_column_indices,
    );

    if want_quadratic_test_row != proof_quadratic_test_row {
        return Err(anyhow!("quadratic proof mismatch"));
    }

    // Check the Merkle tree inclusion proof
    let mut included_nodes = Vec::with_capacity(layout.num_requested_columns());
    let mut field_element_buf = vec![0u8; FE::num_bytes()];
    // The columns in the proof appear in the same order as the requested column indices.
    for index in 0..requested_column_indices.len() {
        let mut sha256 = Sha256::new();

        sha256.update(proof.merkle_tree_nonces[index]);
        for row in &proof.tableau_columns {
            field_element_buf.truncate(0);
            row[index].encode(&mut field_element_buf)?;
            sha256.update(&field_element_buf);
        }
        included_nodes.push(Node::from(sha256));
    }

    MerkleTree::verify(
        Node::from(commitment),
        layout.num_columns() - layout.dblock(),
        &included_nodes,
        &requested_column_indices,
        &proof.inclusion_proof,
    )
    .context("Merkle tree inclusion proof failure")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Circuit,
        constraints::proof_constraints::quadratic_constraints,
        fields::{field2_128::Field2_128, fieldp128::FieldP128},
        ligero::tableau::TableauLayout,
        sumcheck::initialize_transcript,
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        transcript::Transcript,
        witness::WitnessLayout,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    fn verify<FE: ProofFieldElement>(test_vector: CircuitTestVector, circuit: Circuit<FE>) {
        // hack: prepend 1 to the inputs just like Circuit::evaluate does
        let mut public_inputs = vec![FE::ONE];
        public_inputs.extend(test_vector.valid_inputs::<FE>());

        let mut transcript = Transcript::new(b"test").unwrap();

        let quadratic_constraints = quadratic_constraints(&circuit);

        transcript
            .write_byte_array(test_vector.ligero_commitment().as_bytes())
            .unwrap();
        initialize_transcript(
            &mut transcript,
            &circuit,
            &public_inputs[0..circuit.num_public_inputs()],
        )
        .unwrap();
        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            &public_inputs[0..circuit.num_public_inputs()],
            &mut transcript,
            &test_vector.sumcheck_proof(&circuit),
        )
        .unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let tableau_layout = TableauLayout::new(
            test_vector.ligero_parameters(),
            witness_layout.length(),
            quadratic_constraints.len(),
        );

        ligero_verify(
            test_vector.ligero_commitment(),
            &test_vector.ligero_proof(&tableau_layout),
            &mut transcript,
            &linear_constraints,
            &quadratic_constraints,
            &tableau_layout,
        )
        .unwrap();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        verify::<FieldP128>(test_vector, circuit);
    }

    #[ignore = "slow test"]
    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac() {
        let (test_vector, circuit) = load_mac();
        verify::<Field2_128>(test_vector, circuit);
    }
}
