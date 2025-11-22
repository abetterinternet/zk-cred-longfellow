//! Ligero verifier, specified in [Section 4.5][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.5

use crate::{
    constraints::proof_constraints::{
        LinearConstraintLhsTerm, LinearConstraints, QuadraticConstraint,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{
        TableauLayout,
        committer::LigeroCommitment,
        extend, gather, gather_iter,
        merkle::{MerkleTree, Node},
        prover::{LigeroProof, inner_product_vector},
    },
    transcript::Transcript,
};
use anyhow::anyhow;
use sha2::{Digest, Sha256};

pub fn ligero_verify<FE: CodecFieldElement + LagrangePolynomialFieldElement>(
    commitment: LigeroCommitment,
    proof: &LigeroProof<FE>,
    transcript: &mut Transcript,
    linear_constraints: &LinearConstraints<FE>,
    quadratic_constraints: &[QuadraticConstraint],
    tableau_layout: &TableauLayout,
) -> Result<(), anyhow::Error> {
    // Write 0xdeadbeef, padded to 32 bytes, to the transcript to match what longfellow-zk does
    transcript.write_byte_array(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])?;

    // The blind is also "u" in the specification. Generate one blind element for each witness
    // and quadratic witness row in the tableau.
    let low_degree_test_blind =
        transcript.generate_challenge::<FE>(tableau_layout.num_constraint_rows())?;
    let linear_constraint_alphas = transcript.generate_challenge::<FE>(linear_constraints.len())?;
    let quad_constraint_alphas =
        transcript.generate_challenge::<FE>(3 * quadratic_constraints.len())?;
    let quad_proof_blinding =
        transcript.generate_challenge::<FE>(tableau_layout.num_quadratic_triples())?;

    transcript.write_field_element_array(&proof.low_degree_test_proof)?;
    transcript.write_field_element_array(&proof.dot_proof)?;
    transcript.write_field_element_array(&proof.quadratic_proof.0)?;
    transcript.write_field_element_array(&proof.quadratic_proof.1)?;

    let requested_column_indices = transcript.generate_naturals_without_replacement(
        tableau_layout.num_columns() - tableau_layout.dblock(),
        tableau_layout.num_requested_columns(),
    );

    assert_eq!(
        linear_constraints.right_hand_side_terms().len(),
        linear_constraint_alphas.len()
    );

    // Check that dot product matches linear constraints
    let want_dot_product = linear_constraints
        .right_hand_side_terms()
        .iter()
        .zip(&linear_constraint_alphas)
        .fold(FE::ZERO, |sum, (rhs_term, alpha)| sum + *rhs_term * alpha);
    let proof_dot_product = proof.dot_proof.iter().copied().sum();
    if want_dot_product != proof_dot_product {
        return Err(anyhow!("dot product mismatch"));
    }

    let inner_product_vector = inner_product_vector(
        tableau_layout,
        linear_constraints,
        &linear_constraint_alphas,
        quadratic_constraints,
        &quad_constraint_alphas,
    )?;

    // Check that dot proof matches requested columns
    let mut want_dot_row = proof.tableau_columns[TableauLayout::dot_proof_row()].clone();
    assert_eq!(want_dot_row.len(), tableau_layout.num_requested_columns());
    let mut inner_product_vector_extended = Vec::with_capacity(tableau_layout.block_size());
    for (products, tableau_row) in inner_product_vector
        .chunks(tableau_layout.witnesses_per_row())
        .zip(&proof.tableau_columns)
    {
        inner_product_vector_extended.truncate(0);
        inner_product_vector_extended.resize(tableau_layout.num_requested_columns(), FE::ZERO);
        inner_product_vector_extended.extend(products);
        // Specification interpretation verification: nreq + the witnesses should be block size
        assert_eq!(
            inner_product_vector_extended.len(),
            tableau_layout.block_size()
        );
        let extended = extend(&inner_product_vector_extended, tableau_layout.num_columns());
        for ((our_dot_row_element, inner_product_element), tableau_element) in want_dot_row
            .iter_mut()
            .zip(gather_iter(&extended, &requested_column_indices))
            .zip(tableau_row)
        {
            *our_dot_row_element += inner_product_element * tableau_element;
        }
    }

    let extended_dot_proof = gather(
        &extend(&proof.dot_proof, tableau_layout.num_columns()),
        &requested_column_indices,
    );

    if want_dot_row != extended_dot_proof {
        return Err(anyhow!("dot proof mismatch"));
    }

    // Check that low degree test proof matches
    let mut want_low_degree_row =
        proof.tableau_columns[TableauLayout::low_degree_test_row()].clone();
    assert_eq!(
        want_low_degree_row.len(),
        tableau_layout.num_requested_columns()
    );

    for (proof_column, challenge) in proof
        .tableau_columns
        .iter()
        .skip(tableau_layout.first_witness_row())
        .zip(low_degree_test_blind)
    {
        for (ldt_column, witness_column) in want_low_degree_row.iter_mut().zip(proof_column.iter())
        {
            *ldt_column += challenge * witness_column;
        }
    }

    let extended_low_degree_test_proof = gather(
        &extend(&proof.low_degree_test_proof, tableau_layout.num_columns()),
        &requested_column_indices,
    );

    if want_low_degree_row != extended_low_degree_test_proof {
        return Err(anyhow!("low degree test proof mismatch"));
    }

    // Check that the quadratic proof matches
    let mut want_quadratic_test_row =
        proof.tableau_columns[TableauLayout::quadratic_test_row()].clone();
    assert_eq!(
        want_quadratic_test_row.len(),
        tableau_layout.num_requested_columns()
    );

    let first_x_row = tableau_layout.first_quadratic_constraint_row();
    let first_y_row = first_x_row + tableau_layout.num_quadratic_triples();
    let first_z_row = first_y_row + tableau_layout.num_quadratic_triples();

    for (index, uquad) in quad_proof_blinding.into_iter().enumerate() {
        let x_row = &proof.tableau_columns[first_x_row + index][0..tableau_layout.dblock()];
        let y_row = &proof.tableau_columns[first_y_row + index][0..tableau_layout.dblock()];
        let z_row = &proof.tableau_columns[first_z_row + index][0..tableau_layout.dblock()];

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

    let extended_quadratic_proof = gather(
        &extend(
            &proof.quadratic_proof(tableau_layout),
            tableau_layout.num_columns(),
        ),
        &requested_column_indices,
    );

    if want_quadratic_test_row != extended_quadratic_proof {
        return Err(anyhow!("quadratic proof mismatch"));
    }

    // Check the Merkle tree inclusion proof
    let mut included_nodes = Vec::with_capacity(tableau_layout.num_requested_columns());
    let mut field_element_buf = vec![0u8; FE::num_bytes()];
    for (index, requested_index) in requested_column_indices.iter().enumerate() {
        let mut sha256 = Sha256::new();

        sha256.update(proof.merkle_tree_nonces[index]);
        for row in &proof.tableau_columns {
            field_element_buf.truncate(0);
            row[*requested_index].encode(&mut field_element_buf)?;
            sha256.update(&field_element_buf);
        }
        included_nodes.push(Node::from(sha256));
    }

    MerkleTree::verify(
        Node::from(commitment),
        tableau_layout.num_columns() - tableau_layout.dblock(),
        &included_nodes,
        &requested_column_indices,
        &proof.inclusion_proof,
    )?;

    Ok(())
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
            test_vector.ligero_commitment().unwrap(),
            &ligero_proof,
            &mut transcript,
            &linear_constraints,
            &quadratic_constraints,
            &tableau_layout,
        )
        .unwrap();
    }
}
