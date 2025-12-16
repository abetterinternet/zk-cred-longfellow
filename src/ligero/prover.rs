//! Ligero prover, specified in [Section 4.4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4

use crate::{
    Codec,
    constraints::proof_constraints::{
        LinearConstraintLhsTerm, LinearConstraints, QuadraticConstraint,
    },
    fields::{CodecFieldElement, ProofFieldElement},
    ligero::{
        LigeroChallenges,
        merkle::{InclusionProof, MerkleTree},
        tableau::{Tableau, TableauLayout},
        write_hash_of_a, write_proof,
    },
    transcript::Transcript,
};
use anyhow::{Context, anyhow};

const MAX_RUN_LENGTH: usize = 1 << 25;

/// Prove that the commitment satisfies the provided constraints. The provided transcript should
/// have been used in [`LinearConstraints::from_proof`] (or, equivalently,
/// [`crate::sumcheck::prover::SumcheckProver::prove`]).
///
/// This is specified in [4.4][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4
pub fn ligero_prove<FE: ProofFieldElement>(
    transcript: &mut Transcript,
    tableau: &Tableau<FE>,
    merkle_tree: &MerkleTree,
    linear_constraints: &LinearConstraints<FE>,
    quadratic_constraints: &[QuadraticConstraint],
) -> Result<LigeroProof<FE>, anyhow::Error> {
    write_hash_of_a(transcript)?;

    let challenges = LigeroChallenges::generate(
        transcript,
        tableau.layout(),
        linear_constraints.len(),
        quadratic_constraints.len(),
    )?;

    // Sum blinded witness rows into the low degree test
    let mut low_degree_test_proof = tableau.contents()[TableauLayout::low_degree_test_row()]
        [0..tableau.layout().block_size()]
        .to_vec();
    for (witness_row, blind) in tableau
        .contents()
        .iter()
        .skip(tableau.layout().first_witness_row())
        .zip(challenges.low_degree_test_blind)
    {
        for (ldt_column, witness_column) in low_degree_test_proof.iter_mut().zip(witness_row.iter())
        {
            *ldt_column += blind * witness_column;
        }
    }

    // Sum random linear combinations of linear constraints into the dot proof
    let inner_product_vector = inner_product_vector(
        tableau.layout(),
        linear_constraints,
        &challenges.linear_constraint_alphas,
        quadratic_constraints,
        &challenges.quadratic_constraint_alphas,
    )?;

    let mut dot_proof =
        tableau.contents()[TableauLayout::dot_proof_row()][0..tableau.layout().dblock()].to_vec();
    let mut inner_product_vector_extended = Vec::with_capacity(tableau.layout().block_size());
    for (witnesses, tableau_row) in inner_product_vector
        .chunks(tableau.layout().witnesses_per_row())
        .zip(
            tableau
                .contents()
                .iter()
                .skip(tableau.layout().first_witness_row()),
        )
    {
        inner_product_vector_extended.truncate(0);
        inner_product_vector_extended.resize(tableau.layout().num_requested_columns(), FE::ZERO);
        inner_product_vector_extended.extend(witnesses);
        // Specification interpretation verification: nreq + the witnesses should be block size
        assert_eq!(
            inner_product_vector_extended.len(),
            tableau.layout().block_size()
        );

        let ctx = FE::extend_precompute(
            inner_product_vector_extended.len(),
            tableau.layout().dblock(),
        );
        for ((dot_proof_element, inner_product_element), tableau_element) in dot_proof
            .iter_mut()
            .zip(FE::extend(&inner_product_vector_extended, &ctx))
            .zip(tableau_row.iter().take(tableau.layout().dblock()))
        {
            *dot_proof_element += inner_product_element * tableau_element;
        }
    }

    // Check that nothing grew the dot proof behind our back
    assert_eq!(dot_proof.len(), tableau.layout().dblock());

    let mut quadratic_proof = tableau.contents()[TableauLayout::quadratic_test_row()]
        [0..tableau.layout().dblock()]
        .to_vec();

    let first_x_row = tableau.layout().first_quadratic_constraint_row();
    let first_y_row = first_x_row + tableau.layout().num_quadratic_triples();
    let first_z_row = first_y_row + tableau.layout().num_quadratic_triples();

    for (index, challenge) in challenges.quadratic_proof_blind.into_iter().enumerate() {
        let x_row = &tableau.contents()[first_x_row + index];
        let y_row = &tableau.contents()[first_y_row + index];
        let z_row = &tableau.contents()[first_z_row + index];

        // quadratic_proof += uquad[i] * (z[i] - x[i] * y[i])
        for (((proof_element, x), y), z) in
            quadratic_proof.iter_mut().zip(x_row).zip(y_row).zip(z_row)
        {
            *proof_element += challenge * (*z - *x * y);
        }
    }

    // Specification interpretation verification: the middle part of the quadratic proof should
    // be all zeroes.
    assert_eq!(
        &quadratic_proof[tableau.layout().num_requested_columns()..tableau.layout().block_size()],
        vec![FE::ZERO; tableau.layout().block_size() - tableau.layout().num_requested_columns()]
            .as_slice(),
    );

    // Quadratic proof consists of the nonzero parts of the proof
    let quadratic_proof_low = &quadratic_proof[0..tableau.layout().num_requested_columns()];
    let quadratic_proof_high = &quadratic_proof[tableau.layout().block_size()..];

    // Write proofs to the transcript
    write_proof(
        transcript,
        &low_degree_test_proof,
        &dot_proof,
        quadratic_proof_low,
        quadratic_proof_high,
    )?;

    let requested_column_indices = transcript.generate_naturals_without_replacement(
        tableau.layout().num_columns() - tableau.layout().dblock(),
        tableau.layout().num_requested_columns(),
    );

    // The specification for requested_columns suggests we should construct a table of
    // num_requested_columns rows and num_rows columns, whose rows consist of the tableau
    // columns at requested_column_indices, but longfellow-zk doesn't transpose, and we match
    // their behavior.
    // See compute_req in lib/ligero/ligero_prover.h.
    let mut requested_tableau_columns =
        vec![FE::ZERO; tableau.layout().num_requested_columns() * tableau.layout().num_rows()];

    for row in 0..tableau.layout().num_rows() {
        for (column, requested_column_index) in requested_column_indices.iter().enumerate() {
            requested_tableau_columns
                    [row * tableau.layout().num_requested_columns() + column] =
                    // Offset by dblock so we send tableau values and not witnesses. We send few
                    // enough columns that the verifier can't interpolate the polynomial and
                    // recompute witnesses.
                    tableau.contents()[row][*requested_column_index + tableau.layout().dblock()];
        }
    }

    let tableau_columns = requested_tableau_columns
        .chunks(tableau.layout().num_requested_columns())
        .map(|c| c.to_vec())
        .collect();

    // Gather nonces for requested columns.
    let merkle_tree_nonces = requested_column_indices
        .iter()
        .map(|index| merkle_tree.nonces()[*index])
        .collect();

    let inclusion_proof = merkle_tree.prove(requested_column_indices.as_slice());

    Ok(LigeroProof {
        low_degree_test_proof,
        dot_proof,
        quadratic_proof: (quadratic_proof_low.to_vec(), quadratic_proof_high.to_vec()),
        tableau_columns,
        inclusion_proof,
        merkle_tree_nonces,
    })
}

pub fn inner_product_vector<FE: ProofFieldElement>(
    layout: &TableauLayout,
    linear_constraints: &LinearConstraints<FE>,
    linear_constraint_alphas: &[FE],
    quadratic_constraints: &[QuadraticConstraint],
    quadratic_constraint_alphas: &[FE],
) -> Result<Vec<FE>, anyhow::Error> {
    let mut inner_product_vector =
        vec![FE::ZERO; layout.witnesses_per_row() * layout.num_constraint_rows()];

    for LinearConstraintLhsTerm {
        constraint_number,
        witness_index,
        constant_factor,
    } in linear_constraints.left_hand_side_terms()
    {
        inner_product_vector[*witness_index] +=
            linear_constraint_alphas[*constraint_number] * constant_factor;
    }

    // Sum quadratic constraints into IDOT row. Quadratic constraints come after the linear
    // constraints in the inner product vector.
    let xs_start = layout.num_linear_constraint_rows() * layout.witnesses_per_row();
    let ys_start = xs_start + layout.num_quadratic_triples() * layout.witnesses_per_row();
    let zs_start = ys_start + layout.num_quadratic_triples() * layout.witnesses_per_row();

    for i in 0..layout.num_quadratic_triples() {
        for j in 0..layout.witnesses_per_row() {
            let index = j + i * layout.witnesses_per_row();
            if index >= quadratic_constraints.len() {
                break;
            }
            let QuadraticConstraint { x, y, z } = quadratic_constraints[index];
            let alpha_x = quadratic_constraint_alphas[index * 3];
            let alpha_y = quadratic_constraint_alphas[index * 3 + 1];
            let alpha_z = quadratic_constraint_alphas[index * 3 + 2];

            inner_product_vector[xs_start + index] += alpha_x;
            inner_product_vector[x] -= alpha_x;

            inner_product_vector[ys_start + index] += alpha_y;
            inner_product_vector[y] -= alpha_y;

            inner_product_vector[zs_start + index] += alpha_z;
            inner_product_vector[z] -= alpha_z;
        }
    }

    Ok(inner_product_vector)
}

/// A Ligero proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LigeroProof<FieldElement> {
    pub low_degree_test_proof: Vec<FieldElement>,
    pub dot_proof: Vec<FieldElement>,
    pub quadratic_proof: (Vec<FieldElement>, Vec<FieldElement>),
    pub merkle_tree_nonces: Vec<[u8; 32]>,
    pub tableau_columns: Vec<Vec<FieldElement>>,
    pub inclusion_proof: InclusionProof,
}

impl<FE: CodecFieldElement> LigeroProof<FE> {
    /// Deserialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1].
    ///
    /// This can't be a `Codec` implementation because we need the Ligero parameters to know the
    /// sizes of fields.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    pub fn decode(
        layout: &TableauLayout,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let low_degree_test_proof = FE::decode_fixed_array(bytes, layout.block_size())?;
        let dot_proof = FE::decode_fixed_array(bytes, layout.dblock())?;
        let quadratic_proof = (
            FE::decode_fixed_array(bytes, layout.num_requested_columns())?,
            FE::decode_fixed_array(bytes, layout.dblock() - layout.block_size())?,
        );
        let merkle_tree_nonces =
            <[u8; 32]>::decode_fixed_array(bytes, layout.num_requested_columns())?;

        // Columns are serialized as one or more runs, each of which is a length-prefixed vector. A
        // run may contain field or subfield elements.
        let expected_column_elements = layout.num_rows() * layout.num_requested_columns();
        let mut column_elements = Vec::with_capacity(expected_column_elements);
        let mut subfield_run = false;
        while column_elements.len() < layout.num_rows() * layout.num_requested_columns() {
            // Sizes are usually u24 in Longfellow, but in this case it happens to be u32. See
            // `write_size` and `read_size` in lib/zk/zk_proof.h.
            let run_length =
                usize::try_from(u32::decode(bytes)?).context("failed to convert u32 to usize")?;
            if run_length > MAX_RUN_LENGTH {
                return Err(anyhow!("run exceeds maximum run length"));
            }
            if run_length + column_elements.len() > expected_column_elements {
                return Err(anyhow!(
                    "too many column elements in serialized proof: {} > {}",
                    run_length + column_elements.len(),
                    expected_column_elements
                ));
            }
            let run = if subfield_run {
                FE::decode_fixed_array_in_subfield(bytes, run_length)
            } else {
                FE::decode_fixed_array(bytes, run_length)
            }?;
            column_elements.extend(run);
            subfield_run = !subfield_run;
        }
        if column_elements.len() != expected_column_elements {
            return Err(anyhow!(
                "unexpected number of column elements in serialized proof"
            ));
        }

        let tableau_columns = column_elements
            .chunks(layout.num_requested_columns())
            .map(|v| v.to_vec())
            .collect();

        let inclusion_proof = InclusionProof::decode(bytes)?;

        Ok(Self {
            low_degree_test_proof,
            dot_proof,
            quadratic_proof,
            merkle_tree_nonces,
            tableau_columns,
            inclusion_proof,
        })
    }

    /// Serialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1]. This can't be a
    /// `Codec` implementation because we need the Ligero parameters to know the sizes of objects.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        FE::encode_fixed_array(&self.low_degree_test_proof, bytes)?;
        FE::encode_fixed_array(&self.dot_proof, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.0, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.1, bytes)?;
        <[u8; 32]>::encode_fixed_array(&self.merkle_tree_nonces, bytes)?;

        let column_elements: Vec<_> = self.tableau_columns.iter().flat_map(|v| v.iter()).collect();
        let mut column_elements_written = 0;
        let mut is_subfield_run = false;
        while column_elements_written < column_elements.len() {
            // Seek to end of current run
            let mut run_length = 0;
            for element in &column_elements[column_elements_written..] {
                if run_length == MAX_RUN_LENGTH {
                    break;
                }
                if element.fits_in_subfield() == is_subfield_run {
                    run_length += 1;
                }
            }

            u32::try_from(run_length)
                .context("run length too big for u32")?
                .encode(bytes)?;

            for element in
                &column_elements[column_elements_written..column_elements_written + run_length]
            {
                if is_subfield_run {
                    element.encode_in_subfield(bytes)?;
                } else {
                    element.encode(bytes)?;
                }
            }

            column_elements_written += run_length;
            is_subfield_run = !is_subfield_run;
        }

        self.inclusion_proof.encode(bytes)?;

        Ok(())
    }

    /// Stitch the quadratic proof parts back together with the middle span of zeroes.
    pub fn quadratic_proof(&self, layout: &TableauLayout) -> Vec<FE> {
        let mut proof = Vec::with_capacity(layout.dblock());
        proof.extend(&self.quadratic_proof.0);
        proof.resize(layout.block_size(), FE::ZERO);
        proof.extend(&self.quadratic_proof.1);
        assert_eq!(proof.len(), layout.dblock());

        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Evaluation,
        constraints::proof_constraints::quadratic_constraints,
        fields::fieldp128::FieldP128,
        ligero::LigeroCommitment,
        sumcheck::{self, initialize_transcript},
        test_vector::load_rfc,
        transcript::Transcript,
        witness::{Witness, WitnessLayout},
    };
    use std::io::Cursor;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        let ligero_parameters = test_vector.ligero_parameters();

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(&test_vector.valid_inputs()).unwrap();

        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad().unwrap(),
        );

        let quadratic_constraints = quadratic_constraints(&circuit);

        let tableau = Tableau::build_with_field_element_generator(
            &ligero_parameters,
            &witness,
            &quadratic_constraints,
            || test_vector.pad().unwrap(),
        );

        // Fix the nonce to match what longfellow-zk will do: all zeroes, but set the first byte to
        // what the fixed RNG yields.
        let mut merkle_tree_nonce = [0; 32];
        merkle_tree_nonce[0] = test_vector.pad.unwrap() as u8;
        let merkle_tree = tableau
            .commit_with_merkle_tree_nonce_generator(|| merkle_tree_nonce)
            .unwrap();

        let ligero_commitment = LigeroCommitment::from(merkle_tree.root());

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
        let mut transcript = Transcript::new(b"test").unwrap();
        transcript
            .write_byte_array(ligero_commitment.as_bytes())
            .unwrap();
        initialize_transcript(
            &mut transcript,
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )
        .unwrap();

        // Fork the transcript for constraint generation
        let mut constraint_transcript = transcript.clone();

        let sumcheck_proof = sumcheck::prover::SumcheckProver::new(&circuit)
            .prove(&evaluation, &mut transcript, &witness)
            .unwrap();

        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &sumcheck_proof.proof,
        )
        .unwrap();

        assert_eq!(transcript, constraint_transcript);

        let ligero_proof = ligero_prove(
            &mut constraint_transcript,
            &tableau,
            &merkle_tree,
            &linear_constraints,
            &quadratic_constraints,
        )
        .unwrap();

        let mut encoded_ligero_proof = Vec::new();
        ligero_proof.encode(&mut encoded_ligero_proof).unwrap();

        assert_eq!(test_vector.serialized_ligero_proof, encoded_ligero_proof);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn ligero_proof_codec_roundtrip() {
        let (test_vector, circuit) = load_rfc();
        let ligero_parameters = test_vector.ligero_parameters();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let quadratic_constraints = quadratic_constraints(&circuit);
        let tableau_layout = TableauLayout::new(
            &ligero_parameters,
            witness_layout.length(),
            quadratic_constraints.len(),
        );

        let decoded = LigeroProof::<FieldP128>::decode(
            &tableau_layout,
            &mut Cursor::new(test_vector.serialized_ligero_proof.as_slice()),
        )
        .unwrap();
        let mut encoded = Vec::new();
        decoded.encode(&mut encoded).unwrap();

        assert_eq!(test_vector.serialized_ligero_proof, encoded);
    }
}
