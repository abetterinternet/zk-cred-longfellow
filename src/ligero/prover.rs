//! Ligero prover, specified in [Section 4.4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4

use crate::{
    Codec,
    constraints::proof_constraints::{
        LinearConstraintLhsTerm, LinearConstraints, QuadraticConstraint,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{
        TableauLayout, extend,
        merkle::{InclusionProof, MerkleTree},
    },
    transcript::Transcript,
};
use anyhow::{Context, anyhow};

const MAX_RUN_LENGTH: usize = 1 << 25;

/// Prover for Ligero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LigeroProver<'a> {
    tableau_layout: &'a TableauLayout<'a>,
}

impl<'a> LigeroProver<'a> {
    /// Construct a new prover from the Ligero parameters.
    pub fn new(tableau_layout: &'a TableauLayout<'a>) -> Self {
        Self { tableau_layout }
    }

    /// Prove that the commitment satisfies the provided constraints. The provided transcript should
    /// have been used in [`LinearConstraints::from_proof`] (or, equivalently,
    /// [`SumcheckProver::prove`]).
    ///
    /// This is specified in [4.4][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4
    pub fn prove<FE: CodecFieldElement + LagrangePolynomialFieldElement>(
        &mut self,
        transcript: &mut Transcript,
        tableau: &[Vec<FE>],
        merkle_tree: &MerkleTree,
        merkle_tree_nonces: &[[u8; 32]],
        linear_constraints: &LinearConstraints<FE>,
        quadratic_constraints: &[QuadraticConstraint],
    ) -> Result<LigeroProof<FE>, anyhow::Error> {
        // Write 0xdeadbeef, padded to 32 bytes, to the transcript to match what longfellow-zk does
        transcript.write_byte_array(&[
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])?;

        // The blind is also "u" in the specification. Generate one blind element for each witness
        // and quadratic witness row in the tableau.
        let low_degree_test_blind = transcript
            .generate_challenge::<FE>(tableau.len() - self.tableau_layout.first_witness_row())?;

        // Sum tableau rows into the low degree test
        let mut low_degree_test_proof = tableau[0][0..self.tableau_layout.block_size()].to_vec();
        for (witness_row, challenge) in tableau
            .iter()
            .skip(self.tableau_layout.first_witness_row())
            .zip(low_degree_test_blind)
        {
            for (ldt_column, witness_column) in
                low_degree_test_proof.iter_mut().zip(witness_row.iter())
            {
                *ldt_column += challenge * witness_column;
            }
        }

        // Sum random linear combinations of linear constraints into IDOT row
        let mut inner_product_vector = vec![
            FE::ZERO;
            self.tableau_layout.witnesses_per_row()
                * self.tableau_layout.num_constraint_rows()
        ];

        let linear_constraint_alpha =
            transcript.generate_challenge::<FE>(linear_constraints.len())?;
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in linear_constraints.left_hand_side_terms()
        {
            inner_product_vector[*witness_index] +=
                linear_constraint_alpha[*constraint_number] * constant_factor;
        }

        // Sum quadratic constraints into IDOT row
        let quad_constraint_alphas =
            transcript.generate_challenge::<FE>(3 * quadratic_constraints.len())?;

        // Quadratic constraints come after the linear constraints in the inner product vector
        let xs_start = self.tableau_layout.num_linear_constraint_rows()
            * self.tableau_layout.witnesses_per_row();
        let ys_start = xs_start
            + self.tableau_layout.num_quadratic_triples() * self.tableau_layout.witnesses_per_row();
        let zs_start = ys_start
            + self.tableau_layout.num_quadratic_triples() * self.tableau_layout.witnesses_per_row();

        for i in 0..self.tableau_layout.num_quadratic_triples() {
            for j in 0..self.tableau_layout.witnesses_per_row() {
                let index = j + i * self.tableau_layout.witnesses_per_row();
                if index >= quadratic_constraints.len() {
                    break;
                }
                let QuadraticConstraint { x, y, z } = quadratic_constraints[index];
                let alpha_x = quad_constraint_alphas[index * 3];
                let alpha_y = quad_constraint_alphas[index * 3 + 1];
                let alpha_z = quad_constraint_alphas[index * 3 + 2];

                inner_product_vector[xs_start + index] += alpha_x;
                inner_product_vector[x] -= alpha_x;

                inner_product_vector[ys_start + index] += alpha_y;
                inner_product_vector[y] -= alpha_y;

                inner_product_vector[zs_start + index] += alpha_z;
                inner_product_vector[z] -= alpha_z;
            }
        }

        let mut dot_proof = tableau[1][0..self.tableau_layout.dblock()].to_vec();
        let mut inner_product_vector_extended =
            Vec::with_capacity(self.tableau_layout.block_size());
        for (witnesses, tableau_row) in inner_product_vector
            .chunks(self.tableau_layout.witnesses_per_row())
            .zip(tableau.iter().skip(self.tableau_layout.first_witness_row()))
        {
            inner_product_vector_extended.truncate(0);
            inner_product_vector_extended.extend(std::iter::repeat_n(
                FE::ZERO,
                self.tableau_layout.num_requested_columns(),
            ));
            inner_product_vector_extended.extend(witnesses);
            // Specification interpretation verification: nreq + the witnesses should be block size
            assert_eq!(
                inner_product_vector_extended.len(),
                self.tableau_layout.block_size()
            );

            for ((dot_proof_element, inner_product_element), tableau_element) in dot_proof
                .iter_mut()
                .zip(extend(
                    &inner_product_vector_extended,
                    self.tableau_layout.dblock(),
                ))
                .zip(tableau_row.iter().take(self.tableau_layout.dblock()))
            {
                *dot_proof_element += inner_product_element * tableau_element;
            }
        }

        // Check that nothing grew the dot proof behind our back
        assert_eq!(dot_proof.len(), self.tableau_layout.dblock());

        let quad_proof_blinding =
            transcript.generate_challenge::<FE>(self.tableau_layout.num_quadratic_triples())?;

        let mut quadratic_proof = tableau[2][0..self.tableau_layout.dblock()].to_vec();

        let first_x_row = self.tableau_layout.first_quadratic_constraint_row();
        let first_y_row = first_x_row + self.tableau_layout.num_quadratic_triples();
        let first_z_row = first_y_row + self.tableau_layout.num_quadratic_triples();

        for (index, uquad) in quad_proof_blinding.into_iter().enumerate() {
            let x_row = &tableau[first_x_row + index][0..self.tableau_layout.dblock()];
            let y_row = &tableau[first_y_row + index][0..self.tableau_layout.dblock()];
            let z_row = &tableau[first_z_row + index][0..self.tableau_layout.dblock()];

            // quadratic_proof += quad[i] * (z[i] - x[i] * y[i])
            for (((proof_element, x_element), y_element), z_element) in
                quadratic_proof.iter_mut().zip(x_row).zip(y_row).zip(z_row)
            {
                *proof_element += uquad * (*z_element - *x_element * y_element);
            }
        }

        // Specification interpretation verification: the middle part of the quadratic proof should
        // be all zeroes.
        assert_eq!(
            &quadratic_proof
                [self.tableau_layout.num_requested_columns()..self.tableau_layout.block_size()],
            vec![
                FE::ZERO;
                self.tableau_layout.block_size() - self.tableau_layout.num_requested_columns()
            ]
            .as_slice(),
        );

        // Quadratic proof consists of the nonzero parts of the proof
        let quadratic_proof_low = &quadratic_proof[0..self.tableau_layout.num_requested_columns()];
        let quadratic_proof_high = &quadratic_proof[self.tableau_layout.block_size()..];

        // Write proofs to the transcript
        transcript.write_field_element_array(&low_degree_test_proof)?;
        transcript.write_field_element_array(&dot_proof)?;
        transcript.write_field_element_array(quadratic_proof_low)?;
        transcript.write_field_element_array(quadratic_proof_high)?;

        let requested_column_indices = transcript.generate_naturals_without_replacement(
            self.tableau_layout.num_columns() - self.tableau_layout.dblock(),
            self.tableau_layout.num_requested_columns(),
        );

        // The specification for `requested_columns` says we should construct a table of
        // num_requested_columns rows and num_rows columns, whose rows consist of the tableau
        // columns at requested_column_indices.
        // But that's not what longfellow-zk does: first, it doesn't transpose the requested columns
        // as we might expect. Second, it offsets the requested column indices by DBLOCK, for an
        // unclear reason.
        // See `compute_req` in `lib/ligero/ligero_prover.h`.
        let mut requested_tableau_columns = vec![
            FE::ZERO;
            self.tableau_layout.num_rows()
                * self.tableau_layout.num_requested_columns()
        ];

        for row in 0..self.tableau_layout.num_rows() {
            for (column, requested_column_index) in requested_column_indices.iter().enumerate() {
                requested_tableau_columns
                    [row * self.tableau_layout.num_requested_columns() + column] =
                    tableau[row][*requested_column_index + self.tableau_layout.dblock()];
            }
        }

        let requested_tableau_columns = requested_tableau_columns
            .chunks(self.tableau_layout.num_rows())
            .map(|c| c.to_vec())
            .collect();

        let merkle_tree_nonces = merkle_tree_nonces
            .iter()
            .copied()
            .enumerate()
            .filter(|(index, _)| requested_column_indices.contains(index))
            .map(|(_, nonce)| nonce)
            .collect();

        let inclusion_proof = merkle_tree.prove(requested_column_indices.as_slice());

        Ok(LigeroProof {
            low_degree_test_proof,
            dot_proof,
            quadratic_proof: (quadratic_proof_low.to_vec(), quadratic_proof_high.to_vec()),
            requested_tableau_columns,
            inclusion_proof,
            merkle_tree_nonces,
        })
    }
}

/// A Ligero proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LigeroProof<FieldElement> {
    low_degree_test_proof: Vec<FieldElement>,
    dot_proof: Vec<FieldElement>,
    quadratic_proof: (Vec<FieldElement>, Vec<FieldElement>),
    merkle_tree_nonces: Vec<[u8; 32]>,
    requested_tableau_columns: Vec<Vec<FieldElement>>,
    inclusion_proof: InclusionProof,
}

impl<FE: CodecFieldElement> LigeroProof<FE> {
    /// Deserialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1].
    ///
    /// This can't be a `Codec` implementation because we need the Ligero parameters to know the
    /// sizes of fields.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    #[allow(dead_code)]
    fn decode(
        tableau_layout: &TableauLayout,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let low_degree_test_proof = FE::decode_fixed_array(bytes, tableau_layout.block_size())?;
        let dot_proof = FE::decode_fixed_array(bytes, tableau_layout.dblock())?;
        let quadratic_proof = (
            FE::decode_fixed_array(bytes, tableau_layout.num_requested_columns())?,
            FE::decode_fixed_array(bytes, tableau_layout.dblock() - tableau_layout.block_size())?,
        );
        let merkle_tree_nonces =
            <[u8; 32]>::decode_fixed_array(bytes, tableau_layout.num_requested_columns())?;

        // Columns are serialized as one or more runs, each of which is a length-prefixed vector. A
        // run may contain field or subfield elements.
        let expected_column_elements =
            tableau_layout.num_rows() * tableau_layout.num_requested_columns();
        let mut column_elements = Vec::with_capacity(expected_column_elements);
        let mut subfield_run = false;
        while column_elements.len()
            < tableau_layout.num_rows() * tableau_layout.num_requested_columns()
        {
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
            .chunks(tableau_layout.num_rows())
            .map(|v| v.to_vec())
            .collect();

        let inclusion_proof = InclusionProof::decode(bytes)?;

        Ok(Self {
            low_degree_test_proof,
            dot_proof,
            quadratic_proof,
            merkle_tree_nonces,
            requested_tableau_columns: tableau_columns,
            inclusion_proof,
        })
    }

    /// Serialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1]. This can't be a
    /// `Codec` implementation because we need the Ligero parameters to know the sizes of objects.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    #[allow(dead_code)]
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        FE::encode_fixed_array(&self.low_degree_test_proof, bytes)?;
        FE::encode_fixed_array(&self.dot_proof, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.0, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.1, bytes)?;
        <[u8; 32]>::encode_fixed_array(&self.merkle_tree_nonces, bytes)?;

        let column_elements: Vec<_> = self
            .requested_tableau_columns
            .iter()
            .flat_map(|v| v.iter())
            .collect();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Evaluation,
        constraints::proof_constraints::quadratic_constraints,
        decode_test_vector,
        fields::fieldp128::FieldP128,
        ligero::committer::LigeroCommitment,
        sumcheck,
        test_vector::CircuitTestVector,
        transcript::Transcript,
        witness::{Witness, WitnessLayout},
    };
    use std::io::Cursor;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = decode_test_vector!(
            "longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b",
            proofs,
        );

        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(test_vector.valid_inputs.as_deref().unwrap())
            .unwrap();

        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad().unwrap(),
        );

        let quadratic_constraints = quadratic_constraints(&circuit);

        let tableau_layout = TableauLayout::new(
            test_vector.ligero_parameters.as_ref().unwrap(),
            witness.len(),
            quadratic_constraints.len(),
        );

        // Fix the nonce to match what longfellow-zk will do: all zeroes, but set the first byte to
        // what the fixed RNG yields.
        let mut merkle_tree_nonce = [0; 32];
        merkle_tree_nonce[0] = test_vector.pad.unwrap() as u8;

        let (merkle_tree, tableau, merkle_tree_nonces) = LigeroCommitment::commit(
            &tableau_layout,
            &witness,
            &quadratic_constraints,
            || test_vector.pad().unwrap(),
            || merkle_tree_nonce,
        )
        .unwrap();

        let ligero_commitment = LigeroCommitment::from(merkle_tree.root());

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
        let mut transcript = Transcript::new(b"test").unwrap();
        // Fork the transcript for constraint generation
        let mut constraint_transcript = transcript.clone();

        let sumcheck_proof = sumcheck::prover::SumcheckProver::new(&circuit)
            .prove(
                &evaluation,
                &mut transcript,
                &test_vector.ligero_commitment().unwrap(),
                &witness,
            )
            .unwrap();

        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &ligero_commitment,
            &sumcheck_proof.proof,
        )
        .unwrap();

        let ligero_proof = LigeroProver::new(&tableau_layout)
            .prove(
                &mut constraint_transcript,
                tableau.iter().as_ref(),
                &merkle_tree,
                &merkle_tree_nonces,
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
        let (test_vector, circuit) = decode_test_vector!(
            "longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b",
            proofs,
        );

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let quadratic_constraints = quadratic_constraints(&circuit);
        let tableau_layout = TableauLayout::new(
            test_vector.ligero_parameters.as_ref().unwrap(),
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
