//! Ligero prover, specified in [Section 4.4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4

use crate::{
    Codec,
    fields::CodecFieldElement,
    ligero::{TableauLayout, merkle::InclusionProof},
};
use anyhow::{Context, anyhow};

const MAX_RUN_LENGTH: usize = 1 << 25;

/// A Ligero proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LigeroProof<FieldElement> {
    low_degree_test_proof: Vec<FieldElement>,
    dot_proof: Vec<FieldElement>,
    quadratic_proof: (Vec<FieldElement>, Vec<FieldElement>),
    merkle_tree_nonces: Vec<[u8; 32]>,
    tableau_columns: Vec<Vec<FieldElement>>,
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
            FE::decode_fixed_array(bytes, tableau_layout.nreq())?,
            FE::decode_fixed_array(bytes, tableau_layout.dblock() - tableau_layout.block_size())?,
        );
        let merkle_tree_nonces = <[u8; 32]>::decode_fixed_array(bytes, tableau_layout.nreq())?;

        // Columns are serialized as one or more runs, each of which is a length-prefixed vector. A
        // run may contain field or subfield elements.
        let expected_column_elements = tableau_layout.num_rows() * tableau_layout.nreq();
        let mut column_elements = Vec::with_capacity(expected_column_elements);
        let mut subfield_run = false;
        while column_elements.len() < tableau_layout.num_rows() * tableau_layout.nreq() {
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
            tableau_columns,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constraints::proof_constraints::quadratic_constraints, decode_test_vector,
        fields::fieldp128::FieldP128, test_vector::CircuitTestVector, witness::WitnessLayout,
    };
    use std::io::Cursor;

    #[test]
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
