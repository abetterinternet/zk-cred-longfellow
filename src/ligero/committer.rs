//! Ligero committer, specified in [Section 4.3][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3

use crate::{
    constraints::proof_constraints::QuadraticConstraint,
    fields::{CodecFieldElement, LagrangePolynomialFieldElement, field_element_iter_from_source},
    ligero::{
        TableauLayout, extend,
        merkle::{MerkleTree, Node},
    },
    witness::Witness,
};
use anyhow::Context;
use sha2::{Digest, Sha256};

/// A commitment to a witness vector, as specified in [1]. Concretely, this is the root of a Merkle
/// tree of SHA-256 hashes.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LigeroCommitment([u8; 32]);

impl TryFrom<&[u8]> for LigeroCommitment {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let commitment: [u8; 32] = value
            .try_into()
            .context("byte slice wrong size for commitment")?;
        Ok(LigeroCommitment(commitment))
    }
}

impl LigeroCommitment {
    /// The commitment as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A fake but well-formed commitment for tests.
    #[cfg(test)]
    pub fn test_commitment() -> Self {
        Self::try_from([1u8; 32].as_slice()).unwrap()
    }

    /// Compute a Ligero commitment to the witness vector and the quadratic constraints. The layout
    /// of the commitment is specified in [1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
    ///
    /// This function could probably allocate a whole lot less by allocating vecs up front.
    pub fn commit<FE, TableauGenerator, MerkleTreeNonceGenerator>(
        tableau_layout: &TableauLayout,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
        tableau_generator: TableauGenerator,
        mut merkle_tree_nonce_generator: MerkleTreeNonceGenerator,
    ) -> Result<Self, anyhow::Error>
    where
        FE: LagrangePolynomialFieldElement + CodecFieldElement,
        TableauGenerator: FnMut() -> FE,
        MerkleTreeNonceGenerator: FnMut() -> [u8; 32],
    {
        // Rows for the witnesses, but not the quadratic constraints
        let num_witness_rows = tableau_layout.num_linear_constraint_rows();
        // Each quadratic constraint contributes three witnesses
        let num_quadratic_rows = tableau_layout.num_quadratic_rows();
        // Rows for low degree test, linear test and quadratic test
        let mut tableau = Vec::with_capacity(tableau_layout.num_rows());

        let mut element_generator = field_element_iter_from_source(tableau_generator);

        // Construct the tableau matrix from the witness and the constraints.
        // Fill the low degree test row: extend(RANDOM[BLOCK], BLOCK, NCOL)
        let base_row = element_generator
            .by_ref()
            .take(tableau_layout.block_size())
            .collect::<Vec<_>>();
        tableau.push(extend(&base_row, tableau_layout.num_columns()));

        // Fill the linear test row ("IDOT"): random field elements where elements [nreq..nreq+wr)
        // sum to 0, extended to NCOL
        let mut sum = FE::ZERO;
        let mut index = 0;
        let mut row_random_elements = element_generator.by_ref().take(tableau_layout.dblock() - 1);

        let mut z: Vec<_> = std::iter::from_fn(|| {
            let element = if index == tableau_layout.nreq() {
                // Reserve the first witness spot for the additive inverse of the sum of the
                // remaining witnesses. Per the spec we could put this element anywhere in the
                // witnesses, but this matches longfellow-zk and makes it easier to test against
                // their tableau and commitment.
                Some(FE::ZERO)
            } else {
                let element = row_random_elements.next();
                if (tableau_layout.nreq() + 1
                    ..tableau_layout.nreq() + tableau_layout.witnesses_per_row())
                    .contains(&index)
                {
                    // Unwrap safety: the iterator should contain exactly the number of elements we
                    // need, so a panic here means we have misinterpreted the specification.
                    sum += element.unwrap();
                }
                element
            };

            index += 1;
            element
        })
        .take(tableau_layout.dblock())
        .collect();

        z[tableau_layout.nreq()] = -sum;
        // Specification interpretation verification: we should have consumed row_random_elements
        assert_eq!(row_random_elements.next(), None);
        // Specification interpretation verification: make sure range nreq..nreq+wr sums to 0.
        assert_eq!(
            FE::ZERO,
            z.iter()
                .skip(tableau_layout.nreq())
                .take(tableau_layout.witnesses_per_row())
                .fold(FE::ZERO, |acc, elem| acc + elem)
        );
        tableau.push(extend(&z, tableau_layout.num_columns()));

        // Quadratic test row: NREQ random elements then zeroes for each witness, then more random
        // elements to fill to DBLOCK, then extended to NCOL
        let mut index = 0;
        let zq: Vec<_> = std::iter::from_fn(|| {
            let next = if index < tableau_layout.nreq()
                || index >= tableau_layout.nreq() + tableau_layout.witnesses_per_row()
            {
                element_generator.next()
            } else {
                Some(FE::ZERO)
            };

            index += 1;
            next
        })
        .take(tableau_layout.dblock())
        .collect();
        tableau.push(extend(zq.as_slice(), tableau_layout.num_columns()));

        // Padded witness rows: NREQ random elements, then witnesses_per_row elements of the witness
        // extended to NCOL
        for witness_row in 0..num_witness_rows {
            tableau.push(extend(
                element_generator
                    .by_ref()
                    .take(tableau_layout.nreq())
                    .chain(witness.elements(
                        witness_row * tableau_layout.witnesses_per_row(),
                        tableau_layout.witnesses_per_row(),
                    ))
                    .collect::<Vec<_>>()
                    .as_slice(),
                tableau_layout.num_columns(),
            ));
        }

        // Padded quadratic witness rows: NREQ random elements, then witnesses_per_row elements from
        // the x, y or z witnesses, depending on the quadratic witness row index. Then extended to
        // NCOL.
        let mut quad_constraint_x = quadratic_constraints.iter().map(|q| q.x);
        let mut quad_constraint_y = quadratic_constraints.iter().map(|q| q.y);
        let mut quad_constraint_z = quadratic_constraints.iter().map(|q| q.z);

        for quad_constraint_row in 0..num_quadratic_rows {
            let mut row = Vec::with_capacity(tableau_layout.block_size());
            row.extend(element_generator.by_ref().take(tableau_layout.nreq()));

            for _ in 0..tableau_layout.witnesses_per_row() {
                let witness = match quad_constraint_row % 3 {
                    0 => quad_constraint_x.next(),
                    1 => quad_constraint_y.next(),
                    2 => quad_constraint_z.next(),
                    _ => unreachable!("impossible remainder"),
                }
                .map(|index| witness.element(index))
                .unwrap_or(FE::ZERO);
                row.push(witness);
            }

            tableau.push(extend(row.as_slice(), tableau_layout.num_columns()));
        }

        // Make sure we allocated the tableau correctly up front.
        assert_eq!(tableau.len(), tableau_layout.num_rows());

        // Construct a Merkle tree from the tableau columns
        let mut field_element_buf = Vec::with_capacity(FE::num_bytes());
        let tree_size = tableau_layout.num_columns() - tableau_layout.dblock();
        let mut tree = MerkleTree::new(tree_size);
        let mut merkle_tree_nonces = Vec::with_capacity(tree_size);

        for leaf_index in tableau_layout.dblock()..(tableau_layout.num_columns()) {
            let mut sha256 = Sha256::new();

            // longfellow-zk hashes a random nonce into each leaf before the tableau elements, which
            // is not discussed in the draft specification.
            let nonce = merkle_tree_nonce_generator();
            merkle_tree_nonces.push(nonce);
            sha256.update(nonce);
            for row in &tableau {
                field_element_buf.truncate(0);
                row[leaf_index].encode(&mut field_element_buf)?;
                sha256.update(&field_element_buf);
            }
            tree.set_leaf(leaf_index - tableau_layout.dblock(), Node::from(sha256));
        }
        tree.build();

        Ok(Self(tree.root().into()))
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        circuit::Evaluation,
        constraints::proof_constraints::quadratic_constraints,
        decode_test_vector,
        fields::fieldp128::FieldP128,
        test_vector::CircuitTestVector,
        witness::{Witness, WitnessLayout},
    };

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = decode_test_vector!(
            "longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b",
            proofs,
        );

        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(test_vector.valid_inputs.as_deref().unwrap())
            .unwrap();

        let quadratic_constraints = quadratic_constraints(&circuit);
        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad().unwrap(),
        );

        // Fix the nonce to match what longfellow-zk will do: all zeroes, but set the first byte to
        // what the fixed RNG yields.
        let mut merkle_tree_nonce = [0; 32];
        merkle_tree_nonce[0] = test_vector.pad.unwrap() as u8;

        let tableau_layout = TableauLayout::new(
            test_vector.ligero_parameters.as_ref().unwrap(),
            witness.len(),
            quadratic_constraints.len(),
        );

        let ligero_commitment = LigeroCommitment::commit::<FieldP128, _, _>(
            &tableau_layout,
            &witness,
            &quadratic_constraints,
            || test_vector.pad().unwrap(),
            || merkle_tree_nonce,
        )
        .unwrap();

        assert_eq!(ligero_commitment, test_vector.ligero_commitment().unwrap());
    }
}
