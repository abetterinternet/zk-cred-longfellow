//! Ligero committer, specified in [Section 4.3][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3

use crate::{
    constraints::proof_constraints::QuadraticConstraint,
    fields::{LagrangePolynomialFieldElement, field_element_iter_from_source},
    ligero::{
        CodewordMatrixLayout, LigeroParameters, extend,
        merkle::{MerkleTree, Node},
    },
    witness::Witness,
};
use anyhow::Context;
use rand::random;
use sha2::{Digest, Sha256};

/// A commitment to a witness vector, as specified in [1]. Concretely, this is the root of a Merkle
/// tree of SHA-256 hashes.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl From<Node> for LigeroCommitment {
    fn from(value: Node) -> Self {
        Self(<[u8; 32]>::from(value))
    }
}

impl LigeroCommitment {
    /// The commitment as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// A fake but well-formed commitment for tests.
    #[cfg(test)]
    pub fn test_commitment() -> Self {
        Self::try_from([1u8; 32].as_slice()).unwrap()
    }
}

/// An actual codeword matrix containing values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodewordMatrix<'a, FieldElement> {
    layout: CodewordMatrixLayout<'a>,
    contents: Vec<Vec<FieldElement>>,
}

impl<'a, FE: LagrangePolynomialFieldElement> CodewordMatrix<'a, FE> {
    /// Build the codeword matrix.
    pub fn build(
        ligero_parameters: &'a LigeroParameters,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
    ) -> Self {
        Self::build_with_field_element_generator(
            ligero_parameters,
            witness,
            quadratic_constraints,
            FE::sample,
        )
    }

    /// Build the codeword matrix using the provided function to generate random elements.
    pub fn build_with_field_element_generator<FieldElementGenerator>(
        ligero_parameters: &'a LigeroParameters,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
        field_element_generator: FieldElementGenerator,
    ) -> Self
    where
        FieldElementGenerator: FnMut() -> FE,
    {
        let layout = CodewordMatrixLayout::new(
            ligero_parameters,
            witness.len(),
            quadratic_constraints.len(),
        );

        // Rows for the witnesses, but not the quadratic constraints
        let num_witness_rows = layout.num_linear_constraint_rows();
        // Each quadratic constraint contributes three witnesses
        let num_quadratic_rows = layout.num_quadratic_rows();
        // Rows for low degree test, linear test and quadratic test
        let mut matrix = Vec::with_capacity(layout.num_rows());

        let mut element_generator = field_element_iter_from_source(field_element_generator);

        // Construct the tableau matrix from the witness and the constraints.
        // Fill the low degree test row: extend(RANDOM[BLOCK], BLOCK, NCOL)
        let low_degree_test_row: Vec<_> = element_generator
            .by_ref()
            .take(layout.block_size())
            .collect();
        matrix.push(extend(&low_degree_test_row, layout.num_columns()));

        // Fill the linear test row ("IDOT"): random field elements where elements [nreq..nreq+wr)
        // sum to 0, extended to NCOL
        let mut sum = FE::ZERO;
        let mut index = 0;
        let mut row_random_elements = element_generator.by_ref().take(layout.dblock() - 1);

        let mut linear_test_row: Vec<_> = std::iter::from_fn(|| {
            let element = if index == layout.num_requested_columns() {
                // Reserve the first witness spot for the additive inverse of the sum of the
                // remaining witnesses. Per the spec we could put this element anywhere in the
                // witnesses, but this matches longfellow-zk and makes it easier to test against
                // their tableau and commitment.
                Some(FE::ZERO)
            } else {
                let element = row_random_elements.next();
                if (layout.num_requested_columns() + 1..layout.block_size()).contains(&index) {
                    // Unwrap safety: the iterator should contain exactly the number of elements we
                    // need, so a panic here means we have misinterpreted the specification.
                    sum += element.unwrap();
                }
                element
            };

            index += 1;
            element
        })
        .take(layout.dblock())
        .collect();

        linear_test_row[layout.num_requested_columns()] = -sum;
        // Specification interpretation verification: we should have consumed row_random_elements
        assert_eq!(row_random_elements.next(), None);
        // Specification interpretation verification: make sure range nreq..nreq+wr sums to 0.
        assert_eq!(
            FE::ZERO,
            linear_test_row
                .iter()
                .skip(layout.num_requested_columns())
                .take(layout.witnesses_per_row())
                .fold(FE::ZERO, |acc, elem| acc + elem)
        );
        matrix.push(extend(&linear_test_row, layout.num_columns()));

        // Quadratic test row: NREQ random elements then zeroes for each witness, then more random
        // elements to fill to DBLOCK, then extended to NCOL
        let mut index = 0;
        let quadratic_test_row: Vec<_> = std::iter::from_fn(|| {
            let next = if index < layout.num_requested_columns() || index >= layout.block_size() {
                element_generator.next()
            } else {
                Some(FE::ZERO)
            };

            index += 1;
            next
        })
        .take(layout.dblock())
        .collect();
        matrix.push(extend(quadratic_test_row.as_slice(), layout.num_columns()));

        // Padded witness rows: NREQ random elements, then witnesses_per_row elements of the witness
        // extended to NCOL
        for witness_row in 0..num_witness_rows {
            matrix.push(extend(
                element_generator
                    .by_ref()
                    .take(layout.num_requested_columns())
                    .chain(witness.elements(
                        witness_row * layout.witnesses_per_row(),
                        layout.witnesses_per_row(),
                    ))
                    .collect::<Vec<_>>()
                    .as_slice(),
                layout.num_columns(),
            ));
        }

        // Padded quadratic witness rows: NREQ random elements, then witnesses_per_row elements from
        // the x, y or z witnesses, depending on the quadratic witness row index. Then extended to
        // NCOL.
        let mut quad_constraint_x = quadratic_constraints.iter().map(|q| q.x);
        let mut quad_constraint_y = quadratic_constraints.iter().map(|q| q.y);
        let mut quad_constraint_z = quadratic_constraints.iter().map(|q| q.z);

        for quad_constraint_row in 0..num_quadratic_rows {
            let mut row = Vec::with_capacity(layout.block_size());
            row.extend(
                element_generator
                    .by_ref()
                    .take(layout.num_requested_columns()),
            );

            for _ in 0..layout.witnesses_per_row() {
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

            matrix.push(extend(row.as_slice(), layout.num_columns()));
        }

        // Make sure we allocated the tableau correctly up front.
        assert_eq!(matrix.len(), layout.num_rows());

        CodewordMatrix {
            layout,
            contents: matrix,
        }
    }

    /// The layout of the matrix.
    pub fn layout(&'_ self) -> &'_ CodewordMatrixLayout<'_> {
        &self.layout
    }

    /// Commit to the contents of the codeword matrix, returning a Merkle tree whose leaves are
    /// hashes of the matrix columns. A nonce is hashed into each leaf.
    pub fn commit(&self) -> Result<MerkleTree, anyhow::Error> {
        self.commit_with_merkle_tree_nonce_generator(random::<[u8; 32]>)
    }

    /// Commit to the contents of the codeword matrix, using nonces from the provided generator.
    pub fn commit_with_merkle_tree_nonce_generator<MerkleTreeNonceGenerator>(
        &self,
        mut merkle_tree_nonce_generator: MerkleTreeNonceGenerator,
    ) -> Result<MerkleTree, anyhow::Error>
    where
        MerkleTreeNonceGenerator: FnMut() -> [u8; 32],
    {
        // Construct a Merkle tree from the tableau columns
        let mut field_element_buf = Vec::with_capacity(FE::num_bytes());
        let tree_size = self.layout.num_columns() - self.layout.dblock();
        let mut tree = MerkleTree::new(tree_size);

        for leaf_index in self.layout.dblock()..(self.layout.num_columns()) {
            let mut sha256 = Sha256::new();

            // longfellow-zk hashes a random nonce into each leaf before the tableau elements, which
            // is not discussed in the draft specification.
            let nonce = merkle_tree_nonce_generator();
            sha256.update(nonce);
            for row in &self.contents {
                field_element_buf.truncate(0);
                row[leaf_index].encode(&mut field_element_buf)?;
                sha256.update(&field_element_buf);
            }
            tree.set_leaf(leaf_index - self.layout.dblock(), Node::from(sha256), nonce);
        }
        tree.build();

        Ok(tree)
    }

    pub fn contents(&self) -> &[Vec<FE>] {
        &self.contents
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
        test_vector::CircuitTestVector,
        witness::{Witness, WitnessLayout},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = decode_test_vector!(
            "longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b",
            proofs,
        );

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(&test_vector.valid_inputs()).unwrap();

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

        let tree = CodewordMatrix::build_with_field_element_generator(
            &test_vector.ligero_parameters(),
            &witness,
            &quadratic_constraints,
            || test_vector.pad().unwrap(),
        )
        .commit_with_merkle_tree_nonce_generator(|| merkle_tree_nonce)
        .unwrap();

        assert_eq!(
            LigeroCommitment::from(tree.root()),
            test_vector.ligero_commitment().unwrap()
        );
        for nonce in tree.nonces() {
            assert_eq!(nonce, &merkle_tree_nonce);
        }
    }
}
