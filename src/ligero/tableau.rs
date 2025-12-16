//! Ligero committer, specified in [Section 4.3][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3

use crate::{
    constraints::proof_constraints::QuadraticConstraint,
    fields::{CodecFieldElement, ProofFieldElement, field_element_iter_from_source},
    ligero::{
        LigeroParameters,
        merkle::{MerkleTree, Node},
    },
    witness::Witness,
};
use rand::random;
use sha2::{Digest, Sha256};

/// Describes the layout of the tableau. The verifier does not actually have the entire tableau, but
/// needs the layout to locate corresponding values in the blinds it generates or the columns
/// revealed by the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableauLayout<'a> {
    parameters: &'a LigeroParameters,
    num_witnesses: usize,
    num_quadratic_constraints: usize,
}

impl<'a> TableauLayout<'a> {
    pub fn new(
        parameters: &'a LigeroParameters,
        num_witnesses: usize,
        num_quadratic_constraints: usize,
    ) -> Self {
        Self {
            parameters,
            num_witnesses,
            num_quadratic_constraints,
        }
    }

    /// Index of the low degree test row.
    pub const fn low_degree_test_row() -> usize {
        0
    }

    /// Index of the dot proof row, aka linear test row.
    pub const fn dot_proof_row() -> usize {
        1
    }

    /// Index of the quadratic test row.
    pub const fn quadratic_test_row() -> usize {
        2
    }

    /// The size of a block, in terms of number of field elements. Also `BLOCK`. The specification
    /// describes this quantity as the "size of each row", but that would be `NCOL` or
    /// `num_columns`.
    pub fn block_size(&self) -> usize {
        self.parameters.block_size
    }

    /// The total size of a tableau row. Also `NCOL`.
    pub fn num_columns(&self) -> usize {
        self.parameters.num_columns
    }

    /// The number of columns of the tableau that the Verifier requests to be revealed by the
    /// Prover. Also `NREQ`.
    pub fn num_requested_columns(&self) -> usize {
        self.parameters.nreq
    }

    /// `DBLOCK = 2 * BLOCK - 1`
    pub fn dblock(&self) -> usize {
        self.parameters.block_size * 2 - 1
    }

    /// The number of witness values included in each row. Also `WR`.
    pub fn witnesses_per_row(&self) -> usize {
        self.parameters.witnesses_per_row
    }

    /// The number of quadratic constraints written in each row. Also `QR`.
    pub fn quadratic_constraints_per_row(&self) -> usize {
        self.parameters.quadratic_constraints_per_row
    }

    /// Index of the first row of the tableau containing witnesses, used in the linear constraint
    /// test.
    pub fn first_witness_row(&self) -> usize {
        // One row each for low degree, linear and quadratic tests.
        3
    }

    /// Index of the first row of the tableau containing quadratic constraints on the witnesses.
    pub fn first_quadratic_constraint_row(&self) -> usize {
        self.first_witness_row() + self.num_linear_constraint_rows()
    }

    /// The number of triples of tableau rows needed to represent the quadratic constraints
    pub fn num_quadratic_triples(&self) -> usize {
        self.num_quadratic_constraints
            .div_ceil(self.parameters.quadratic_constraints_per_row)
    }

    /// The number of tableau rows needed to represent the quadratic constraints.
    pub fn num_quadratic_rows(&self) -> usize {
        3 * self.num_quadratic_triples()
    }

    /// The number of tableau rows needed to represent linear constraints on the witnesses.
    pub fn num_linear_constraint_rows(&self) -> usize {
        self.num_witnesses
            .div_ceil(self.parameters.witnesses_per_row)
    }

    /// The total number of rows in the tableau for witness constraints.
    pub fn num_constraint_rows(&self) -> usize {
        self.num_linear_constraint_rows() + self.num_quadratic_rows()
    }

    /// The total number of rows in the tableau.
    pub fn num_rows(&self) -> usize {
        self.first_witness_row() + self.num_linear_constraint_rows() + self.num_quadratic_rows()
    }

    /// Gather the tableau elements at the provided indices from source, in the order of the
    /// indices. As specified in [2.1][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.1
    pub fn gather_iter<FE: ProofFieldElement>(
        &self,
        source: &[FE],
        indices: &[usize],
    ) -> impl Iterator<Item = FE> {
        // offset by dblock so that we yield tableau elements, not witnesses.
        indices.iter().map(|index| source[*index + self.dblock()])
    }

    /// Gather the tableau elements at the provided indices from source, in the order of the indices. As
    /// specified in [2.1][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.1
    pub fn gather<FE: ProofFieldElement>(&self, source: &[FE], indices: &[usize]) -> Vec<FE> {
        self.gather_iter(source, indices).collect()
    }
}

/// An actual tableau containing values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tableau<'a, FieldElement> {
    layout: TableauLayout<'a>,
    contents: Vec<Vec<FieldElement>>,
}

impl<'a, FE: CodecFieldElement + ProofFieldElement> Tableau<'a, FE> {
    /// Build the tableau.
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

    /// Build the tableau using the provided function to generate random elements.
    pub fn build_with_field_element_generator<FieldElementGenerator>(
        ligero_parameters: &'a LigeroParameters,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
        field_element_generator: FieldElementGenerator,
    ) -> Self
    where
        FieldElementGenerator: FnMut() -> FE,
    {
        let layout = TableauLayout::new(
            ligero_parameters,
            witness.len(),
            quadratic_constraints.len(),
        );

        // Rows for the witnesses, but not the quadratic constraints
        let num_witness_rows = layout.num_linear_constraint_rows();
        // Each quadratic constraint contributes three witnesses
        let num_quadratic_rows = layout.num_quadratic_rows();
        // Rows for low degree test, linear test and quadratic test
        let mut tableau = Vec::with_capacity(layout.num_rows());

        let mut element_generator = field_element_iter_from_source(field_element_generator);

        // Construct the tableau from the witness and the constraints.
        // Fill the low degree test row: extend(RANDOM[BLOCK], BLOCK, NCOL)
        let context_block = FE::extend_precompute(layout.block_size(), layout.num_columns());
        let low_degree_test_row: Vec<_> = element_generator
            .by_ref()
            .take(layout.block_size())
            .collect();
        tableau.push(FE::extend(&low_degree_test_row, &context_block));

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
        let context_dblock = FE::extend_precompute(layout.dblock(), layout.num_columns());
        tableau.push(FE::extend(&linear_test_row, &context_dblock));

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
        tableau.push(FE::extend(quadratic_test_row.as_slice(), &context_dblock));

        // Padded witness rows: NREQ random elements, then witnesses_per_row elements of the witness
        // extended to NCOL
        for witness_row in 0..num_witness_rows {
            tableau.push(FE::extend(
                element_generator
                    .by_ref()
                    .take(layout.num_requested_columns())
                    .chain(witness.elements(
                        witness_row * layout.witnesses_per_row(),
                        layout.witnesses_per_row(),
                    ))
                    .collect::<Vec<_>>()
                    .as_slice(),
                &context_block,
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

            tableau.push(FE::extend(row.as_slice(), &context_block));
        }

        // Make sure we allocated the tableau correctly up front.
        assert_eq!(tableau.len(), layout.num_rows());

        Tableau {
            layout,
            contents: tableau,
        }
    }

    /// The layout of the tableau.
    pub fn layout(&'_ self) -> &'_ TableauLayout<'_> {
        &self.layout
    }

    /// Commit to the contents of the tableau, returning a Merkle tree whose leaves are hashes of
    /// the columns. A nonce is hashed into each leaf.
    pub fn commit(&self) -> Result<MerkleTree, anyhow::Error> {
        self.commit_with_merkle_tree_nonce_generator(random::<[u8; 32]>)
    }

    /// Commit to the contents of the tableau, using nonces from the provided generator.
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
        fields::fieldp128::FieldP128,
        ligero::LigeroCommitment,
        test_vector::load_rfc,
        witness::{Witness, WitnessLayout},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();

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

        let tree = Tableau::build_with_field_element_generator(
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
