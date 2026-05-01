//! Ligero committer, specified in [Section 4.3][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3

#[cfg(test)]
use std::ops::Range;

use crate::{
    fields::{ProofFieldElement, field_element_iter_from_source},
    ligero::{
        LigeroParameters, Nonce,
        merkle::{MerkleTree, Node},
    },
    sumcheck::constraints::QuadraticConstraint,
    witness::Witness,
};
use rand::{RngCore, random};
use sha2::{Digest, Sha256};

/// Describes the layout of the tableau. The verifier does not actually have the entire tableau, but
/// needs the layout to locate corresponding values in the blinds it generates or the columns
/// revealed by the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableauLayout {
    parameters: LigeroParameters,
    num_witnesses: usize,
    num_quadratic_constraints: usize,
}

impl TableauLayout {
    pub fn new(
        parameters: LigeroParameters,
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

    /// The indices of rows containing quadratic constraints.
    #[cfg(test)]
    pub(crate) fn quadratic_constraint_rows(&self) -> Range<usize> {
        self.first_quadratic_constraint_row()
            ..self.first_quadratic_constraint_row() + self.num_quadratic_rows()
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

    /// Returns the Ligero parameters.
    pub fn ligero_parameters(&self) -> &LigeroParameters {
        &self.parameters
    }
}

/// An actual tableau containing values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tableau<FieldElement> {
    layout: TableauLayout,
    contents: Vec<Vec<FieldElement>>,
}

impl<FE: ProofFieldElement> Tableau<FE> {
    /// Build the tableau.
    pub fn build(
        ligero_parameters: LigeroParameters,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
        extend_context_block_ncol: &FE::ExtendContext,
        extend_context_dblock_ncol: &FE::ExtendContext,
    ) -> Self {
        let mut buffer = vec![0; FE::num_bytes()];
        let mut rng = rand::rng();
        Self::build_with_field_element_generator(
            ligero_parameters,
            witness,
            quadratic_constraints,
            || FE::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes)),
            extend_context_block_ncol,
            extend_context_dblock_ncol,
        )
    }

    /// Build the tableau using the provided function to generate random elements.
    pub fn build_with_field_element_generator<FieldElementGenerator>(
        ligero_parameters: LigeroParameters,
        witness: &Witness<FE>,
        quadratic_constraints: &[QuadraticConstraint],
        field_element_generator: FieldElementGenerator,
        extend_context_block_ncol: &FE::ExtendContext,
        extend_context_dblock_ncol: &FE::ExtendContext,
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
        // Fill the low degree test row:
        // rr...r│ee...e
        //    │      │
        //    │      └ extended from BLOCK to NCOL total elements by interpolation
        // BLOCK random elements
        let low_degree_test_row: Vec<_> = element_generator
            .by_ref()
            .take(layout.block_size())
            .collect();
        tableau.push(FE::extend(&low_degree_test_row, extend_context_block_ncol));

        // Fill the linear test row ("IDOT"): random field elements where elements [nreq..nreq+wr)
        // sum to 0, extended to NCOL
        // rr...r│i│ee...e
        //    │   │    │
        //    │   │    └ extended from DBLOCK to NCOL total elements by interpolation
        //    │   └ additive inverse of previous wr elements
        // DBLOCK - 1 random elements
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
        tableau.push(FE::extend(&linear_test_row, extend_context_dblock_ncol));

        // Quadratic test row:
        // rr...r│00...0│rr...r│ee...e
        //    │      │      │      │
        //    │      │      │      └ extended from DBLOCK to NCOL total elements by interpolation
        //    │      │      └ DBLOCK - num_witnesses - NREQ random elements
        //    │      └ num_witnesses zeroes
        // NREQ random elements
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
        tableau.push(FE::extend(
            quadratic_test_row.as_slice(),
            extend_context_dblock_ncol,
        ));

        // Padded witness rows:
        // rr...r│ww...w│ee...e
        // rr...r│ww...w│ee...e
        // ...
        // rr...r│ww...w│ee...e
        //    │      │      │
        //    │      │      └ extended from BLOCK to NCOL total elements by interpolation
        //    │      └ witnesses_per_row witness elements
        // NREQ random elements
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
                extend_context_block_ncol,
            ));
        }

        // Padded quadratic witness rows. These rows are the vertical juxtaposition of the matrices
        // for the x, y and z variables in the constraints, per the Ligero paper
        // (<https://eprint.iacr.org/2022/1608.pdf>). So x, y and z witnesses are on distinct rows.
        //
        // We may have more quadratic constraints than can fit into a single triple of tableau rows.
        // We lay out all the xs, then all the ys, then all the zs. The last row of witnesses for
        // each variable is padded with zeroes as needed.
        //
        // rr...r│xxxxxxxxx...x│ee...e
        // rr...r│xxxxxxxxx...x│ee...e
        // rr...r│xx...x│00...0│ee...e
        // rr...r│yyyyyyyyy...y│ee...e
        // rr...r│yyyyyyyyy...y│ee...e
        // rr...r│yy...y│00...0│ee...e
        // rr...r│zzzzzzzzz...z│ee...e
        // rr...r│zzzzzzzzz...z│ee...e
        //    │             │      │
        //    │             │      └ extended from BLOCK to NCOL total elements by interpolation
        //    │             └ witnesses_per_row z witnesses
        // NREQ random elements
        // rr...r│zz...z│00...0│ee...e
        //    │      │      │      │
        //    │      │      │      └ extended from BLOCK to NCOL total elements by interpolation
        //    │      │      └ pad with 0s up to BLOCK elements
        //    │      └ remaining z witnesses
        // NREQ random elements
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
                // num_quadratic_rows is always a multiple of three
                let witness = if quad_constraint_row < num_quadratic_rows / 3 {
                    quad_constraint_x.next()
                } else if quad_constraint_row < 2 * num_quadratic_rows / 3 {
                    quad_constraint_y.next()
                } else {
                    quad_constraint_z.next()
                }
                .map(|index| witness.element(index))
                .unwrap_or(FE::ZERO);
                row.push(witness);
            }

            tableau.push(FE::extend(row.as_slice(), extend_context_block_ncol));
        }

        // Make sure we allocated the tableau correctly up front.
        assert_eq!(tableau.len(), layout.num_rows());

        Tableau {
            layout,
            contents: tableau,
        }
    }

    /// The layout of the tableau.
    pub fn layout(&self) -> &TableauLayout {
        &self.layout
    }

    /// Commit to the contents of the tableau, returning a Merkle tree whose leaves are hashes of
    /// the columns. A nonce is hashed into each leaf.
    pub fn commit(&self) -> Result<MerkleTree, anyhow::Error> {
        self.commit_with_merkle_tree_nonce_generator(|| Nonce(random::<[u8; 32]>()))
    }

    /// Commit to the contents of the tableau, using nonces from the provided generator.
    pub fn commit_with_merkle_tree_nonce_generator<MerkleTreeNonceGenerator>(
        &self,
        mut merkle_tree_nonce_generator: MerkleTreeNonceGenerator,
    ) -> Result<MerkleTree, anyhow::Error>
    where
        MerkleTreeNonceGenerator: FnMut() -> Nonce,
    {
        // Construct a Merkle tree from the tableau columns
        let tree_size = self.layout.num_columns() - self.layout.dblock();
        let mut tree = MerkleTree::new(tree_size);

        for leaf_index in self.layout.dblock()..(self.layout.num_columns()) {
            let mut sha256 = Sha256::new();

            // longfellow-zk hashes a random nonce into each leaf before the tableau elements, which
            // is not discussed in the draft specification.
            let nonce = merkle_tree_nonce_generator();
            sha256.update(nonce);
            for row in &self.contents {
                sha256.update(row[leaf_index].as_byte_array()?);
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
    use std::iter;

    use super::*;
    use crate::{
        circuit::Evaluation,
        fields::{FieldElement, fieldp128::FieldP128},
        sumcheck::constraints::quadratic_constraints,
        test_vector::load_rfc,
        witness::{Witness, WitnessLayout},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let quadratic_constraints = quadratic_constraints(&circuit, &witness_layout);
        let witness = Witness::fill_witness(
            witness_layout,
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad(),
        );

        // Fix the nonce to match what longfellow-zk will do: all zeroes, but set the first byte to
        // what the fixed RNG yields.
        let mut merkle_tree_nonce = Nonce([0; 32]);
        merkle_tree_nonce.0[0] = test_vector.pad as u8;

        let layout = TableauLayout::new(
            *test_vector.ligero_parameters(),
            witness.len(),
            quadratic_constraints.len(),
        );
        let extend_context_block_ncol =
            FieldP128::extend_precompute(layout.block_size(), layout.num_columns());
        let extend_context_dblock_ncol =
            FieldP128::extend_precompute(layout.dblock(), layout.num_columns());

        let tree = Tableau::build_with_field_element_generator(
            *test_vector.ligero_parameters(),
            &witness,
            &quadratic_constraints,
            || test_vector.pad(),
            &extend_context_block_ncol,
            &extend_context_dblock_ncol,
        )
        .commit_with_merkle_tree_nonce_generator(|| merkle_tree_nonce)
        .unwrap();

        assert_eq!(tree.root(), test_vector.ligero_commitment());
        for nonce in tree.nonces() {
            assert_eq!(nonce, &merkle_tree_nonce);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn multiple_quadratic_constraint_rows() {
        let (test_vector, circuit) = load_rfc();
        let mut ligero_params = *test_vector.ligero_parameters();
        // The test vector has a small number of quadratic constraints and thus a small value of
        // quadratic_constraints_per_row. Our test synthesizes additional quadratic constraints so
        // we fix up that parameter accordingly in order to pack the tableau efficiently.
        ligero_params.quadratic_constraints_per_row = ligero_params.witnesses_per_row;

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        // Construct bogus quadratic constraints that repeat the same x, y, z values so we can later
        // easily check the constructed tableau, and construct enough of them that we'll need three
        // rows for each of the x, y and z coordinates.
        let quadratic_constraints: Vec<_> =
            iter::from_fn(|| Some(QuadraticConstraint { x: 0, y: 1, z: 2 }))
                .take(ligero_params.witnesses_per_row * 3)
                .collect();

        // Construct witness with all zeroes, except for the witnesses pointed to by the quadratic
        // constraints.
        let mut witness = Witness::fill_witness(
            witness_layout,
            iter::from_fn(|| Some(FieldP128::ZERO))
                .take(evaluation.private_inputs(circuit.num_public_inputs()).len())
                .collect::<Vec<_>>()
                .as_slice(),
            || FieldP128::ZERO,
        );
        witness.set_element(0, FieldP128::from_u128(15));
        witness.set_element(1, FieldP128::from_u128(16));
        witness.set_element(2, FieldP128::from_u128(17));

        let layout = TableauLayout::new(ligero_params, witness.len(), quadratic_constraints.len());
        assert_eq!(layout.num_quadratic_rows(), 9);

        let tableau = Tableau::build_with_field_element_generator(
            ligero_params,
            &witness,
            &quadratic_constraints,
            || test_vector.pad(),
            &FieldP128::extend_precompute(layout.block_size(), layout.num_columns()),
            &FieldP128::extend_precompute(layout.dblock(), layout.num_columns()),
        );

        for (idx, quadratic_constraint_row) in tableau.contents()
            [tableau.layout.quadratic_constraint_rows()]
        .iter()
        .enumerate()
        {
            // We should get three rows of x, then three rows of y and then three rows of z
            let expected_quadratic_witnesses = if idx < 3 {
                vec![FieldP128::from_u128(15); tableau.layout.witnesses_per_row()]
            } else if idx < 6 {
                vec![FieldP128::from_u128(16); tableau.layout.witnesses_per_row()]
            } else {
                vec![FieldP128::from_u128(17); tableau.layout.witnesses_per_row()]
            };

            let got_quadratic_witnesses =
                &quadratic_constraint_row[tableau.layout.num_requested_columns()
                    ..tableau.layout.num_requested_columns() + tableau.layout.witnesses_per_row()];
            assert_eq!(expected_quadratic_witnesses, got_quadratic_witnesses);
        }
    }
}
