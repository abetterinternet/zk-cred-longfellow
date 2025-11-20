//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

use crate::fields::LagrangePolynomialFieldElement;
use serde::Deserialize;

pub mod committer;
pub mod merkle;
pub mod prover;
pub mod verifier;

/// Common parameters for the Ligero proof system. Described in [Section 4.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.2
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LigeroParameters {
    /// The number of columns of the commitment matrix that the Verifier requests to be revealed by
    /// the Prover. Also `NREQ`.
    pub nreq: usize,
    /// The number of witness values included in each row. Also `WR`.
    pub witnesses_per_row: usize,
    /// The number of quadratic constraints written in each row. Also `QR`.
    pub quadratic_constraints_per_row: usize,
    /// The size of a block, in terms of number of field elements. Also `BLOCK`. The specification
    /// describes this quantity as the "size of each row", but that would be `NCOL` or
    /// `num_columns`.
    pub block_size: usize,
    /// The total size of a tableau row. Also `NCOL`.
    pub num_columns: usize,
}

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

    /// The number of columns of the commitment matrix that the Verifier requests to be revealed by
    /// the Prover. Also `NREQ`.
    pub fn nreq(&self) -> usize {
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
}

/// The extend method, as defined in [2.2.1][1]. We interpolate a polynomial of degree at most
/// `nodes.len() - 1` from the provided evaluations at points `[0..nodes.len())` and then evaluate
/// that polynomial at `[0, evaluations)`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.1
pub fn extend<FE: LagrangePolynomialFieldElement>(nodes: &[FE], evaluations: usize) -> Vec<FE> {
    // For now we use the relatively straightforward method of computing Lagrange basis polynomials
    // for each provided point.
    //
    // https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
    let mut output = Vec::with_capacity(evaluations);
    let mut denominators = vec![None; nodes.len()];

    for input in (0..evaluations).map(|e| FE::from_u128(e as u128)) {
        let mut eval = FE::ZERO;

        // Evaluate each basis polynomial
        for (node_x_coordinate, node_y_coordinate) in nodes.iter().enumerate() {
            // Compute and cache denominators
            let denominator = match denominators[node_x_coordinate] {
                Some(denominator) => denominator,
                None => {
                    let denominator = nodes
                        .iter()
                        .enumerate()
                        .filter(|(other_node_x_coordinate, _)| {
                            *other_node_x_coordinate != node_x_coordinate
                        })
                        .fold(FE::ONE, |product, (other_node_x_coordinate, _)| {
                            product
                                * (FE::from_u128(node_x_coordinate as u128)
                                    - FE::from_u128(other_node_x_coordinate as u128))
                        })
                        .mul_inv();
                    denominators[node_x_coordinate] = Some(denominator);
                    denominator
                }
            };

            // Compute each term of the basis polynomial
            let basis_poly_eval = nodes
                .iter()
                .enumerate()
                .filter(|(other_node_x_coordinate, _)| {
                    *other_node_x_coordinate != node_x_coordinate
                })
                .fold(FE::ONE, |product, (other_node_x_coordinate, _)| {
                    product * (input - FE::from_u128(other_node_x_coordinate as u128))
                })
                * *node_y_coordinate
                * denominator;
            eval += basis_poly_eval;
        }

        output.push(eval);
    }

    output
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::fields::{fieldp128::FieldP128, fieldp256::FieldP256, fieldp521::FieldP521};

    fn extend_x_2<FE: LagrangePolynomialFieldElement>() {
        let output = extend(
            // x^2 evaluated at 0, 1, 2 => 0, 1, 4
            &[FE::ZERO, FE::ONE, FE::from_u128(4)],
            6,
        );

        assert_eq!(
            output,
            // x^2 evaluated at 0..6 = > 0, 1, 4, 9, 16, 25
            vec![
                FE::ZERO,
                FE::ONE,
                FE::from_u128(4),
                FE::from_u128(9),
                FE::from_u128(16),
                FE::from_u128(25),
            ]
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_x_2_p128() {
        extend_x_2::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_x_2_p256() {
        extend_x_2::<FieldP256>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_x_2_p521() {
        extend_x_2::<FieldP521>();
    }
}
