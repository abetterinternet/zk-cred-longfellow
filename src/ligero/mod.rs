//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

use serde::Deserialize;

use crate::fields::LagrangePolynomialFieldElement;

pub mod committer;
pub mod merkle;
pub mod prover;
pub mod verifier;

/// Common parameters for the Ligero proof system. Described in [Section 4.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.2
#[derive(Debug, Clone, Deserialize)]
pub struct LigeroParameters {
    /// The number of columns of the commitment matrix that the Verifier requests to be revealed by the Prover.
    pub nreq: usize,
    /// The number of witness values included in each row. Also "WR".
    pub witnesses_per_row: usize,
    /// The number of quadratic constraints written in each row. Also "QR".
    pub quadratic_constraints_per_row: usize,
    /// The size of each row, in terms of number of field elements. Also "BLOCK".
    /// There is some confusion in the specification between this and NCOL.
    pub row_size: usize,
    /// The total size of a tableau row.
    /// There is some confusion in the specification between this and BLOCK.
    pub num_columns: u128,
}

impl LigeroParameters {
    /// DBLOCK, 2 * BLOCK - 1
    pub fn dblock(&self) -> usize {
        self.row_size * 2 - 1
    }
}

/// The extend method, as defined in [2.2.1][1]. We interpolate a polynomial of degree at most
/// `nodes.len() - 1` from the provided evaluations at points `[0..nodes.len())` and then evaluate
/// that polynomial at `[0, evaluations)`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.1
pub fn extend<FE: LagrangePolynomialFieldElement>(nodes: &[FE], evaluations: u128) -> Vec<FE> {
    // For now we use the relatively straightforward method of computing Lagrange basis polynomials
    // for each provided point.
    //
    // https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
    let mut output = Vec::with_capacity(evaluations as usize);
    let mut denominators = vec![None; nodes.len()];

    for input in (0..evaluations).map(FE::from_u128) {
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
    use super::*;
    use crate::fields::{
        field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256, fieldp521::FieldP521,
    };

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

    #[test]
    fn extend_x_2_p128() {
        extend_x_2::<FieldP128>();
    }

    #[test]
    fn extend_x_2_p256() {
        extend_x_2::<FieldP256>();
    }

    #[test]
    fn extend_x_2_p521() {
        extend_x_2::<FieldP521>();
    }

    #[ignore]
    #[test]
    fn extend_x_2_2_128() {
        extend_x_2::<Field2_128>();
    }
}
