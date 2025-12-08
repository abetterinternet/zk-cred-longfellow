use crate::fields::LagrangePolynomialFieldElement;
use std::marker::PhantomData;

/// Precomputed values for the Lagrange basis polynomial-based implementation of `extend()`.
pub struct LagrangeExtendContext<FE> {
    nodes_len: usize,
    evaluations: usize,
    _phantom: PhantomData<FE>,
}

pub(super) fn lagrange_extend_precompute<FE>(
    nodes_len: usize,
    evaluations: usize,
) -> LagrangeExtendContext<FE>
where
    FE: LagrangePolynomialFieldElement,
{
    LagrangeExtendContext {
        nodes_len,
        evaluations,
        _phantom: PhantomData,
    }
}

/// The extend method, as defined in [2.2.1][1] and [2.2.2][2]. We interpolate a polynomial of
/// degree at most `nodes.len() - 1` from the provided evaluations at points `[0..nodes.len())`
/// and then evaluate that polynomial at `[0, evaluations)`.
///
/// The returned vector has length `context.evaluations`. The first `nodes.len()` elements are
/// copies of the input `nodes` slice. Additional elements are computed by interpolation.
///
/// This implementation only works for large characteristic fields.
///
/// # Panics
///
/// Panics if `nodes.len() != context.nodes_len`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.1
/// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
pub(super) fn lagrange_extend<FE>(nodes: &[FE], context: &LagrangeExtendContext<FE>) -> Vec<FE>
where
    FE: LagrangePolynomialFieldElement,
{
    // For now we use the relatively straightforward method of computing Lagrange basis polynomials
    // for each provided point.
    //
    // https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
    assert_eq!(nodes.len(), context.nodes_len);
    let evaluations = context.evaluations;
    debug_assert!(
        evaluations > nodes.len(),
        "extend was called with an output length less than or equal to the input length"
    );
    if evaluations <= nodes.len() {
        return nodes[..evaluations].to_vec();
    }

    let mut output = Vec::with_capacity(evaluations);
    output.extend_from_slice(nodes);
    let mut denominators = vec![None; nodes.len()];

    for input in (nodes.len()..evaluations).map(|e| FE::from_u128(e as u128)) {
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
