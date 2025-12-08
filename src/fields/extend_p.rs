use crate::fields::LagrangePolynomialFieldElement;

/// Precomputed values for the convolution-based implementation of `extend()`.
pub struct ExtendContext<FE> {
    /// Length of the input vector.
    nodes_len: usize,
    /// Length of the output vector.
    evaluations: usize,
    /// Reciprocals, used for the terms 1 / (k - i) or 1 / (k - d).
    ///
    /// The element at index zero is zero, then every other element is the reciprocal of its index.
    reciprocals: Vec<FE>,
    /// Binomial coefficients.
    ///
    /// binomial_coefficients[i] is d choose i.
    binomial_coefficients: Vec<FE>,
}

/// Precompute values for the convolution-based implementation of `extend()`.
///
/// This function precomputes reciprocals and binomial coefficients needed by `extend()`.
/// The returned context can be reused for multiple calls to `extend()` with the same
/// dimensions, amortizing the O(evaluations) precomputation cost.
///
/// # Parameters
///
/// * `nodes_len` - The number of input nodes (degree + 1 of the polynomial)
/// * `evaluations` - The desired output length
pub(super) fn extend_precompute<FE>(nodes_len: usize, evaluations: usize) -> ExtendContext<FE>
where
    FE: LagrangePolynomialFieldElement,
{
    let mut reciprocals = Vec::with_capacity(evaluations + 1);
    reciprocals.push(FE::ZERO);
    reciprocals.extend((1..=evaluations).map(|i| FE::from_u128(i.try_into().unwrap()).mul_inv()));

    let d = nodes_len - 1;
    let mut binomial_coefficients = Vec::with_capacity(nodes_len);
    let mut binomial = FE::ONE;
    binomial_coefficients.push(binomial);
    for (i, reciprocal) in reciprocals.iter().enumerate().take(nodes_len).skip(1) {
        binomial = binomial * FE::from_u128((d - i + 1).try_into().unwrap()) * reciprocal;
        binomial_coefficients.push(binomial);
    }

    ExtendContext {
        nodes_len,
        evaluations,
        reciprocals,
        binomial_coefficients,
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
pub(super) fn extend<FE>(nodes: &[FE], context: &ExtendContext<FE>) -> Vec<FE>
where
    FE: LagrangePolynomialFieldElement,
{
    // For now we use equation (2) from "Anonymous Credentials from ECDSA", as-is.
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

    // This variable is set to k choose d throughout the algorithm (where d is `nodes.len() - 1`).
    // We initialize it to d choose d, which is 1. Remark A.3 from the paper gives the recurrence
    // rule used to update this variable.
    let mut binomial_k_d = FE::ONE;
    let d = nodes.len() - 1;

    // Precompute (-1)^i * (d choose i) * p(i).
    let convolution_right_terms = nodes
        .iter()
        .enumerate()
        .zip(context.binomial_coefficients.iter())
        .map(|((i, p_i), binomial_coefficient)| {
            let mut right = *binomial_coefficient * p_i;
            // Multiply by (-1)^i. Note that it is safe to branch on i, since it doesn't depend on
            // any secret.
            if i & 1 != 0 {
                right = -right;
            }
            right
        })
        .collect::<Vec<FE>>();

    for k in nodes.len()..evaluations {
        // Calculate (k - d) * (k choose d) from k from this iteration, and (k-1) choose d from the last iteration,
        // using Remark A.3.
        let k_minus_d_times_k_choose_d = FE::from_u128(k.try_into().unwrap()) * binomial_k_d;
        // Update k choose d for k in this iteration, by dividing by (k - d).
        binomial_k_d = k_minus_d_times_k_choose_d * context.reciprocals[k - d];
        let sum = context.reciprocals[k - nodes.len() + 1..=k]
            .iter()
            .rev()
            .zip(convolution_right_terms.iter())
            .map(|(left, right)| *left * right)
            .fold(FE::ZERO, |accumulator, value| accumulator + value);
        let mut evaluation = k_minus_d_times_k_choose_d * sum;
        // Multiply by (-1)^d. Note that it is safe to branch on d, since it is public knowledge.
        if d & 1 != 0 {
            evaluation = -evaluation;
        }
        output.push(evaluation);
    }

    output
}
