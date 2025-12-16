use crate::fields::NttFieldElement;
use std::cmp;

/// Precomputed values for the convolution-based implementation of `extend()`.
pub struct ExtendContext<FE> {
    /// Length of the input vector.
    nodes_len: usize,
    /// Length of the output vector.
    evaluations: usize,
    /// Size of the NTT operation used for convolutions.
    ntt_size: usize,
    /// Reciprocals, used for the terms 1 / (k - i) or 1 / (k - d).
    ///
    /// The element at index zero is zero, then every other element is the reciprocal of its index.
    reciprocals: Vec<FE>,
    /// Binomial coefficients.
    ///
    /// binomial_coefficients[i] is d choose i.
    binomial_coefficients: Vec<FE>,
    /// Convolution kernel, in the NTT domain.
    ///
    /// This kernel incorporates both reciprocals, from the 1 / (k - i) term in the polynomial
    /// interpolation formula, and a factor of 1/ntt_size to cancel out the scaling that will be
    /// later performed by [`NttFieldElement::scaled_inverse_ntt_bit_reversed()`].
    transformed_convolution_kernel: Vec<FE>,
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
    FE: NttFieldElement,
{
    let ntt_size = evaluations.next_power_of_two();

    let reciprocals_len = cmp::max(evaluations + 1, ntt_size);
    let mut reciprocals = Vec::with_capacity(reciprocals_len);
    reciprocals.push(FE::ZERO);
    reciprocals
        .extend((1..reciprocals_len).map(|i| FE::from_u128(i.try_into().unwrap()).mul_inv()));

    let d = nodes_len - 1;
    let mut binomial_coefficients = Vec::with_capacity(nodes_len);
    let mut binomial = FE::ONE;
    binomial_coefficients.push(binomial);
    for (i, reciprocal) in reciprocals.iter().enumerate().take(nodes_len).skip(1) {
        binomial = binomial * FE::from_u128((d - i + 1).try_into().unwrap()) * reciprocal;
        binomial_coefficients.push(binomial);
    }

    let ntt_size_inv = FE::from_u128(u128::try_from(ntt_size).unwrap()).mul_inv();
    let mut convolution_left_terms = reciprocals[..ntt_size].to_vec();
    // Scale the convolution kernel by 1/ntt_size, to cancel out the scaling done later by
    // scaled_inverse_ntt_bit_reversed().
    for elem in convolution_left_terms.iter_mut() {
        *elem *= ntt_size_inv;
    }

    // Precompute the NTT transformation of the convolution kernel.
    let mut transformed_convolution_kernel = convolution_left_terms;
    FE::ntt_bit_reversed(&mut transformed_convolution_kernel);

    ExtendContext {
        nodes_len,
        evaluations,
        ntt_size,
        reciprocals,
        binomial_coefficients,
        transformed_convolution_kernel,
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
    FE: NttFieldElement,
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
    let mut convolution_right_terms = Vec::with_capacity(context.ntt_size);
    convolution_right_terms.extend(
        nodes
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
            }),
    );
    // Pad with zeros.
    convolution_right_terms.resize(context.ntt_size, FE::ZERO);

    // Apply NTT transform to convolution input array.
    let mut transformed_convolution_input = convolution_right_terms;
    FE::ntt_bit_reversed(&mut transformed_convolution_input);

    // Perform a pointwise multiplication in the NTT domain.
    for (input_elem, kernel_elem) in transformed_convolution_input
        .iter_mut()
        .zip(context.transformed_convolution_kernel.iter())
    {
        *input_elem *= *kernel_elem;
    }

    // Transform the convolution result back.
    let mut convolution_result = transformed_convolution_input;
    FE::scaled_inverse_ntt_bit_reversed(&mut convolution_result);

    for (k, convolution_elem) in convolution_result
        .iter()
        .enumerate()
        .take(evaluations)
        .skip(nodes.len())
    {
        // Calculate (k - d) * (k choose d) from k from this iteration, and (k-1) choose d from the last iteration,
        // using Remark A.3.
        let k_minus_d_times_k_choose_d = FE::from_u128(k.try_into().unwrap()) * binomial_k_d;
        // Update k choose d for k in this iteration, by dividing by (k - d).
        binomial_k_d = k_minus_d_times_k_choose_d * context.reciprocals[k - d];
        let mut evaluation = k_minus_d_times_k_choose_d * convolution_elem;
        // Multiply by (-1)^d. Note that it is safe to branch on d, since it is public knowledge.
        if d & 1 != 0 {
            evaluation = -evaluation;
        }
        output.push(evaluation);
    }

    output
}
