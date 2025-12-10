//! Implements the extend procedure for binary fields, as specified in [2.2.2][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2

use crate::fields::{
    FieldElement,
    field2_128::{Field2_128, extend_constants::twiddle_array_at},
};
use std::cmp::min;

#[derive(Copy, Clone)]
pub struct ExtendContext {
    pub nodes_len: usize,
    pub evaluations: usize,
}

/// Twiddle the bits of coset by the normalized subspace vanishing polynomials.
///
/// Implements procedure TWIDDLE from Algorithm 1 in section 3.2 of [the paper][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn twiddle(power: u32, mut coset: usize) -> Field2_128 {
    let mut accumulator = Field2_128::ZERO;
    let mut position = 0;
    while coset > 0 {
        if coset & 1 == 1 {
            accumulator += twiddle_array_at(power, position);
        }
        coset >>= 1;
        position += 1;
    }

    accumulator
}

/// Compute all the twiddles needed for `curr_power` in linear time.
fn twiddles(curr_power: u32, power: u32, coset: usize, twiddled: &mut [Field2_128]) {
    // We need every (2 * recursive_len)th twiddle of curr_power, starting at coset. We
    // first straightforwardly compute TWIDDLE(curr_power, coset):
    twiddled[0] = twiddle(curr_power, coset);

    // Section 3.2 gives us the recurrence TWIDDLE(i, u + 2^k) = W_hat[i][k] + TWIDDLE(i, u).
    // Recall that 2 * recursive_len = 2 * 2 ^ curr_power.
    //
    // The next value we need is TWIDDLE(curr_power, coset + 2 * recursive_len)
    // = TWIDDLE(curr_power, coset + 2 * 2 ^ curr_power)
    // = TWIDDLE(curr_power, coset + 2^(curr_power + 1))
    //
    // Then by the recurrence:
    //
    // = TWIDDLE(curr_power, coset) + W_hat[curr_power][curr_power + 1]
    //
    // The next value we need is TWIDDLE(curr_power, coset + 2 * 2 * recursive_len)
    // = TWIDDLE(curr_power, coset) + W_hat[curr_power][curr_power + 2]
    //
    // The next value is TWIDDLE(curr_power, coset + 3 * 2 * recursive_len)
    //
    // This is trickier because we can't express 6 * recursive_len as a power of 2. Instead:
    //
    // = TWIDDLE(curr_power, coset + 2 * recursive_len + 2 * 2 * recursive_len)
    // = TWIDDLE(curr_power, coset + 2 * recursive_len) + W_hat[curr_power][curr_power + 2]
    //
    // ... and we did previously compute TWIDDLE(curr_power, coset + 2 * recursive_len).
    // Using that as TWIDDLE(i, u) in the recurrence lets us compute the next 4 values
    // before we need a bigger base twiddle again.
    //
    // So the 0th power increment lets us compute 1 twiddle element, then the 1st gets us 2,
    // and the nth computes 1 << n + 1.
    for power_increment in 0..(power - curr_power - 1) {
        for twiddle_base in 0..1 << power_increment {
            twiddled[twiddle_base + (1 << power_increment)] = twiddled[twiddle_base]
                + twiddle_array_at(curr_power, curr_power + 1 + power_increment);
        }
    }
}

/// Implements procedure BUTTERFLY-FWD from Algorithm 1 in section 3.2 of [the paper][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn fft_butterfly_forward(
    fft_array: &mut [Field2_128],
    index: usize,
    recursive_len: usize,
    twiddle: Field2_128,
) {
    fft_array[index] += twiddle * fft_array[index + recursive_len];
    fft_array[index + recursive_len] += fft_array[index];
}

/// Implements procedure BUTTERFLY-BWD from Algorithm 1 in section 3.2 of [the paper][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn fft_butterfly_backward(
    fft_array: &mut [Field2_128],
    index: usize,
    recursive_len: usize,
    twiddle: Field2_128,
) {
    fft_array[index + recursive_len] -= fft_array[index];
    fft_array[index] -= twiddle * fft_array[index + recursive_len];
}

/// Implements procedure BUTTERFLY-DIAG from Algorithm 1 in section 3.2 of [the paper][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn fft_butterfly_diagonal(
    fft_array: &mut [Field2_128],
    index: usize,
    recursive_len: usize,
    twiddle: Field2_128,
) {
    let prev_at_index = fft_array[index];

    fft_array[index] -= twiddle * fft_array[index + recursive_len];
    fft_array[index + recursive_len] += prev_at_index;
}

/// Direction in which the FFT operates.
#[derive(Eq, PartialEq)]
enum Direction {
    Forward,
    Backward,
}

/// Implements procedure FFT and IFFT (depending on direction) from Algorithm 1 in section 3.2
/// of [the paper][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn fft(direction: Direction, power: u32, coset: usize, fft_array: &mut [Field2_128]) {
    if power == 0 {
        return;
    }
    let mut twiddled = vec![Field2_128::ZERO; 1 << (power - 1)];
    for mut curr_power in 0..power {
        // Forward FFT iterates over power..0
        if direction == Direction::Forward {
            curr_power = power - curr_power - 1;
        }
        let recursive_len = 2usize.pow(curr_power);

        twiddles(curr_power, power, coset, &mut twiddled);

        // for all u : 0 ≤ 2s · u < 2ℓ
        for (index, start) in (0..2usize.pow(power))
            .step_by(2 * recursive_len)
            .enumerate()
        {
            let twiddle = twiddled[index];
            for v in 0..recursive_len {
                match direction {
                    Direction::Forward => {
                        fft_butterfly_forward(fft_array, start + v, recursive_len, twiddle)
                    }
                    Direction::Backward => {
                        fft_butterfly_backward(fft_array, start + v, recursive_len, twiddle)
                    }
                };
            }
        }
    }
}

/// Perform a Fast Fourier Transform in the novel polynomial basis, in place.
///
/// The first `nodes_count` elements of `fft_array` are evaluations of a polynomial in one variable
/// of degree up to `nodes_count - 1`. The FFT is used to interpolate and evaluate it.
///
/// On return, the first `nodes_count` elements of `fft_array` are coefficients of the polynomial
/// and the remainder is evaluations of it at points `[nodes_count..fft_array.len()]`.
///
/// `fft_array.len()` must be `2^power` and greater than `nodes_count`. `coset` is which coset to
/// recurse on and twiddle with.
///
/// Corresponds to Algorithm 2: Bidirectional-FFT in [the paper][1]. Their `k` is `nodes_count`
/// here, their `i` is `power`, their alpha is `coset` and their `B` is `fft_array`.
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
fn bidirectional_fft(
    mut power: u32,
    coset: usize,
    nodes_count: usize,
    fft_array: &mut [Field2_128],
) {
    assert_eq!(
        fft_array.len(),
        2usize.pow(power),
        "length of fft_array must be 2^power"
    );
    assert!(nodes_count <= fft_array.len());

    if power > 0 {
        power -= 1;
        let recursive_len = 2usize.pow(power);
        assert_eq!(recursive_len, 1 << power);
        let twiddle = twiddle(power, coset);
        if nodes_count < recursive_len {
            // Forward FFT: evaluate the polynomial
            for v in nodes_count..recursive_len {
                fft_butterfly_forward(fft_array, v, recursive_len, twiddle);
            }
            bidirectional_fft(power, coset, nodes_count, &mut fft_array[..recursive_len]);
            for v in 0..nodes_count {
                fft_butterfly_diagonal(fft_array, v, recursive_len, twiddle);
            }
            fft(
                Direction::Forward,
                power,
                coset + recursive_len,
                &mut fft_array[recursive_len..],
            );
        } else {
            // Inverse FFT: replace evaluations of the polynomial with coefficients
            fft(
                Direction::Backward,
                power,
                coset,
                &mut fft_array[..recursive_len],
            );
            for v in (nodes_count - recursive_len)..recursive_len {
                fft_butterfly_diagonal(fft_array, v, recursive_len, twiddle);
            }
            bidirectional_fft(
                power,
                coset + recursive_len,
                nodes_count - recursive_len,
                &mut fft_array[recursive_len..],
            );
            for v in 0..(nodes_count - recursive_len) {
                fft_butterfly_backward(fft_array, v, recursive_len, twiddle);
            }
        }
    }
}

/// Interpolate a polynomial from the provided nodes, then evaluate it at points
/// 0..requested_evaluations.
pub(crate) fn interpolate(nodes: &[Field2_128], requested_evaluations: usize) -> Vec<Field2_128> {
    // We first run the bidirectional FFT to interpolate the polynomial, then run forward FFTs over
    // as many coset as are needed to evaluate all the requested points.
    //
    // See "Details of Reed-Solomon encoding" in paper section 3.2.
    //
    // The FFT must run in an array whose size is a power of two.
    let fft_size = nodes.len().next_power_of_two();
    let power = fft_size.ilog2();

    let mut fft_vec = nodes.to_vec();
    fft_vec.resize(fft_size, Field2_128::ZERO);

    // Run the bidirectional FFT to get context.nodes_len coefficients of the polynomial, then
    // fft_size - context.nodes_len evaluations of the polynomial in fft_vec.
    bidirectional_fft(power, 0, nodes.len(), &mut fft_vec);

    let mut out_vec = vec![Field2_128::ZERO; requested_evaluations];

    // Copy the provided evaluations from the nodes to the output
    out_vec[..nodes.len()].copy_from_slice(nodes);

    // Copy evaluations from the first coset, if any
    let range = nodes.len()..min(fft_size, requested_evaluations);
    let fft_vec_evals = &mut fft_vec[range.clone()];
    out_vec[range].copy_from_slice(fft_vec_evals);

    // Zero out evaluations in fft_vec so we can use it for FFT again
    fft_vec_evals.fill(Field2_128::ZERO);

    // Use the forward FFT over the remaining cosets, each of size 2^power, to compute the remaining
    // requested evaluations.
    for curr_power in (1..).map_while(|coset| {
        let curr_power = coset << power;
        if curr_power >= requested_evaluations {
            None
        } else {
            Some(curr_power)
        }
    }) {
        // If there's enough room left in out_vec, we copy the coefficients from fft_vec into the
        // output vec and transform in place.
        //
        // If not, then this has to be the last iteration of the loop. We do the transform in
        // fft_vec. That will overwrite the coefficients, but that's okay: we don't need them
        // anymore after this iteration.
        if curr_power + fft_size <= requested_evaluations {
            out_vec[curr_power..(fft_size + curr_power)].copy_from_slice(&fft_vec[..fft_size]);
            fft(
                Direction::Forward,
                power,
                curr_power,
                &mut out_vec[curr_power..],
            );
        } else {
            fft(Direction::Forward, power, curr_power, &mut fft_vec);
            out_vec[curr_power..requested_evaluations]
                .copy_from_slice(&fft_vec[..(requested_evaluations - curr_power)]);
        }
    }

    out_vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::LagrangePolynomialFieldElement;
    use rand::random;
    use std::{iter::repeat_with, ops::Range};

    #[test]
    fn twiddles_equivalency() {
        let power = 16;
        let mut twiddled = vec![Field2_128::ZERO; 1 << (power - 1)];
        for curr_power in 0..power {
            twiddles(curr_power, power, 0, &mut twiddled);

            for (index, start) in (0..2usize.pow(power))
                .step_by(2 * 2usize.pow(curr_power))
                .enumerate()
            {
                let slow_twiddle = twiddle(curr_power, start);
                let twiddle = twiddled[index];
                assert_eq!(slow_twiddle, twiddle);
            }
        }
    }

    #[test]
    fn extend_gf_2_128() {
        fn eval_horners_method(polynomial: &[Field2_128], eval_at: Range<u16>) -> Vec<Field2_128> {
            eval_at
                .map(|x| {
                    let x = Field2_128::inject(x);
                    let mut output = Field2_128::ZERO;

                    for coefficient in polynomial.iter().rev() {
                        output = output * x + *coefficient;
                    }

                    output
                })
                .collect()
        }

        // Interpolate to various numbers of evaluations, falling just before, just after or on
        // powers of two
        for requested_evaluations in [1, 63, 64, 65, 99, 128] {
            for polynomial_degree in 1..requested_evaluations {
                // Generate a random polynomial and evaluate nodes
                let polynomial: Vec<_> = repeat_with(|| Field2_128::inject(random()))
                    .take(polynomial_degree)
                    .collect();

                // Evaluate the polynomial using the slow method
                let expected =
                    eval_horners_method(&polynomial, 0..requested_evaluations.try_into().unwrap());

                // Interpolate from the nodes
                let extended = Field2_128::extend(
                    &expected[0..polynomial_degree],
                    &Field2_128::extend_precompute(polynomial_degree, requested_evaluations),
                );

                assert_eq!(
                    extended, expected,
                    "interpolation mismatch at degree {polynomial_degree} and requested \
                    evaluations {requested_evaluations}"
                );
            }
        }
    }
}
