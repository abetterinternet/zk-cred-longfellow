use crate::fields::FieldElement;

/// Represents an element of an NTT-friendly field.
///
/// Fields implementing this trait must have a subgroup under multiplication with an order that has
/// many factors of two. For background on the NTT, see <https://eprint.iacr.org/2024/585>.
pub trait NttFieldElement: FieldElement {
    /// Roots of unity in the field, with power-of-two degrees.
    ///
    /// Each element at index i is a generator of the subgroup of the multiplicative group with
    /// order 2^i. Thus, it is an element omega that satisfies omega^(2^i) = 1, and omega^j != 1 for
    /// 0 < j < 2^i.
    ///
    /// This array is limited to only 32 elements, because all relevant fields have a subgroup of
    /// order 2^31, and an input size of 2^31 should be more than enough for the NTT operations we
    /// will perform.
    const ROOTS_OF_UNITY: [Self; 32];

    /// Roots of unity in the field, and the inverses of [`NttFieldElement::ROOTS_OF_UNITY`].
    ///
    /// Each element is the inverse of the corresponding element of
    /// [`NttFieldElement::ROOTS_OF_UNITY`].
    const ROOTS_OF_UNITY_INVERSES: [Self; 32];

    /// The multiplicative inverse of 2 in this field.
    const HALF: Self;

    /// Computes the Number Theoretic Transform of a sequence. The result is returned in-place in
    /// bit-reversed order.
    ///
    /// The `omegas` argument must be a list of power-of-two roots of unity, such that element i is
    /// the 2^i-th root of unity. It should start with 1 itself, and contain at least enough values
    /// to include the `values.len()`-th root of unity. Note that for each element in the array, its
    /// predecessor is its square.
    ///
    /// # Panics
    ///
    /// This panics if the length of the input is not a power of two, or if it is greater than 2^31.
    fn ntt_bit_reversed(values: &mut [Self]) {
        // Unwrap safety: usize should be at least as large as u32 anywhere we run.
        let log_n = usize::try_from(values.len().ilog2()).expect("u32 too big for usize?");
        if 1 << log_n != values.len() {
            panic!(
                "length of input to NTT was {}, which is not a power of two",
                values.len()
            );
        }
        if values.len() == 1 {
            return;
        }

        // Evaluate the NTT with the decimation-in-frequency radix-2 FFT algorithm.
        let mut stride = 1 << (log_n - 1);
        for omega in Self::ROOTS_OF_UNITY[1..=log_n].iter().rev() {
            // The i=0 iteration of the below loop is unrolled separately to save some multiplications.
            let mut j = 0;
            while j < values.len() {
                (values[j], values[j + stride]) = (
                    values[j] + values[j + stride],
                    (values[j] - values[j + stride]),
                );

                j += stride * 2;
            }

            let mut omega_power = *omega;
            for i in 1..stride {
                let mut j = i;
                while j < values.len() {
                    (values[j], values[j + stride]) = (
                        values[j] + values[j + stride],
                        (values[j] - values[j + stride]) * omega_power,
                    );

                    j += stride * 2;
                }
                omega_power *= *omega;
            }

            stride /= 2;
        }
    }

    /// Computes the inverse Number Theoretic Transform of a sequence, scaled by a constant. The
    /// input must be in bit-reversed order. The result is returned in-place in the natural order.
    ///
    /// The `omega_inverses` argument must be a list of power-of-two roots of unity, such that
    /// element i is the 2^i-th root of unity. It should start with 1 itself, and contain at least
    /// enough values to include the `values.len()`-th root of unity. Note that for each element in
    /// the array, its predecessor is its square. These values should be the multiplicative inverses
    /// of the roots of unity used during the forwards NTT transformation.
    ///
    /// The output is scaled by a factor of `values.len()`. This factor's inverse needs to be
    /// multiplied separately to get the inverse NTT result.
    ///
    /// # Panics
    ///
    /// This panics if the length of the input is not a power of two, or if it is greater than 2^31.
    fn scaled_inverse_ntt_bit_reversed(values: &mut [Self]) {
        // Unwrap safety: usize should be at least as large as u32 anywhere we run.
        let log_n = usize::try_from(values.len().ilog2()).expect("u32 too big for usize?");
        if 1 << log_n != values.len() {
            panic!(
                "length of input to inverse NTT was {}, which is not a power of two",
                values.len()
            );
        }
        if values.len() == 1 {
            return;
        }

        // Evaluate the inverse NTT.
        let mut stride = 1;
        for omega_inv in Self::ROOTS_OF_UNITY_INVERSES[1..=log_n].iter() {
            // The i=0 iteration of the below loop is unrolled separately to save some multiplications.
            let mut j = 0;
            while j < values.len() {
                (values[j], values[j + stride]) = (
                    values[j] + values[j + stride],
                    values[j] - values[j + stride],
                );

                j += stride * 2;
            }

            let mut omega_power = *omega_inv;
            for i in 1..stride {
                let mut j = i;
                while j < values.len() {
                    let product = values[j + stride] * omega_power;
                    (values[j], values[j + stride]) = (values[j] + product, values[j] - product);

                    j += stride * 2;
                }
                omega_power *= *omega_inv;
            }

            stride *= 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{
        CodecFieldElement, NttFieldElement, fieldp128::FieldP128, fieldp256::FieldP256,
        fieldp256_2::FieldP256_2,
    };
    use std::iter;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn test_ntt_constants<FE: NttFieldElement>() {
        // Check constants.
        let two = FE::from_u128(2);
        assert_eq!(two * FE::HALF, FE::ONE);

        assert_eq!(FE::ROOTS_OF_UNITY[0], FE::ONE);
        assert_eq!(FE::ROOTS_OF_UNITY_INVERSES[0], FE::ONE);
        for (elem, inv) in FE::ROOTS_OF_UNITY[1..]
            .iter()
            .zip(FE::ROOTS_OF_UNITY_INVERSES[1..].iter())
        {
            assert_ne!(*elem, FE::ONE);
            assert_eq!(*elem * inv, FE::ONE);
        }
        for window in FE::ROOTS_OF_UNITY.windows(2) {
            assert_eq!(window[0], window[1].square());
        }
    }

    fn test_ntt<FE: NttFieldElement>(random: impl Fn() -> FE) {
        // Run on various input sizes.
        test_ntt_with_size(&random, 1);
        test_ntt_with_size(&random, 2);
        test_ntt_with_size(&random, 4);
        test_ntt_with_size(&random, 8);
        test_ntt_with_size(&random, 16);
        test_ntt_with_size(&random, 32);
    }

    fn test_ntt_with_size<FE: NttFieldElement>(random: &impl Fn() -> FE, size: usize) {
        // Test NTT.
        let log2_size = size.ilog2();
        let input = iter::repeat_with(random).take(size).collect::<Vec<_>>();
        let mut inout = input.clone();
        FE::ntt_bit_reversed(&mut inout);
        let mut output = vec![FE::ZERO; size];
        if size == 1 {
            output[0] = inout[0];
        } else {
            for (i, output_elem) in output.iter_mut().enumerate() {
                let bit_reversed_index = i.reverse_bits() >> (usize::BITS - log2_size);
                *output_elem = inout[bit_reversed_index];
            }
        }
        // Compare with NTT definition.
        let mut expected = Vec::with_capacity(size);
        let omega_n = FE::ROOTS_OF_UNITY[usize::try_from(log2_size).unwrap()];
        assert_eq!(pow(omega_n, size.try_into().unwrap()), FE::ONE);
        if size > 1 {
            assert_ne!(pow(omega_n, u128::try_from(size).unwrap() / 2), FE::ONE);
        }
        for j in 0..size {
            let mut expected_elem = FE::ZERO;
            for (i, a_i) in input.iter().enumerate() {
                expected_elem += pow(omega_n, u128::try_from(i * j).unwrap()) * a_i;
            }
            expected.push(expected_elem);
        }
        assert_eq!(output, expected);

        // Test inverse NTT.
        FE::scaled_inverse_ntt_bit_reversed(&mut inout);
        let size_inv = pow(FE::HALF, log2_size.into());
        for elem in inout.iter_mut() {
            *elem *= size_inv;
        }
        assert_eq!(input, inout);
    }

    /// Field element exponentiation. See also [`crate::fields::LagrangePolynomialFieldElement::pow()`].
    fn pow<FE: NttFieldElement>(mut base: FE, mut exponent: u128) -> FE {
        let mut out = FE::ONE;

        while exponent > 0 {
            if exponent & 1 != 0 {
                out *= base;
            }
            exponent >>= 1;
            base = base.square();
        }

        out
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p128_constants() {
        test_ntt_constants::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p256_quadratic_extension_constants() {
        test_ntt_constants::<FieldP256_2>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p128() {
        test_ntt::<FieldP128>(FieldP128::sample);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p256_quadratic_extension() {
        test_ntt::<FieldP256_2>(|| FieldP256_2::new(FieldP256::sample(), FieldP256::sample()));
    }
}
