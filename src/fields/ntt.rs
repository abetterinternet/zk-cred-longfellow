use crate::fields::FieldElement;

/// Represents an element of an NTT-friendly field.
///
/// Fields implementing this trait must have a subgroup under multiplication with
pub trait NttFieldElement: FieldElement {
    /// A 2^k-th root of unity in the field.
    ///
    /// A 2^k-th root of unity of a field is a generator of the subgroup of the multiplicative group
    /// with order 2^k. Thus, it satisfies omega^(2^k) = 1, and omega^i != 1 for 0 < i < 2^k.
    const ROOT_OF_UNITY: Self;

    /// The base-2 logarithm of the order of `ROOT_OF_UNITY` in the multiplicative group.
    const LOG2_ROOT_ORDER: usize;

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
    /// This panics if the length of the input is not a power of two.
    ///
    /// This panics if there are not enough roots of unity in `omegas`.
    fn ntt_bit_reversed(values: &mut [Self], omegas: &[Self]) {
        let log_n = usize::try_from(values.len().ilog2()).unwrap();
        if 1 << log_n != values.len() {
            panic!(
                "length of input to NTT was {}, which is not a power of two",
                values.len()
            );
        }

        // Evaluate the NTT with the decimation-in-frequency radix-2 FFT algorithm.
        let mut stride = 1 << (log_n - 1);
        for omega in omegas[1..=log_n].iter().rev() {
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
                if i < stride - 1 {
                    omega_power *= *omega;
                }
            }

            stride /= 2;
        }
    }

    /// Computes the inverse Number Theoretic Transform of a sequence. The input must be in
    /// bit-reversed order. The result is returned in-place in the natural order.
    ///
    /// The `omegas` argument must be a list of power-of-two roots of unity, such that element i is
    /// the 2^i-th root of unity. It should start with 1 itself, and contain at least enough values
    /// to include the `values.len()`-th root of unity. Note that for each element in the array, its
    /// predecessor is its square.
    ///
    /// The `size_inv` argument must be the multiplicative inverse of the length of the input array.
    ///
    /// # Panics
    ///
    /// This panics if the length of the input is not a power of two.
    ///
    /// This panics if there are not enough roots of unity in `omegas`.
    fn inverse_ntt_bit_reversed(values: &mut [Self], _omegas: &[Self], _size_inv: Self) {
        let log_n = values.len().ilog2();
        if 1 << log_n != values.len() {
            panic!(
                "length of input to NTT was {}, which is not a power of two",
                values.len()
            );
        }
        todo!()
    }

    /// Precomputes roots of unity of different degrees, for use in NTT and inverse NTT operations.
    ///
    /// This returns a vector of elements where the element at index i is the 2^i-th root of unity,
    /// and the element at index 0 is 1 itself.
    fn omegas() -> Vec<Self> {
        let mut output = vec![Self::ZERO; Self::LOG2_ROOT_ORDER + 1];
        let mut root = Self::ROOT_OF_UNITY;
        for output_elem in output.iter_mut().rev() {
            *output_elem = root;
            root = root.square();
        }
        output
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

    fn test_ntt<FE: NttFieldElement>(random: impl Fn() -> FE) {
        // Check constants.
        let two = FE::from_u128(2);
        assert_eq!(two * FE::HALF, FE::ONE);

        let mut temp = FE::ROOT_OF_UNITY;
        for _ in 0..FE::LOG2_ROOT_ORDER {
            assert_ne!(temp, FE::ONE);
            temp = temp.square();
        }
        assert_eq!(temp, FE::ONE);

        test_ntt_with_size(&random, 2);
        test_ntt_with_size(&random, 4);
        test_ntt_with_size(&random, 8);
        test_ntt_with_size(&random, 16);
        test_ntt_with_size(&random, 32);
    }

    fn test_ntt_with_size<FE: NttFieldElement>(random: &impl Fn() -> FE, size: usize) {
        // Test NTT.
        let log2_size = size.ilog2();
        let omegas = FE::omegas();
        assert_eq!(omegas[0], FE::ONE);
        assert_eq!(omegas[1], -FE::ONE);
        let input = iter::repeat_with(random).take(size).collect::<Vec<_>>();
        let mut inout = input.clone();
        FE::ntt_bit_reversed(&mut inout, &omegas);
        let mut output = vec![FE::ZERO; size];
        for (i, output_elem) in output.iter_mut().enumerate() {
            let bit_reversed_index = i.reverse_bits() >> (usize::BITS - log2_size);
            *output_elem = inout[bit_reversed_index];
        }
        // Compare with NTT definition.
        let mut expected = Vec::with_capacity(size);
        let omega_n = pow(
            FE::ROOT_OF_UNITY,
            1 << (FE::LOG2_ROOT_ORDER - usize::try_from(log2_size).unwrap()),
        );
        assert_eq!(pow(omega_n, size.try_into().unwrap()), FE::ONE);
        assert_ne!(pow(omega_n, u128::try_from(size).unwrap() / 2), FE::ONE);
        for j in 0..size {
            let mut expected_elem = FE::ZERO;
            for (i, a_i) in input.iter().enumerate() {
                expected_elem += pow(omega_n, u128::try_from(i * j).unwrap()) * a_i;
            }
            expected.push(expected_elem);
        }
        assert_eq!(output, expected);

        // TODO: Test inverse NTT.
        // FE::inverse_ntt_bit_reversed(&mut inout);
        // assert_eq!(input, inout);
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
    fn test_p128() {
        test_ntt::<FieldP128>(FieldP128::sample);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p256_quadratic_extension() {
        test_ntt::<FieldP256_2>(|| FieldP256_2::new(FieldP256::sample(), FieldP256::sample()));
    }
}
