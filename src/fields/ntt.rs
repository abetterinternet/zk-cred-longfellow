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
    /// # Panics
    ///
    /// This panics if the length of the input is not a power of two.
    fn ntt_bit_reversed(_input: &mut [Self]) {
        todo!()
    }

    /// Computes the inverse Number Theoretic Transform of a sequence. The input must be in
    /// bit-reversed order. The result is returned in-place in the natural order.
    ///
    /// # Panics
    ///
    /// This panics if the length of the input is not a power of two.
    fn inverse_ntt_bit_reversed(_input: &mut [Self]) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{NttFieldElement, fieldp128::FieldP128, fieldp256_2::FieldP256_2};
    use wasm_bindgen_test::wasm_bindgen_test;

    fn test_ntt<FE: NttFieldElement>() {
        // Check constants.
        let two = FE::from_u128(2);
        assert_eq!(two * FE::HALF, FE::ONE);

        let mut temp = FE::ROOT_OF_UNITY;
        for _ in 0..FE::LOG2_ROOT_ORDER {
            assert_ne!(temp, FE::ONE);
            temp = temp.square();
        }
        assert_eq!(temp, FE::ONE);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p128() {
        test_ntt::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_p256_quadratic_extension() {
        test_ntt::<FieldP256_2>();
    }
}
