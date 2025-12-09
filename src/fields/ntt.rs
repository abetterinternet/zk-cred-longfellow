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
