//! Implementation of GF(2^128).
//!
//! This is defined using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.

use crate::{
    Codec,
    fields::{
        CodecFieldElement, FieldElement, ProofFieldElement, addition_chains,
        field2_128::extend::{ExtendContext, interpolate},
    },
};
use anyhow::{Context, anyhow};
use constants::{subfield_basis, subfield_basis_lu_decomposition};
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicU8, Ordering};
use std::{
    fmt::Debug,
    io::{Cursor, Read},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::FieldId;

/// An element of the field GF(2^128).
///
/// This field is constructed using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
#[derive(Clone, Copy)]
pub struct Field2_128(u128);

impl Field2_128 {
    const SUBFIELD_BIT_LENGTH: usize = 16;

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    const fn from_u128_const(value: u128) -> Self {
        Self(value)
    }

    /// Inject the value into the field using the subfield basis, per [2.2.2][1]. The basis only has
    /// 16 elements, so we can't inject anything bigger than u16.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
    pub fn inject(value: u16) -> Self {
        // It's safe and reasonable to inject any u16 because the basis has 16 elements.
        const BITS: usize = u16::BITS as usize;
        assert_eq!(subfield_basis().len(), BITS);
        Self::inject_bits::<BITS>(value)
    }

    /// Inject a value with a limited number of bits into the field using the subfield basis.
    ///
    /// This is similar to [`Self::inject()`], but skips certain loop iterations. This can be used
    /// as an optimization when encoding values that are statically known to be far smaller than
    /// [`u16::MAX`].
    pub fn inject_bits<const BITS: usize>(mut value: u16) -> Self {
        let mut injected = Self::ZERO;
        for basis_element in &subfield_basis()[..BITS] {
            let bit = Choice::from((value & 1) as u8);
            injected += Self::conditional_select(&Self::ZERO, basis_element, bit);
            value >>= 1;
        }
        debug_assert_eq!(value, 0);

        injected
    }

    /// Reverse [`Self::inject`]: find the representation of `self` in the subfield, if it exists.
    /// In other words, determine if this element of `GF(2^128)` is also an element of the subfield.
    /// The representation is a u16, which is interpreted as a vector of bits that can be dotted
    /// with the subfield basis to get the GF(2^128) representation, but is also the encoding of the
    /// field element.
    pub fn uninject(&self) -> Option<u16> {
        let decomposition = subfield_basis_lu_decomposition();

        let mut remainder = self.0;
        let mut subfield_encoding = 0u16;

        for rank in 0..Self::SUBFIELD_BIT_LENGTH {
            let bit = Choice::from(((remainder >> decomposition.first_nonzero[rank]) & 1) as u8);
            // Subtract the row-reduced element of beta from the value we started with
            remainder ^= u128::conditional_select(&0, &decomposition.upper[rank], bit);
            // Sum the corresponding coefficients of the linear combination of basis elements into
            // the encoding.
            subfield_encoding ^=
                u16::conditional_select(&0, &decomposition.lower_inverse[rank], bit);
            // Recall that in GF(2), addition and subtraction are the same and in turn boil down to
            // XOR
        }

        if remainder == 0 {
            Some(subfield_encoding)
        } else {
            None
        }
    }

    /// Decomposes a field element into bits.
    pub fn iter_bits(&self) -> impl Iterator<Item = bool> {
        (0..Self::NUM_BITS).map(|i| (self.0 >> i) & 1 != 0)
    }
}

/// The lower-upper decomposition of the basis for the 16-bit subfield of [`Field2_128`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubfieldBasisLowerUpperDecomposition {
    upper: [u128; Field2_128::SUBFIELD_BIT_LENGTH],
    lower_inverse: [u16; Field2_128::SUBFIELD_BIT_LENGTH],
    first_nonzero: [usize; Field2_128::SUBFIELD_BIT_LENGTH],
}

impl FieldElement for Field2_128 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(0b1);

    fn from_u128(value: u128) -> Self {
        Self(value)
    }

    fn square(&self) -> Self {
        Self(galois_square(self.0))
    }

    fn mul_inv(&self) -> Self {
        // Compute the multiplicative inverse by exponentiating to the power (2^128 - 2). See
        // FieldP256::mul_inv() for an explanation of this technique.
        addition_chains::gf_2_128_m2::exp(*self)
    }
}

impl CodecFieldElement for Field2_128 {
    const NUM_BITS: u32 = 128;

    const FIELD_ID: super::FieldId = FieldId::GF2_128;

    fn is_in_subfield(&self) -> bool {
        self.uninject().is_some()
    }

    fn encode_in_subfield(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let subfield_encoding = self
            .uninject()
            .ok_or_else(|| anyhow!("GF(2^128) element {:?} is not in subfield", self))?;

        subfield_encoding.encode(bytes)
    }

    fn decode_fixed_array_in_subfield(
        bytes: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let subfield_elements = u16::decode_fixed_array(bytes, count)?;

        Ok(subfield_elements.iter().map(|e| Self::inject(*e)).collect())
    }
}

impl ProofFieldElement for Field2_128 {
    // These constants were computed using constants.sage.
    const SUMCHECK_P2: Self = Self::from_u128_const(122753392676920971658749122761936853580);

    const SUMCHECK_P2_MUL_INV: Self =
        Self::from_u128_const(334209021876177427854041998379618990425);

    const ONE_MINUS_SUMCHECK_P2_MUL_INV: Self =
        Self::from_u128_const(184748276259172837197859239441540652321);

    const SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV: Self =
        Self::from_u128_const(150968175972766452367765019741058622584);

    type ExtendContext = ExtendContext;

    fn extend_precompute(nodes_len: usize, evaluations: usize) -> Self::ExtendContext {
        ExtendContext {
            nodes_len,
            evaluations,
        }
    }

    fn extend(nodes: &[Self], context: &Self::ExtendContext) -> Vec<Self> {
        assert_eq!(nodes.len(), context.nodes_len);
        interpolate(nodes, context.evaluations)
    }
}

impl Debug for Field2_128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Field2_128(0x{:032x})", self.0)
    }
}

impl Default for Field2_128 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for Field2_128 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Field2_128 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Field2_128 {}

impl From<u64> for Field2_128 {
    fn from(value: u64) -> Self {
        Self::from_u128(value as u128)
    }
}

impl TryFrom<&[u8]> for Field2_128 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference =
            <&[u8; 16]>::try_from(value).context("failed to decode Field2_128")?;
        Ok(Self(u128::from_le_bytes(*array_reference)))
    }
}

impl Codec for Field2_128 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 16];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read Field2_128 element")?;
        Ok(Self(u128::from_le_bytes(buffer)))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes.extend_from_slice(&self.0.to_le_bytes());
        Ok(())
    }
}

impl Add<&Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for Field2_128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Sub<&Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub<Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl SubAssign for Field2_128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Mul<&Self> for Field2_128 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self(galois_multiply(self.0, rhs.0))
    }
}

impl Mul<Self> for Field2_128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(galois_multiply(self.0, rhs.0))
    }
}

impl MulAssign for Field2_128 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = galois_multiply(self.0, rhs.0);
    }
}

impl Neg for Field2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl ConditionallySelectable for Field2_128 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Self(u128::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(target_arch = "aarch64")]
mod backend_aarch64;
mod backend_bit_slicing;
#[cfg(test)]
mod backend_naive_loop;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod backend_x86;
mod constants;
mod extend;

/// Cache for runtime CPU feature support detection.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
struct CachedFeatureFlag {
    /// Stores whether feature detection has been performed yet, and what the result was.
    ///
    /// Multiple threads are allowed to race to initialize this state.
    state: AtomicU8,

    /// Function that determines whether the specific feature is supported.
    callback: fn() -> bool,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
impl CachedFeatureFlag {
    const MASK_INITIALIZED: u8 = 0b01;
    const MASK_SUPPORTED: u8 = 0b10;

    pub const fn new(callback: fn() -> bool) -> Self {
        Self {
            state: AtomicU8::new(0),
            callback,
        }
    }

    pub fn get(&self) -> bool {
        let mut state = self.state.load(Ordering::Relaxed);

        if state & Self::MASK_INITIALIZED == 0 {
            let result = (self.callback)();
            state |= Self::MASK_INITIALIZED;
            if result {
                state |= Self::MASK_SUPPORTED;
            }
            self.state.fetch_or(state, Ordering::Relaxed);
        }

        state & Self::MASK_SUPPORTED != 0
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
    is_x86_feature_detected!("sse2") && is_x86_feature_detected!("pclmulqdq")
});
#[cfg(target_arch = "aarch64")]
static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
    is_aarch64_feature_detected!("neon") && is_aarch64_feature_detected!("aes")
});

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This dispatches to an appropriate implementation depending on CPU support, or a fallback
/// implementation.
fn galois_multiply(x: u128, y: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if FEATURES.get() {
        return unsafe { backend_x86::galois_multiply(x, y) };
    }
    #[cfg(target_arch = "aarch64")]
    if FEATURES.get() {
        return unsafe { backend_aarch64::galois_multiply(x, y) };
    }
    backend_bit_slicing::galois_multiply(x, y)
}

/// Squares a GF(2^128) element, represented as a `u128`.
///
/// This dispatches to an appropriate implementation depending on CPU support, or a fallback
/// implementation.
fn galois_square(x: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if FEATURES.get() {
        return unsafe { backend_x86::galois_square(x) };
    }
    #[cfg(target_arch = "aarch64")]
    if FEATURES.get() {
        return unsafe { backend_aarch64::galois_square(x) };
    }
    backend_bit_slicing::galois_square(x)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "aarch64")]
    use crate::fields::field2_128::backend_aarch64;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use crate::fields::field2_128::backend_x86;
    use crate::fields::{
        CodecFieldElement,
        field2_128::{
            Field2_128, backend_bit_slicing, backend_naive_loop, galois_multiply, galois_square,
        },
    };
    use rand::random;
    use wasm_bindgen_test::wasm_bindgen_test;

    static ARGS: [u128; 8] = [
        u128::MIN,
        u128::MAX,
        0x5555_5555_5555_5555_5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA,
        0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE,
        0x8000_0000_0000_0000_0000_0000_0000_0001,
        0x8000_0000_0000_0000_0000_0000_0000_0002,
        0x0000_0000_0000_0001_0000_0000_0000_0000,
    ];

    #[wasm_bindgen_test(unsupported = test)]
    fn compare_bit_slicing() {
        for (i, x) in ARGS.into_iter().enumerate() {
            for y in ARGS[i..].iter().copied() {
                let expected = backend_naive_loop::galois_multiply(x, y);
                let result = backend_bit_slicing::galois_multiply(x, y);
                assert_eq!(
                    expected, result,
                    "0x{x:x} * 0x{y:x}, 0x{expected:x} != 0x{result:x}"
                );
                let assoc_result = backend_bit_slicing::galois_multiply(y, x);
                assert_eq!(
                    expected, assoc_result,
                    "0x{x:x} * 0x{y:x}, 0x{expected:x} != 0x{assoc_result:x}"
                );
            }
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:x}^2, 0x{expected:x} != 0x{result:x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn feature_detection() {
        let result = galois_multiply(3, 3);
        assert_eq!(result, 5);
        let result = galois_square(3);
        assert_eq!(result, 5);
    }

    // This test vector is taken from the Intel white paper "Intel Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode".
    const TEST_VECTOR_A: u128 = 0x7b5b54657374566563746f725d53475d;
    const TEST_VECTOR_B: u128 = 0x48692853686179295b477565726f6e5d;
    const TEST_VECTOR_PRODUCT: u128 = 0x40229a09a5ed12e7e4e10da323506d2;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_vector_naive_loop() {
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_vector_bit_slicing() {
        let result = backend_bit_slicing::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = backend_bit_slicing::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_vector_x86() {
        let result = unsafe { backend_x86::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = unsafe { backend_x86::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_vector_aarch64() {
        let result = unsafe { backend_aarch64::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = unsafe { backend_aarch64::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "nondeterministic test"]
    fn random_test_multiply_bit_slicing() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_naive_loop::galois_multiply(x, y);
            let result = backend_bit_slicing::galois_multiply(x, y);
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "nondeterministic test"]
    fn random_test_square_bit_slicing() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn random_test_multiply_x86() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_bit_slicing::galois_multiply(x, y);
            let result = unsafe { backend_x86::galois_multiply(x, y) };
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn random_test_square_x86() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_x86::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(target_arch = "aarch64")]
    fn random_test_multiply_aarch64() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_bit_slicing::galois_multiply(x, y);
            let result = unsafe { backend_aarch64::galois_multiply(x, y) };
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(target_arch = "aarch64")]
    fn random_test_square_aarch64() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_aarch64::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "test is slow without optimization"]
    fn low_hamming_weight_bit_slicing() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_naive_loop::galois_multiply(x, y);
                let result = backend_bit_slicing::galois_multiply(x, y);
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn low_hamming_weight_x86() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_bit_slicing::galois_multiply(x, y);
                let result = unsafe { backend_x86::galois_multiply(x, y) };
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_x86::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn low_hamming_weight_aarch64() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_bit_slicing::galois_multiply(x, y);
                let result = unsafe { backend_aarch64::galois_multiply(x, y) };
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_aarch64::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    fn inject_roundtrip() {
        for to_inject in 0..u16::MAX {
            let in_subfield = Field2_128::inject(to_inject);
            assert!(in_subfield.is_in_subfield());
            assert_eq!(in_subfield.uninject(), Some(to_inject));
        }
    }

    #[test]
    fn inject_not_in_subfield() {
        let not_in_subfield = Field2_128::from_u128_const(u128::MAX);
        assert!(!not_in_subfield.is_in_subfield());
        assert_eq!(not_in_subfield.uninject(), None);
    }
}
