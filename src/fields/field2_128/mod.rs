//! Implementation of GF(2^128).
//!
//! This is defined using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.

use crate::{
    Codec,
    fields::{
        CodecFieldElement, FieldElement, LagrangePolynomialFieldElement, mul_inv_field_order,
    },
};
use anyhow::Context;
use num_bigint::BigUint;
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicU8, Ordering};
use std::{
    fmt::Debug,
    io::{Cursor, Read},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::ConstantTimeEq;

/// An element of the field GF(2^128).
///
/// This field is constructed using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
#[derive(Clone, Copy)]
pub struct Field2_128(u128);

impl FieldElement for Field2_128 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(0b1);
    const SUMCHECK_P2: Self = Self(0b10);

    fn from_u128(value: u128) -> Self {
        Self(value)
    }

    fn square(&self) -> Self {
        *self * self
    }
}

impl CodecFieldElement for Field2_128 {
    const NUM_BITS: u32 = 128;
}

impl LagrangePolynomialFieldElement for Field2_128 {
    fn sumcheck_p2_mul_inv() -> Self {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(x).inverse().to_integer()
        Self::from_u128(170141183460469231731687303715884105795)
    }

    fn one_minus_sumcheck_p2_mul_inv() -> Self {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(1 - x).inverse().to_integer()
        Self::from_u128(340282366920938463463374607431768211330)
    }

    fn sumcheck_p2_squared_minus_sumcheck_p2_mul_inv() -> Self {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(x^2 - x).inverse().to_integer()
        Self::from_u128(170141183460469231731687303715884105665)
    }

    fn mul_inv(&self) -> Self {
        let field_order = BigUint::from_slice(&[0, 0, 0, 0, 1]); // 2 ^ 128
        mul_inv_field_order(self, field_order)
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

#[cfg(target_arch = "aarch64")]
mod backend_aarch64;
mod backend_bit_slicing;
#[cfg(test)]
mod backend_naive_loop;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod backend_x86;

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

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This dispatches to an appropriate implementation depending on CPU support, or a fallback
/// implementation.
fn galois_multiply(x: u128, y: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
            is_x86_feature_detected!("sse2") && is_x86_feature_detected!("pclmulqdq")
        });
        if FEATURES.get() {
            return unsafe { backend_x86::galois_multiply(x, y) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
            is_aarch64_feature_detected!("neon") && is_aarch64_feature_detected!("aes")
        });
        if FEATURES.get() {
            return unsafe { backend_aarch64::galois_multiply(x, y) };
        }
    }
    backend_bit_slicing::galois_multiply(x, y)
}

#[cfg(test)]
mod tests {
    use rand::random;

    #[cfg(target_arch = "aarch64")]
    use crate::fields::field2_128::backend_aarch64;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use crate::fields::field2_128::backend_x86;
    use crate::fields::field2_128::{backend_bit_slicing, backend_naive_loop, galois_multiply};

    static ARGS: [u128; 8] = [
        u128::MIN,
        u128::MAX,
        0x5555_5555_5555_5555_5555_5555_5555_5555u128,
        0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128,
        0x8000_0000_0000_0000_0000_0000_0000_0001u128,
        0x8000_0000_0000_0000_0000_0000_0000_0002u128,
        0x0000_0000_0000_0001_0000_0000_0000_0000u128,
    ];

    #[test]
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
        }
    }

    #[test]
    fn feature_detection() {
        let result = galois_multiply(3, 3);
        assert_eq!(result, 5);
    }

    // This test vector is taken from the Intel white paper "Intel Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode".
    const TEST_VECTOR_A: u128 = 0x7b5b54657374566563746f725d53475d;
    const TEST_VECTOR_B: u128 = 0x48692853686179295b477565726f6e5d;
    const TEST_VECTOR_PRODUCT: u128 = 0x40229a09a5ed12e7e4e10da323506d2;

    #[test]
    fn test_vector_naive_loop() {
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[test]
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

    #[test]
    #[ignore = "nondeterministic test"]
    fn random_test_bit_slicing() {
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

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn random_testing_x86() {
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
    #[cfg(target_arch = "aarch64")]
    fn random_testing_aarch64() {
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
        }
    }
}
