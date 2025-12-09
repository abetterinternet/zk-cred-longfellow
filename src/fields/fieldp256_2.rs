use std::{
    fmt::{self, Debug},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::ConstantTimeEq;

use crate::fields::{FieldElement, NttFieldElement, QuadraticExtension, fieldp256::FieldP256};

/// The quadratic extension of the P-256 base field.
///
/// This is defined as F_p256\[x\]/(x^2 + 1).
#[derive(Clone, Copy, Default)]
pub struct FieldP256_2(pub(super) QuadraticExtension<FieldP256>);

impl FieldElement for FieldP256_2 {
    const ZERO: Self = Self(QuadraticExtension::<FieldP256>::ZERO);

    const ONE: Self = Self(QuadraticExtension::<FieldP256>::ONE);

    const SUMCHECK_P2: Self = Self(QuadraticExtension::<FieldP256>::SUMCHECK_P2);

    fn from_u128(value: u128) -> Self {
        Self(QuadraticExtension::<FieldP256>::from_u128(value))
    }

    fn square(&self) -> Self {
        Self(QuadraticExtension::square(&self.0))
    }
}

impl NttFieldElement for FieldP256_2 {
    const ROOT_OF_UNITY: Self = {
        // Computed in SageMath:
        //
        // gen = Fp256_2.multiplicative_generator() ^ ((Fp256_2.order() - 1) / 2^97)
        // [coeff.to_bytes(byteorder='little') for coeff in gen.polynomial().coefficients()]
        //
        // Panic safety: these constants are valid base field elements.
        let bytes_real =
            b"`}\xd7iv\x10\x1f\xefV\xb8\x14\xa8p!Q9s4iR1\xde -\xd3\x80\xa6\x00\xe8\xe1U<";
        let real = match FieldP256::try_from_bytes_const(bytes_real) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        let bytes_imag = b"5\xa0\x95\xc4\x8a?\x08\x82\xae\xc4\x15\xf5v\xfb\xef\xdat\xbcG#I\x10\xb7\xb2\x8dH\xdcB\x88\x8cx\xdf";
        let imag = match FieldP256::try_from_bytes_const(bytes_imag) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        Self(QuadraticExtension::new(real, imag))
    };

    const LOG2_ROOT_ORDER: usize = 97;

    const HALF: Self = {
        // Computed in SageMath:
        //
        // half = Fp256_2(2).inverse()
        // [coeff.to_bytes(byteorder='little') for coeff in half.polynomial().coefficients()]
        //
        // Panic safety: this constant is a valid field element.
        let bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\xff\xff\xff\x7f";
        let base = match FieldP256::try_from_bytes_const(bytes) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };
        Self(QuadraticExtension::new(base, FieldP256::ZERO))
    };
}

impl Debug for FieldP256_2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ConstantTimeEq for FieldP256_2 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for FieldP256_2 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FieldP256_2 {}

impl From<u64> for FieldP256_2 {
    fn from(value: u64) -> Self {
        Self(QuadraticExtension::from(value))
    }
}

impl Add for FieldP256_2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl AddAssign for FieldP256_2 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for FieldP256_2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - &rhs.0)
    }
}

impl SubAssign for FieldP256_2 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Mul for FieldP256_2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&Self> for FieldP256_2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0 * &rhs.0)
    }
}

impl MulAssign for FieldP256_2 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl Neg for FieldP256_2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}
