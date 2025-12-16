use std::{
    fmt::{self, Debug},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::fields::{FieldElement, NttFieldElement, QuadraticExtension, fieldp256::FieldP256};

/// The quadratic extension of the P-256 base field.
///
/// This is defined as F_p256\[x\]/(x^2 + 1).
#[derive(Clone, Copy, Default)]
pub struct FieldP256_2(pub(super) QuadraticExtension<FieldP256>);

impl FieldP256_2 {
    /// Construct an element of the quadratic extension field from two base field elements.
    pub fn new(real: FieldP256, imag: FieldP256) -> Self {
        Self(QuadraticExtension::new(real, imag))
    }

    /// Square a field element.
    ///
    /// This method is needed as a workaround since trait methods cannot yet be declared as const.
    const fn square_const(&self) -> Self {
        let cross = self.0.real().mul_const(self.0.imag());
        Self(QuadraticExtension::new(
            self.0
                .real()
                .square_const()
                .sub_const(&self.0.imag().square_const()),
            cross.add_const(&cross),
        ))
    }
}

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

    fn mul_inv(&self) -> Self {
        Self(QuadraticExtension::mul_inv(&self.0))
    }
}

impl NttFieldElement for FieldP256_2 {
    const ROOTS_OF_UNITY: [Self; 32] = {
        // Computed in SageMath:
        //
        // gen = Fp256_2.multiplicative_generator() ^ ((Fp256_2.order() - 1) / 2^31)
        // [coeff.to_bytes(byteorder='little') for coeff in gen.polynomial().coefficients()]
        //
        // Panic safety: these constants are valid base field elements.
        let bytes_real = b"\xb7y\x06\x7ff\xb3\x18\xaa\xe0\xd2\xd7\xc2[\xb6r\xf6-\xaf\xd5\xd6\xbf\
            \xb1\xa8@\xfc}+P\xbf\x0ev\n";
        let real = match FieldP256::try_from_bytes_const(bytes_real) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        let bytes_imag = b"\xb4\xf9\x9fI\xf06\xab\xfb\xc0\xb3\xae\x0b\xb7;\xd5\x13\x13\xdf\x05_\
            \xca.\x93\xe2E\x8e\xab\xa8J\x86\x8c\xaa";
        let imag = match FieldP256::try_from_bytes_const(bytes_imag) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        let start = Self(QuadraticExtension::new(real, imag));

        let mut output = [Self::ZERO; 32];
        let mut temp = start;
        let mut i = output.len() - 1;
        loop {
            output[i] = temp;
            if i == 0 {
                break;
            }
            temp = temp.square_const();
            i -= 1;
        }

        output
    };

    const ROOTS_OF_UNITY_INVERSES: [Self; 32] = {
        // Computed in SageMath:
        //
        // gen = Fp256_2.multiplicative_generator() ^ ((Fp256_2.order() - 1) / 2^31)
        // [coeff.to_bytes(byteorder='little') for coeff in gen.inverse().polynomial().coefficients()]
        //
        // Panic safety: these constants are valid base field elements.
        let bytes_real = b"\xb7y\x06\x7ff\xb3\x18\xaa\xe0\xd2\xd7\xc2[\xb6r\xf6-\xaf\xd5\xd6\xbf\
            \xb1\xa8@\xfc}+P\xbf\x0ev\n";
        let real = match FieldP256::try_from_bytes_const(bytes_real) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        let bytes_imag =
            b"K\x06`\xb6\x0f\xc9T\x04?LQ\xf4I\xc4*\xec\xec \xfa\xa05\xd1l\x1d\xbbqTW\xb4ysU";
        let imag = match FieldP256::try_from_bytes_const(bytes_imag) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        };

        let start = Self(QuadraticExtension::new(real, imag));

        let mut output = [Self::ZERO; 32];
        let mut temp = start;
        let mut i = output.len() - 1;
        loop {
            output[i] = temp;
            if i == 0 {
                break;
            }
            temp = temp.square_const();
            i -= 1;
        }

        output
    };

    const HALF: Self = {
        // Computed in SageMath:
        //
        // half = Fp256_2(2).inverse()
        // [coeff.to_bytes(byteorder='little') for coeff in half.polynomial().coefficients()]
        //
        // Panic safety: this constant is a valid field element.
        let bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\xff\xff\xff\x7f";
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

impl ConditionallySelectable for FieldP256_2 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Self(QuadraticExtension::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::fields::{
        CodecFieldElement, FieldElement, fieldp256::FieldP256, fieldp256_2::FieldP256_2,
    };

    #[wasm_bindgen_test(unsupported = test)]
    fn test_square_const() {
        for _ in 0..100 {
            let x = FieldP256_2::new(FieldP256::sample(), FieldP256::sample());
            assert_eq!(x.square_const(), x.square());
        }
    }
}
