use crate::{
    Codec, Sha256Digest,
    fields::{
        FieldElement, addition_chains,
        fieldp256_scalar::ops::{
            fiat_p256_scalar_add, fiat_p256_scalar_from_bytes, fiat_p256_scalar_from_montgomery,
            fiat_p256_scalar_montgomery_domain_field_element, fiat_p256_scalar_mul,
            fiat_p256_scalar_non_montgomery_domain_field_element, fiat_p256_scalar_opp,
            fiat_p256_scalar_selectznz, fiat_p256_scalar_square, fiat_p256_scalar_sub,
            fiat_p256_scalar_to_bytes, fiat_p256_scalar_to_montgomery,
        },
    },
};
use anyhow::{Context, anyhow};
use std::{
    cmp::Ordering,
    fmt::{self, Debug},
    io::{self, Read},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The scalar field for the NIST P-256 elliptic curve.
// The `fiat_p256_scalar_montgomery_domain_field_element` member must follow the invariant from
// fiat-crypto that its value must be "strictly less than the prime modulus (m)". We also rely on
// this invariant for comparison operations.
#[derive(Clone, Copy)]
pub struct FieldP256Scalar(fiat_p256_scalar_montgomery_domain_field_element);

impl FieldP256Scalar {
    /// Bytes of the prime modulus, in little endian order.
    ///
    /// This is used to validate encoded field elements before passing them to fiat-crypto routines,
    /// because they have preconditions requiring that inputs are less than the modulus.
    const MODULUS_BYTES: [u8; 32] = [
        0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3, 0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6,
        0xbc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// Converts a field element to the non-Montgomery domain form.
    fn as_residue(&self) -> fiat_p256_scalar_non_montgomery_domain_field_element {
        let mut out = fiat_p256_scalar_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_from_montgomery(&mut out, &self.0);
        out
    }

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    #[inline]
    const fn from_u128_const(value: u128) -> Self {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_to_montgomery(
            &mut out,
            &fiat_p256_scalar_non_montgomery_domain_field_element([
                value as u64,
                (value >> 64) as u64,
                0,
                0,
            ]),
        );
        Self(out)
    }

    /// Converts this field element to a representative of its residue class, and returns it as four
    /// `u64` limbs, with the least significant limb first.
    pub fn to_non_montgomery(&self) -> [u64; 4] {
        let mut non_montgomery = fiat_p256_scalar_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_from_montgomery(&mut non_montgomery, &self.0);
        non_montgomery.0
    }

    /// Converts a SHA-256 digest to a scalar element for use in ECDSA.
    ///
    /// This performs a conditional subtraction of the modulus before converting to a field element.
    ///
    /// The `hash` argument is treated as a big-endian encoding of an integer, per SEC 1 section
    /// 2.3.8.
    pub fn from_hash(hash: Sha256Digest) -> Self {
        const MODULUS_HIGH: u128 = 0xffffffff00000000ffffffffffffffff;
        const MODULUS_LOW: u128 = 0xbce6faada7179e84f3b9cac2fc632551;

        // Interpret the hash as a big-endian 256-bit number.
        //
        // Unwrap safety: these indices are statically in-range.
        let high = u128::from_be_bytes(hash.0[..16].try_into().unwrap());
        let low = u128::from_be_bytes(hash.0[16..].try_into().unwrap());

        // Perform a conditional subtraction.
        let (result_low, borrow) = low.overflowing_sub(MODULUS_LOW);
        let (result_high, overflow) = high.borrowing_sub(MODULUS_HIGH, borrow);

        let overflow = Choice::from(overflow as u8);
        let [select_high, select_low] = ConditionallySelectable::conditional_select(
            &[result_high, result_low],
            &[high, low],
            overflow,
        );

        // Encode the 256-bit integer in little-endian form, in order to match fiat-crytpo's
        // preconditions, then convert it to a field element.
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&select_low.to_le_bytes());
        buf[16..].copy_from_slice(&select_high.to_le_bytes());
        // Unwrap safety: we just performed a conditional subtraction of the modulus, and we don't
        // need to do more than one subtraction, since the modulus is so close to 2^256 - 1.
        Self::try_from(&buf).unwrap()
    }
}

impl FieldElement for FieldP256Scalar {
    const ZERO: Self = Self(fiat_p256_scalar_montgomery_domain_field_element([0; 4]));
    const ONE: Self = Self::from_u128_const(1);

    fn from_u128(value: u128) -> Self {
        Self::from_u128_const(value)
    }

    fn square(&self) -> Self {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_square(&mut out, &self.0);
        Self(out)
    }

    fn mul_inv(&self) -> Self {
        // Compute the multiplicative inverse by exponentiating to the power (p - 2). See
        // FieldP256::mul_inv() for an explanation of this technique.
        addition_chains::p256_scalar_m2::exp(*self)
    }
}

impl Debug for FieldP256Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let residue = self.as_residue();
        write!(
            f,
            "FieldP256Scalar(0x{:016x}{:016x}{:016x}{:016x})",
            residue.0[3], residue.0[2], residue.0[1], residue.0[0]
        )
    }
}

impl Default for FieldP256Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for FieldP256Scalar {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Since we ensure that the `fiat_p256_scalar_montgomery_domain_field_element` value is
        // always less than the prime modulus, and the Montgomery domain map is an isomorphism, we
        // can directly compare Montgomery domain values for equality without converting.
        self.0.0.ct_eq(&other.0.0)
    }
}

impl PartialEq for FieldP256Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldP256Scalar {}

impl From<u64> for FieldP256Scalar {
    fn from(value: u64) -> Self {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_to_montgomery(
            &mut out,
            &fiat_p256_scalar_non_montgomery_domain_field_element([value, 0, 0, 0]),
        );
        Self(out)
    }
}

impl TryFrom<&[u8; 32]> for FieldP256Scalar {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        if value.iter().rev().cmp(Self::MODULUS_BYTES.iter().rev()) != Ordering::Less {
            return Err(anyhow!(
                "serialized FieldP256Scalar element is not less than the modulus"
            ));
        }
        let mut temp = fiat_p256_scalar_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_from_bytes(&mut temp.0, value);
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_to_montgomery(&mut out, &temp);
        Ok(Self(out))
    }
}

impl TryFrom<&[u8]> for FieldP256Scalar {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference =
            <&[u8; 32]>::try_from(value).context("failed to decode FieldP256Scalar")?;
        Self::try_from(array_reference)
    }
}

impl Codec for FieldP256Scalar {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 32];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read FieldP256Scalar element")?;
        Self::try_from(&buffer)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let mut non_montgomery = fiat_p256_scalar_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_from_montgomery(&mut non_montgomery, &self.0);
        let mut out = [0u8; 32];
        fiat_p256_scalar_to_bytes(&mut out, &non_montgomery.0);
        bytes.extend_from_slice(&out);
        Ok(())
    }
}

impl Add<&Self> for FieldP256Scalar {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Add<Self> for FieldP256Scalar {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign for FieldP256Scalar {
    fn add_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_scalar_add(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Sub<&Self> for FieldP256Scalar {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Sub<Self> for FieldP256Scalar {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign for FieldP256Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_scalar_sub(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Mul<&Self> for FieldP256Scalar {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_mul(&mut out, &self.0, &rhs.0);
        Self(out)
    }
}

impl Mul<Self> for FieldP256Scalar {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign for FieldP256Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_scalar_mul(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Neg for FieldP256Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = fiat_p256_scalar_montgomery_domain_field_element([0; 4]);
        fiat_p256_scalar_opp(&mut out, &self.0);
        Self(out)
    }
}

impl ConditionallySelectable for FieldP256Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        let mut output = [0; 4];
        fiat_p256_scalar_selectznz(&mut output, choice.unwrap_u8(), &a.0.0, &b.0.0);
        Self(fiat_p256_scalar_montgomery_domain_field_element(output))
    }
}

#[allow(unused, clippy::unnecessary_cast, clippy::needless_lifetimes)]
#[rustfmt::skip]
mod ops;

#[cfg(test)]
mod tests {
    use crate::{
        Sha256Digest,
        fields::{FieldElement, fieldp256_scalar::FieldP256Scalar},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn modulus_bytes_correct() {
        let mut p_minus_one_bytes = FieldP256Scalar::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        let p_minus_one = FieldP256Scalar::try_from(&p_minus_one_bytes).unwrap();
        assert_eq!(p_minus_one + FieldP256Scalar::ONE, FieldP256Scalar::ZERO);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn from_hash() {
        assert_eq!(
            FieldP256Scalar::from_hash(Sha256Digest([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ])),
            FieldP256Scalar::ONE
        );
        assert_eq!(
            FieldP256Scalar::from_hash(Sha256Digest([
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ])),
            FieldP256Scalar::from_u128(1 << 127).square() * FieldP256Scalar::from_u128(2)
        );
        assert_eq!(
            FieldP256Scalar::from_hash(Sha256Digest([0xff; 32])),
            FieldP256Scalar::try_from(&[
                0xae, 0xda, 0x9c, 0x03, 0x3d, 0x35, 0x46, 0x0c, 0x7b, 0x61, 0xe8, 0x58, 0x52, 0x05,
                0x19, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00
            ])
            .unwrap()
        );
    }
}
