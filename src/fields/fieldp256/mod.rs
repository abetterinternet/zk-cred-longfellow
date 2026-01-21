use crate::{
    Codec,
    fields::{
        CodecFieldElement, ExtendContext, FieldElement, ProofFieldElement, addition_chains, extend,
        extend_precompute,
        fieldp256::ops::{
            fiat_p256_add, fiat_p256_from_bytes, fiat_p256_from_montgomery,
            fiat_p256_montgomery_domain_field_element, fiat_p256_mul,
            fiat_p256_non_montgomery_domain_field_element, fiat_p256_opp, fiat_p256_selectznz,
            fiat_p256_square, fiat_p256_sub, fiat_p256_to_bytes, fiat_p256_to_montgomery,
        },
        fieldp256_2::FieldP256_2,
    },
};
use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize, de::Error as _, ser::Error as _};
use std::{
    cmp::Ordering,
    fmt::{self, Debug},
    io::{self, Cursor, Read, Write},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};

use super::FieldId;

/// FieldP256 is the field for the NIST P-256 elliptic curve.
///
/// Field elements are serialized in little-endian form, per [Section 7.2.1 of draft-google-cfrg-libzk-00][1].
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.2.1
// The `fiat_p256_montgomery_domain_field_element` member must follow the invariant from fiat-crypto
// that its value must be "strictly less than the prime modulus (m)". We also rely on this invariant
// for comparison operations.
#[derive(Clone, Copy)]
pub struct FieldP256(fiat_p256_montgomery_domain_field_element);

impl FieldP256 {
    /// Bytes of the prime modulus, in little endian order.
    ///
    /// This is used to validate encoded field elements before passing them to fiat-crypto routines,
    /// because they have preconditions requiring that inputs are less than the modulus.
    const MODULUS_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// Converts a field element to the non-Montgomery domain form.
    fn as_residue(&self) -> fiat_p256_non_montgomery_domain_field_element {
        let mut out = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_montgomery(&mut out, &self.0);
        out
    }

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    #[inline]
    const fn from_u128_const(value: u128) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(
            &mut out,
            &fiat_p256_non_montgomery_domain_field_element([
                value as u64,
                (value >> 64) as u64,
                0,
                0,
            ]),
        );
        Self(out)
    }

    /// Decode a serialized field element.
    ///
    /// This is equivalent to the implementation of `TryFrom<&[u8; 32]>`, but it can be called from
    /// const contexts.
    pub(crate) const fn try_from_bytes_const(value: &[u8; 32]) -> Result<Self, &'static str> {
        // We have to use an open-coded for loop instead of iterator combinators due to the present
        // limitations of const functions.
        let mut i = 31;
        loop {
            if value[i] > Self::MODULUS_BYTES[i] {
                return Err("serialized FieldP256 element is not less than the modulus");
            } else if value[i] < Self::MODULUS_BYTES[i] {
                break;
            }

            if i == 0 {
                return Err("serialized FieldP256 element is not less than the modulus");
            } else {
                i -= 1;
            }
        }

        let mut temp = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_bytes(&mut temp.0, value);
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(&mut out, &temp);
        Ok(Self(out))
    }

    /// Add two field elements.
    ///
    /// This method is needed as a workaround since trait methods cannot yet be declared as const.
    pub(super) const fn add_const(&self, rhs: &Self) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }

    /// Subtract two field elements.
    ///
    /// This method is needed as a workaround since trait methods cannot yet be declared as const.
    pub(super) const fn sub_const(&self, rhs: &Self) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }

    /// Multiply two field elements.
    ///
    /// This method is needed as a workaround since trait methods cannot yet be declared as const.
    pub(super) const fn mul_const(&self, rhs: &Self) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_mul(&mut out, &self.0, &rhs.0);
        Self(out)
    }

    /// Square a field element.
    ///
    /// This method is needed as a workaround since trait methods cannot yet be declared as const.
    pub(super) const fn square_const(&self) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_square(&mut out, &self.0);
        Self(out)
    }

    /// Computes the modular square root of an element.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Since p % 4 is 3, we can compute modular square roots with a single exponentiation.
        // This algorithm is taken from the implementation of the `ff::PrimeField` derive macro.
        //
        // To find a modular square root, we calculate a candidate square root by exponentiating
        // to the power (p + 1) / 4.
        //
        //     (p + 1) / 4 = 0x3fffffffc0000000400000000000000000000000400000000000000000000000
        //
        // We then perform a trial squaring to determine if the requested square root exists or not.
        //
        // The exponentiation and trial squaring will produce the following result.
        //
        //     x ^ ((p + 1) / 4) ^ 2 mod p
        //     x ^ ((p + 1) / 2) mod p
        //     x * x ^ ((p - 1) / 2) mod p
        //
        // The value of x ^ ((p - 1) / 2) depends on the multiplicative order of x. The order of the
        // multiplicative group, p - 1, has a single factor of two, thus there is a subgroup of
        // order (p - 1) / 2 in the multiplicative group. If x is in that subgroup, then
        // x ^ ((p - 1) / 2) mod p = 1, and we will get back x after the exponentiation and trial
        // squaring. If x is not in that subgroup, then (p - 1) / 2 does not divide the order of
        // x, and we will get back some other element, also outside the subgroup, for
        // x ^ ((p - 1) / 2) mod p. Then, the result of the trial squaring will not be equal to x.

        let candidate = addition_chains::p256sqrt::exp(*self);

        CtOption::new(candidate, candidate.square().ct_eq(self))
    }
}

impl FieldElement for FieldP256 {
    const ZERO: Self = Self(fiat_p256_montgomery_domain_field_element([0; 4]));
    const ONE: Self = Self::from_u128_const(1);

    fn from_u128(value: u128) -> Self {
        Self::from_u128_const(value)
    }

    fn square(&self) -> Self {
        self.square_const()
    }

    fn mul_inv(&self) -> Self {
        // The multiplicative group of any finite field is a group with order one less than the field
        // order. Let n = |F*| = |F| - 1.
        //
        // Every element of the group has an order that divides the group's order, by Lagrange's
        // theorem. That is, |g| | n. Thus, we can write |g| * a = n, for some integer a.
        //
        // Let h = g ^ (n - 1). We can rewrite this as follows.
        //
        // h = g ^ (|g| * a - 1)
        // h = g ^ (|g| * (a - 1) + |g| - 1)
        // h = g ^ (|g| * (a - 1)) * g ^ (|g| - 1)
        // h = (g ^ |g|) ^ (a - 1) * g ^ (|g| - 1)
        // h = e ^ (a - 1) * g ^ (|g| - 1)
        // h = g ^ (|g| - 1)
        //
        // This element h is the inverse of g, because h * g = g ^ (|g| - 1) * g = g ^ |g| = e.
        //
        // Therefore, we can compute inverses by exponentiating elements, g ^ -1 = g ^ (|F| - 2).
        // We do so with an optimized addition chain exponentiation routine.
        addition_chains::p256m2::exp(*self)
    }
}

impl CodecFieldElement for FieldP256 {
    const NUM_BITS: usize = 256;

    const FIELD_ID: super::FieldId = FieldId::P256;

    fn as_byte_array(&self) -> Result<impl AsRef<[u8]>, anyhow::Error> {
        let mut buf = [0u8; Self::NUM_BITS / 8];
        self.encode(&mut &mut buf[..])?;

        Ok(buf)
    }
}

impl Serialize for FieldP256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(
            self.as_byte_array().map_err(S::Error::custom)?,
        ))
    }
}

impl<'de> Deserialize<'de> for FieldP256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|string| {
            Self::decode(&mut Cursor::new(
                &hex::decode(string).map_err(D::Error::custom)?,
            ))
            .map_err(D::Error::custom)
        })
    }
}

impl ProofFieldElement for FieldP256 {
    const SUMCHECK_P2: Self = Self::from_u128_const(2);

    const SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)(2) \
        //   .inverse().to_bytes(byteorder='little')
        //
        // Panic safety: this constant is a valid field element.
        let bytes =
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x80\x00\x00\x00\x80\xff\xff\xff\x7f";
        match Self::try_from_bytes_const(bytes) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        }
    };

    const ONE_MINUS_SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)(1 - 2) \
        //   .inverse().to_bytes(byteorder='little')
        //
        // Panic safety: this constant is a valid field element.
        let bytes =
            b"\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff";
        match Self::try_from_bytes_const(bytes) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        }
    };

    const SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)(2^2 - 2) \
        //   .inverse().to_bytes(byteorder='little')
        //
        // Panic safety: this constant is a valid field element.
        let bytes =
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x80\x00\x00\x00\x80\xff\xff\xff\x7f";
        match Self::try_from_bytes_const(bytes) {
            Ok(value) => value,
            Err(_) => panic!("could not convert precomputed constant to field element"),
        }
    };

    type ExtendContext = ExtendContext<FieldP256_2>;

    fn extend_precompute(nodes_len: usize, evaluations: usize) -> Self::ExtendContext {
        extend_precompute(nodes_len, evaluations)
    }

    fn extend(nodes: &[Self], context: &Self::ExtendContext) -> Vec<Self> {
        let projected = nodes
            .iter()
            .map(|elem| FieldP256_2::new(*elem, Self::ZERO))
            .collect::<Vec<_>>();
        let extended = extend::<FieldP256_2>(&projected, context);
        extended
            .into_iter()
            .map(|elem| {
                // If this is implemented correctly, interpolating and evaluating with evaluations and
                // evaluation points all in a subfield (FieldP256) should produce new evaluations in the
                // same subfield.
                debug_assert_eq!(elem.0.imag(), &Self::ZERO);
                *elem.0.real()
            })
            .collect()
    }
}

impl Debug for FieldP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let residue = self.as_residue();
        write!(
            f,
            "FieldP256(0x{:016x}{:016x}{:016x}{:016x})",
            residue.0[3], residue.0[2], residue.0[1], residue.0[0]
        )
    }
}

impl Default for FieldP256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for FieldP256 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Since we ensure that the `fiat_p256_montgomery_domain_field_element` value is always less
        // than the prime modulus, and the Montgomery domain map is an isomorphism, we can directly
        // compare Montgomery domain values for equality without converting.
        self.0.0.ct_eq(&other.0.0)
    }
}

impl PartialEq for FieldP256 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldP256 {}

impl From<u64> for FieldP256 {
    fn from(value: u64) -> Self {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(
            &mut out,
            &fiat_p256_non_montgomery_domain_field_element([value, 0, 0, 0]),
        );
        Self(out)
    }
}

impl TryFrom<&[u8; 32]> for FieldP256 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        if value.iter().rev().cmp(Self::MODULUS_BYTES.iter().rev()) != Ordering::Less {
            return Err(anyhow!(
                "serialized FieldP256 element is not less than the modulus"
            ));
        }
        let mut temp = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_bytes(&mut temp.0, value);
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_to_montgomery(&mut out, &temp);
        Ok(Self(out))
    }
}

impl TryFrom<&[u8]> for FieldP256 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference = <&[u8; 32]>::try_from(value).context("failed to decode FieldP256")?;
        Self::try_from(array_reference)
    }
}

impl Codec for FieldP256 {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 32];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read FieldP256 element")?;
        Self::try_from(&buffer)
    }

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        let mut non_montgomery = fiat_p256_non_montgomery_domain_field_element([0; 4]);
        fiat_p256_from_montgomery(&mut non_montgomery, &self.0);
        let mut out = [0u8; 32];
        fiat_p256_to_bytes(&mut out, &non_montgomery.0);
        bytes.write_all(&out)?;
        Ok(())
    }
}

impl Add<&Self> for FieldP256 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.add_const(rhs)
    }
}

impl Add for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign for FieldP256 {
    fn add_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_add(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Sub<&Self> for FieldP256 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.sub_const(rhs)
    }
}

impl Sub for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign for FieldP256 {
    fn sub_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_sub(&mut self.0, &copy.0, &rhs.0);
    }
}

impl Mul<&Self> for FieldP256 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.mul_const(rhs)
    }
}

impl Mul<Self> for FieldP256 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign for FieldP256 {
    fn mul_assign(&mut self, rhs: Self) {
        let copy = *self;
        fiat_p256_mul(&mut self.0, &copy.0, &rhs.0)
    }
}

impl Neg for FieldP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = fiat_p256_montgomery_domain_field_element([0; 4]);
        fiat_p256_opp(&mut out, &self.0);
        Self(out)
    }
}

impl ConditionallySelectable for FieldP256 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        let mut output = [0; 4];
        fiat_p256_selectznz(&mut output, choice.unwrap_u8(), &(a.0).0, &(b.0).0);
        Self(fiat_p256_montgomery_domain_field_element(output))
    }
}

#[allow(unused, clippy::unnecessary_cast, clippy::needless_lifetimes)]
#[rustfmt::skip]
mod ops;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        Codec,
        fields::{FieldElement, fieldp256::FieldP256},
    };

    #[wasm_bindgen_test(unsupported = test)]
    fn modulus_bytes_correct() {
        let mut p_minus_one_bytes = FieldP256::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        let p_minus_one = FieldP256::decode(&mut Cursor::new(&p_minus_one_bytes)).unwrap();
        assert_eq!(p_minus_one + FieldP256::ONE, FieldP256::ZERO);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn try_from_bytes_const_equivalent() {
        let mut p_minus_one_bytes = FieldP256::MODULUS_BYTES;
        p_minus_one_bytes[0] -= 1;
        for bytes in [
            [0; 32],
            p_minus_one_bytes,
            FieldP256::MODULUS_BYTES,
            [0xff; 32],
        ] {
            let res1 = FieldP256::try_from_bytes_const(&bytes).map_err(|e| e.to_owned());
            let res2 = FieldP256::try_from(&bytes).map_err(|e| e.to_string());
            assert_eq!(res1, res2);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_sqrt() {
        // The expected values for these test cases were produced in Sage. Note that some
        // guess-and-check was required to pick the square root with the correct sign to match what
        // the exponentiation routine returns. The byte strings were produced with one of the
        // following snippets.
        //
        // GF(p)(x).sqrt().to_bytes(byteorder='little')
        //
        // (-GF(p)(x).sqrt()).to_bytes(byteorder='little')
        assert_eq!(FieldP256::ZERO.sqrt().unwrap(), FieldP256::ZERO);
        assert_eq!(FieldP256::ONE.sqrt().unwrap(), FieldP256::ONE);
        assert_eq!(
            FieldP256::from_u128(2).sqrt().unwrap(),
            FieldP256::try_from(
                b"\"]\xaa\xd3\xf2\x87\x07\xea\x97[\x86\xd3\x94N/@\xcf(=T[4\xbf\xacwU\xdd\x8c\xfe\xbd\x8b\xaf"
            )
            .unwrap()
        );
        assert_eq!(FieldP256::from_u128(3).sqrt().is_none().unwrap_u8(), 1);
        assert_eq!(
            FieldP256::from_u128(4).sqrt().unwrap(),
            FieldP256::from_u128(2)
        );
        assert_eq!(
            FieldP256::from_u128(5).sqrt().unwrap(),
            FieldP256::try_from(
                b"<\xad\x15\x1b\xc2\xda\xf9\xd2>(\xe0F\xe0\xd3\x96\x9c\"\xcb\xff\xaei\x90\x18ck\x17@\xaf\xa4\xc5^\x08"
            )
            .unwrap()
        );
        assert_eq!(FieldP256::from_u128(6).sqrt().is_none().unwrap_u8(), 1);
        assert_eq!(
            FieldP256::from_u128(7).sqrt().unwrap(),
            FieldP256::try_from(
                b"\x0c \x88\x1d\xa0\xa3[\x97\xa7\"1O\xb2\xee\xbd\x15\xe4\xf4\x02\x19\x00\x93q\xf6\xc6Q&u\x06\xda\xf3\xe6"
            )
            .unwrap()
        );
    }
}
