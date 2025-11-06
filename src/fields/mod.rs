//! Various finite field implementations.
use crate::{
    Codec,
    fields::{
        field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256, fieldp521::FieldP521,
    },
};
use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use rand::RngCore;
use std::{
    fmt::Debug,
    io::Cursor,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConstantTimeEq};

/// An element of a finite field.
pub trait FieldElement:
    Debug
    + Clone
    + Copy
    + ConstantTimeEq
    + PartialEq
    + Eq
    + Default
    + From<u64>
    + Add<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    /// The additive identity of the field.
    const ZERO: Self;
    /// The multiplicative of the field.
    const ONE: Self;
    /// The third evaluation point used by sumcheck.
    ///
    /// This will be 2 for large characteristic fields, and x for fields of characteristic two.
    const SUMCHECK_P2: Self;

    /// Project an integer into the field.
    fn from_u128(value: u128) -> Self;

    /// Test whether this element is zero.
    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Square a field element.
    fn square(&self) -> Self;
}

/// An element of a finite field with a defined serialization format.
pub trait CodecFieldElement:
    FieldElement + for<'a> TryFrom<&'a [u8], Error = anyhow::Error> + Codec
{
    /// Number of bits needed to represent a field element.
    const NUM_BITS: u32;

    /// Number of bytes needed to represent a field element.
    fn num_bytes() -> usize {
        (Self::NUM_BITS as usize).div_ceil(8)
    }

    /// Generate a field element by rejection sampling.
    fn sample() -> Self {
        Self::sample_from_source(|num_bytes| {
            let mut bytes = vec![0; num_bytes];
            rand::rng().fill_bytes(&mut bytes);

            bytes
        })
    }

    /// Generate a field element by rejection sampling, sampling random bytes from the provided
    /// source.
    fn sample_from_source<F>(source: F) -> Self
    where
        F: FnMut(usize) -> Vec<u8>,
    {
        Self::sample_counting_rejections(source).0
    }

    /// Generate a field element by rejection sampling and return how many rejections were observed.
    fn sample_counting_rejections<F>(mut source: F) -> (Self, usize)
    where
        F: FnMut(usize) -> Vec<u8>,
    {
        let mut rejections = 0;
        let field_element = loop {
            // Some fields like P521 have a bit count that isn't congruent to 8. We sample
            // enough excess bits to get whole bytes and then mask off the excess, which can be
            // at most 7 bits.
            // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.3
            let num_sampled_bytes = Self::num_bytes();
            let mut sampled_bytes = source(num_sampled_bytes);
            let excess_bits = num_sampled_bytes * 8 - Self::NUM_BITS as usize;
            if excess_bits != 0 {
                sampled_bytes[num_sampled_bytes - 1] &= (1 << (8 - excess_bits)) - 1;
            }
            // FE::try_from rejects if the value is still too big after masking.
            // TODO: FE::try_from could fail for reasons besides the generated value being too big
            if let Ok(fe) = Self::try_from(&sampled_bytes) {
                break fe;
            }
            rejections += 1;
        };

        (field_element, rejections)
    }
}

/// Elements of a field in which we can interpolate polynomials up to degree two. Our nodes are
/// `x_0 = 0`, `x_1 = 1`, and `x_2 = SUMCHECK_P2` in the field. Since we only have three nodes, we
/// can work out each Lagrange basis polynomial by hand. We precompute the denominators to avoid
/// implementing division.
///
/// For details see [Section 6.6][1] and [2].
///
/// # Bugs
///
/// The methods `sumcheck_p2_mul_inv`, `one_minus_sumcheck_p2_mul_inv`,
/// `sumcheck_p2_squared_minus_sumcheck_p2_mul_inv` should be constants ([3]).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
/// [2]: https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
/// [3]: https://github.com/abetterinternet/zk-cred-longfellow/issues/40
pub trait LagrangePolynomialFieldElement: FieldElement {
    /// Evaluate the 0th Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_0(x: Self) -> Self {
        // (x - x_1) * (x - x_2)
        (x - Self::ONE) * (x - Self::SUMCHECK_P2)
            // (x_0 - x_1) * (x_0 - x_2) = (0 - 1) * (0 - SUMCHECK_P2) = SUMCHECK_P2
            * Self::sumcheck_p2_mul_inv()
    }

    /// Evaluate the 1st Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_1(x: Self) -> Self {
        // (x - x_0) * (x - x_2)
        (x - Self::ZERO) * (x - Self::SUMCHECK_P2)
            // (x_1 - x_0) * (x_1 - x_2) = (1 - 0) * (1 - SUMCHECK_P2) = 1 - SUMCHECK_P2
            * Self::one_minus_sumcheck_p2_mul_inv()
    }

    /// Evaluate the 2nd Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_2(x: Self) -> Self {
        // (x - x_0) * (x - x_1)
        (x - Self::ZERO) * (x - Self::ONE)
            // (x_2 - x_0) * (x_2 - x_1) = (SUMCHECK_P2 - 0) * (SUMCHECK_P2 - 1)
            //   = SUMCHECK_P2^2 - SUMCHECK_P2
            * Self::sumcheck_p2_squared_minus_sumcheck_p2_mul_inv()
    }

    /// The multiplicative inverse of `SUMCHECK_P2`. Denominator of the 0th Lagrange basis
    /// polynomial.
    // TODO: This could probably be a constant.
    fn sumcheck_p2_mul_inv() -> Self;

    /// The multiplicative inverse of `1 - SUMCHECK_P2`. Denominator of the 1st Lagrange basis
    /// polynomial.
    // TODO: This could probably be a constant.
    fn one_minus_sumcheck_p2_mul_inv() -> Self;

    /// The multiplicative inverse of `SUMCHECK_P2^2 - SUMCHECK_P2`. Denominator of the 2nd Lagrange
    /// basis polynomial.
    // TODO: This could probably be a constant.
    fn sumcheck_p2_squared_minus_sumcheck_p2_mul_inv() -> Self;

    /// The multiplicative inverse of this value.
    fn mul_inv(&self) -> Self;

    /// Raise a field element to some power.
    fn pow(&self, mut exponent: BigUint) -> Self {
        // Modular exponentiation from Schneier's _Applied Cryptography_, via Wikipedia
        // https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
        let mut out = Self::ONE;
        let mut base = *self;

        while exponent > BigUint::ZERO {
            if exponent.is_odd() {
                out *= base;
            }
            exponent >>= 1;
            base = base.square();
        }

        out
    }
}

/// Compute the multiplicative inverse of base, using the provided order of the field.
fn mul_inv_field_order<FE: LagrangePolynomialFieldElement>(base: &FE, field_order: BigUint) -> FE {
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
    base.pow(field_order - (BigUint::one() + BigUint::one()))
}

/// Field identifier. According to the draft specification, the encoding is of variable length ([1])
/// but in the Longfellow implementation ([2]), they're always 3 bytes long.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-00#section-7.2
/// [2]: https://github.com/google/longfellow-zk/blob/902a955fbb22323123aac5b69bdf3442e6ea6f80/lib/proto/circuit.h#L309
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FieldId {
    /// The absence of a field, presumably if some circuit or proof has no subfield. This isn't
    /// described in the specification (FieldID values start at 1) but is present in the Longfellow
    /// implementation ([1]).
    ///
    /// [1]: https://github.com/google/longfellow-zk/blob/87474f308020535e57a778a82394a14106f8be5b/lib/proto/circuit.h#L55
    None = 0,
    /// NIST P256.
    P256 = 1,
    /// NIST P384.
    P384 = 2,
    /// NIST P521.
    P521 = 3,
    /// GF(2^128).
    GF2_128 = 4,
    /// GF(2^16).
    GF2_16 = 5,
    /// [`FieldP128`]
    FP128 = 6,
    // FieldID values for the following fields are not supported:
    // * Prime fields with modulus 2^64 - 59 or 2^64 - 2^32 + 1.
    // * Quadratic extension field F_{2^64 - 59}^2.
    // * secp256k1 base field.
    // * Variable-length FieldID values specifying custom prime fields or
    //   quadratic extension fields.
}

impl TryFrom<u8> for FieldId {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            3 => Ok(Self::P521),
            4 => Ok(Self::GF2_128),
            5 => Ok(Self::GF2_16),
            6 => Ok(Self::FP128),
            _ => Err(anyhow!("unknown field ID {value}")),
        }
    }
}

impl Codec for FieldId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let value = bytes
            .read_u24::<LittleEndian>()
            .context("failed to read u24")?;
        let as_u8: u8 = value.try_into().context("decoded value too big for u8")?;
        Self::try_from(as_u8)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes
            .write_u24::<LittleEndian>(*self as u32)
            .context("failed to write u24")
    }
}

impl FieldId {
    /// Returns the number of bytes occupied by the encoding of a field element of this ID.
    pub fn encoded_length(&self) -> usize {
        match self {
            FieldId::None => 0,
            FieldId::P256 => FieldP256::num_bytes(),
            FieldId::P384 => 48,
            FieldId::P521 => FieldP521::num_bytes(),
            FieldId::GF2_128 => Field2_128::num_bytes(),
            FieldId::GF2_16 => 2,
            FieldId::FP128 => FieldP128::num_bytes(),
        }
    }
}

/// A serialized field element. The encoded length depends on the [`FieldId`].
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SerializedFieldElement(pub Vec<u8>);

impl SerializedFieldElement {
    // Annoyingly we can't implement Codec for this: encoding or decoding a field element requires
    // knowledge of the field element in use by the circuit, which means we can't decode without
    // some context.
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        u8::encode_fixed_array(&self.0, bytes)
    }

    pub fn decode(field_id: FieldId, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(u8::decode_fixed_array(
            bytes,
            field_id.encoded_length(),
        )?))
    }
}

impl TryFrom<SerializedFieldElement> for u128 {
    type Error = anyhow::Error;

    fn try_from(value: SerializedFieldElement) -> Result<Self, Self::Error> {
        Ok(u128::from_le_bytes(value.0.try_into().map_err(|_| {
            anyhow!("byte array wrong length for u128")
        })?))
    }
}

pub mod field2_128;
pub mod fieldp128;
pub mod fieldp256;
pub mod fieldp256_2;
pub mod fieldp521;

mod quadratic_extension;
use quadratic_extension::QuadraticExtension;

#[cfg(test)]
mod tests {
    use crate::{
        Codec,
        fields::{
            CodecFieldElement, FieldElement, FieldId, LagrangePolynomialFieldElement,
            SerializedFieldElement, field2_128::Field2_128, fieldp128::FieldP128,
            fieldp256::FieldP256, fieldp256_2::FieldP256_2, fieldp521::FieldP521,
        },
    };
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use rand::RngCore;
    use std::{io::Cursor, panic::catch_unwind};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[test]
    fn codec_roundtrip_field_p128() {
        let element = SerializedFieldElement(Vec::from([
            0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
            0xfe, 0xff,
        ]));

        let mut encoded = Vec::new();
        element.encode(&mut encoded).unwrap();

        let decoded =
            SerializedFieldElement::decode(FieldId::FP128, &mut Cursor::new(&encoded)).unwrap();

        assert_eq!(element, decoded)
    }

    #[test]
    fn field_p128_from_bytes_accept() {
        FieldP128::try_from(
            &[
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ][..],
        )
        .expect("Exactly the length of a field element (16 bytes), but a legal field value.");
    }

    #[test]
    fn field_p128_from_bytes_reject() {
        for (label, invalid_element) in [
            ("Empty slice", &[][..]),
            ("Slice is too short for the field", &[0xff][..]),
            (
                "Value is too big for the field",
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ][..],
            ),
            (
                "Slice is too long for the field",
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
            ),
        ] {
            FieldP128::try_from(invalid_element).expect_err(label);
        }
    }

    #[test]
    fn codec_roundtrip_field_p256() {
        let element = SerializedFieldElement(Vec::from([
            0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
            0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff,
            0xff, 0xff, 0xfe, 0xff,
        ]));

        let mut encoded = Vec::new();
        element.encode(&mut encoded).unwrap();

        let decoded =
            SerializedFieldElement::decode(FieldId::P256, &mut Cursor::new(&encoded)).unwrap();

        assert_eq!(element, decoded)
    }

    #[test]
    fn field_p256_from_bytes_accept() {
        FieldP256::try_from(
            &[
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ][..],
        )
        .expect("Exactly the length of a field element (32 bytes), but a legal field value.");
    }

    #[test]
    fn field_p256_from_bytes_reject() {
        for (label, invalid_element) in [
            ("Empty slice", &[][..]),
            ("Slice is too short for the field", &[0xff][..]),
            (
                "Value is too big for the field",
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ][..],
            ),
            (
                "Slice is too long for the field",
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00,
                ][..],
            ),
        ] {
            FieldP256::try_from(invalid_element).expect_err(label);
        }
    }

    #[test]
    fn field_p256_roundtrip() {
        FieldP256::from_u128(111).roundtrip();
    }

    #[test]
    fn field_p128_roundtrip() {
        FieldP128::from_u128(111).roundtrip();
    }

    #[test]
    fn field_p521_roundtrip() {
        FieldP521::from_u128(111).roundtrip();
    }

    #[test]
    fn field_2_128_roundtrip() {
        Field2_128::from_u128(0xdeadbeef12345678f00faaaabbbbcccc).roundtrip();
    }

    #[allow(clippy::op_ref, clippy::eq_op)]
    fn field_element_test_large_characteristic<F: FieldElement>() {
        let three = F::from(3);
        let nine = F::from(9);
        let neg_one = -F::ONE;

        assert_eq!(F::from(0), F::ZERO);
        assert_eq!(F::from(1), F::ONE);
        assert_eq!(F::from(2), F::SUMCHECK_P2);

        assert_ne!(F::ZERO, F::ONE);
        assert_ne!(F::ONE, three);
        assert_ne!(three, nine);
        assert_ne!(nine, neg_one);

        assert_eq!(neg_one + &F::ONE, F::ZERO);
        assert_eq!(neg_one + F::ONE, F::ZERO);
        let mut temp = neg_one;
        temp += F::ONE;
        assert_eq!(temp, F::ZERO);

        assert_eq!(F::ONE + &F::ONE, F::SUMCHECK_P2);
        assert_eq!(F::ONE + F::ONE, F::SUMCHECK_P2);
        let mut temp = F::ONE;
        temp += F::ONE;
        assert_eq!(temp, F::SUMCHECK_P2);

        assert_eq!(three + &F::ZERO, three);
        assert_eq!(three + F::ZERO, three);
        let mut temp = three;
        temp += F::ZERO;
        assert_eq!(temp, three);

        assert_eq!(three * &three, nine);
        assert_eq!(three * three, nine);
        assert_eq!(three * &F::ONE, three);
        assert_eq!(three * F::ONE, three);
        assert_eq!(three * &F::ZERO, F::ZERO);
        assert_eq!(three * F::ZERO, F::ZERO);

        let mut temp = F::ONE;
        temp *= F::ONE;
        assert_eq!(temp, F::ONE);
        temp *= three;
        assert_eq!(temp, three);
        temp *= three;
        assert_eq!(temp, three + three + three);

        assert_eq!(-neg_one, F::ONE);

        assert_eq!(F::ONE - F::ONE, F::ZERO);
        assert_eq!(F::ZERO - F::ONE, neg_one);
        assert_eq!(three - F::ZERO, three);
        let mut temp = three;
        temp -= F::ONE;
        assert_eq!(temp, F::SUMCHECK_P2);

        for x in [F::ZERO, F::ONE, three, nine, neg_one] {
            assert_eq!(x.square(), x * x);
        }
        let mut value = F::from(u64::MAX);
        for _ in 0..20 {
            assert_eq!(value.square(), value * value);
            value *= value;
        }
    }

    fn field_element_test_codec<F: CodecFieldElement>(decode_is_fallible: bool) {
        let three = F::from(3);
        let nine = F::from(9);
        let neg_one = -F::ONE;
        for x in [F::ZERO, F::ONE, three, nine, neg_one] {
            let encoded = x.get_encoded().unwrap();
            assert_eq!(encoded.len(), F::num_bytes());
            let mut cursor = Cursor::new(&encoded[..]);
            let decoded = F::decode(&mut cursor).unwrap();
            assert_eq!(cursor.position(), encoded.len() as u64);
            assert_eq!(decoded, x);
        }

        let max_int_encoded = vec![0xffu8; F::num_bytes()];
        let result = F::decode(&mut Cursor::new(&max_int_encoded));
        if decode_is_fallible {
            result.unwrap_err();
        } else {
            result.unwrap();
        }

        let zero_encoded = vec![0u8; F::num_bytes()];
        assert_eq!(F::decode(&mut Cursor::new(&zero_encoded)).unwrap(), F::ZERO);

        let mut one_encoded = zero_encoded.clone();
        one_encoded[0] = 1;
        assert_eq!(F::decode(&mut Cursor::new(&one_encoded)).unwrap(), F::ONE);

        assert_eq!(F::from_u128(u64::MAX as u128), F::from(u64::MAX));
    }

    fn field_element_test_mul_inv_lagrange_nodes<F: LagrangePolynomialFieldElement>() {
        assert_eq!(F::sumcheck_p2_mul_inv() * F::SUMCHECK_P2, F::ONE);
        assert_eq!(
            F::one_minus_sumcheck_p2_mul_inv() * (F::ONE - F::SUMCHECK_P2),
            F::ONE
        );
        assert_eq!(
            F::sumcheck_p2_squared_minus_sumcheck_p2_mul_inv()
                * ((F::SUMCHECK_P2 * F::SUMCHECK_P2) - F::SUMCHECK_P2),
            F::ONE
        );
    }

    fn field_element_test_mul_inv<F: LagrangePolynomialFieldElement>() {
        for element in [3, 9] {
            for field_element in [F::from(element), -F::from(element)] {
                assert_eq!(
                    field_element.mul_inv() * field_element,
                    F::ONE,
                    "field element: {field_element:?}"
                );
            }
        }
    }

    fn field_element_test_pow<F: LagrangePolynomialFieldElement>() {
        for element in [3, 9] {
            let field_element = F::from(element);
            assert_eq!(
                field_element.pow(BigUint::zero()),
                F::ONE,
                "field element: {field_element:?}"
            );

            assert_eq!(
                field_element.pow(BigUint::one()),
                field_element,
                "field element: {field_element:?}"
            );

            assert_eq!(
                field_element.pow(BigUint::from(2usize)),
                field_element.square(),
                "field element: {field_element:?}"
            );

            // odd exponent
            assert_eq!(
                field_element.pow(BigUint::from(11usize)),
                F::from(element.pow(11)),
                "field element: {field_element:?}"
            );

            // even exponent
            assert_eq!(
                field_element.pow(BigUint::from(12usize)),
                F::from(element.pow(12)),
                "field element: {field_element:?}"
            );
        }
    }

    #[test]
    fn test_field_p256() {
        field_element_test_large_characteristic::<FieldP256>();
        field_element_test_codec::<FieldP256>(true);
        field_element_test_mul_inv_lagrange_nodes::<FieldP256>();
        field_element_test_pow::<FieldP256>();
        field_element_test_mul_inv::<FieldP256>();
    }

    #[test]
    fn test_field_p128() {
        field_element_test_large_characteristic::<FieldP128>();
        field_element_test_codec::<FieldP128>(true);
        field_element_test_mul_inv_lagrange_nodes::<FieldP128>();
        field_element_test_pow::<FieldP128>();
        field_element_test_mul_inv::<FieldP128>();
    }

    #[test]
    fn test_field_p521() {
        field_element_test_large_characteristic::<FieldP521>();
        field_element_test_codec::<FieldP521>(true);
        field_element_test_mul_inv_lagrange_nodes::<FieldP521>();
        field_element_test_pow::<FieldP521>();
        field_element_test_mul_inv::<FieldP521>();
    }

    #[test]
    fn test_field_p256_squared() {
        field_element_test_large_characteristic::<FieldP256_2>();
    }

    #[test]
    fn test_field_2_128() {
        field_element_test_codec::<Field2_128>(false);
        field_element_test_mul_inv_lagrange_nodes::<Field2_128>();
        // We don't yet have this stuff wired up for this field.
        // https://github.com/abetterinternet/zk-cred-longfellow/issues/47
        catch_unwind(field_element_test_pow::<Field2_128>).unwrap_err();
        catch_unwind(field_element_test_mul_inv::<Field2_128>).unwrap_err();
    }

    #[test]
    fn sample_field_without_excess_bits() {
        // Crude test that checks the rejection rate is below 50%.
        let count = 100;
        let mut total_rejections = 0;
        for _ in 0..count {
            let (_, rejections) = FieldP256::sample_counting_rejections(|num_bytes| {
                let mut bytes = vec![0; num_bytes];
                rand::rng().fill_bytes(&mut bytes);

                bytes
            });

            total_rejections += rejections;
        }
        assert!(total_rejections as f64 / (total_rejections as f64 + count as f64) < 0.5);
    }

    #[test]
    fn sample_field_with_excess_bits_without_rejections() {
        // FieldP521 has excess bits, but every 521 bit integer except the field prime itself, is a
        // valid field element, so if excess bit masking is correctly implemented, the chance of
        // rejections is negligible
        let mut total_rejections = 0;
        for _ in 0..100 {
            let (_, rejections) = FieldP521::sample_counting_rejections(|num_bytes| {
                let mut bytes = vec![0; num_bytes];
                rand::rng().fill_bytes(&mut bytes);

                bytes
            });
            total_rejections += rejections;
        }
        assert_eq!(total_rejections, 0);
    }

    #[test]
    fn sample_binary_field() {
        // GF(2^128) has an order that is a power of two, so we should never trigger rejection
        // sampling when generating random field elements.
        for _ in 0..100 {
            let (_, rejections) = Field2_128::sample_counting_rejections(|num_bytes| {
                let mut bytes = vec![0; num_bytes];
                rand::rng().fill_bytes(&mut bytes);

                bytes
            });
            assert_eq!(rejections, 0);
        }

        // Check that no bits are getting masked off when generating elements.
        let element = Field2_128::sample_from_source(|num_bytes| vec![0xff; num_bytes]);
        assert_eq!(element.get_encoded().unwrap(), vec![0xffu8; 16]);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sample() {
        FieldP128::sample();
    }

    fn lagrange_basis_polynomial_test<FE: LagrangePolynomialFieldElement>() {
        // lag_i is 1 at i and 0 at the other nodes
        assert_eq!(FE::lagrange_basis_polynomial_0(FE::ZERO), FE::ONE);
        assert_eq!(FE::lagrange_basis_polynomial_0(FE::ONE), FE::ZERO);
        assert_eq!(FE::lagrange_basis_polynomial_0(FE::SUMCHECK_P2), FE::ZERO);

        assert_eq!(FE::lagrange_basis_polynomial_1(FE::ZERO), FE::ZERO);
        assert_eq!(FE::lagrange_basis_polynomial_1(FE::ONE), FE::ONE);
        assert_eq!(FE::lagrange_basis_polynomial_1(FE::SUMCHECK_P2), FE::ZERO);

        assert_eq!(FE::lagrange_basis_polynomial_2(FE::ZERO), FE::ZERO);
        assert_eq!(FE::lagrange_basis_polynomial_2(FE::ONE), FE::ZERO);
        assert_eq!(FE::lagrange_basis_polynomial_2(FE::SUMCHECK_P2), FE::ONE);
    }

    #[test]
    fn lagrange_basis_polynomial_field_p128() {
        lagrange_basis_polynomial_test::<FieldP128>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_p256() {
        lagrange_basis_polynomial_test::<FieldP256>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_p521() {
        lagrange_basis_polynomial_test::<FieldP521>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_2_128() {
        lagrange_basis_polynomial_test::<Field2_128>();
    }
}
