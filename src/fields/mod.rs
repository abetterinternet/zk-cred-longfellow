//! Various finite field implementations.
use crate::{
    Codec,
    fields::{field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256},
};
use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_integer::Integer;
use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    io::{Cursor, Write},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
    + ConditionallySelectable
{
    /// The additive identity of the field.
    const ZERO: Self;

    /// The multiplicative identity of the field.
    const ONE: Self;

    /// Project an integer into the field.
    fn from_u128(value: u128) -> Self;

    /// Test whether this element is zero.
    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Square a field element.
    fn square(&self) -> Self;

    /// The multiplicative inverse of this value.
    fn mul_inv(&self) -> Self;

    /// Raise a field element to some power.
    ///
    /// This is constant-time with respect to the field element input, but variable-time with
    /// respect to the exponent.
    fn exp_vartime(&self, mut exponent: BigUint) -> Self {
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

    /// True if the field has large characteristic, false otherwise.
    fn large_characteristic() -> bool {
        // Default to true and make GF(2^128) opt out.
        true
    }
}

/// An element of a finite field with a defined serialization format.
pub trait CodecFieldElement:
    FieldElement
    + for<'a> TryFrom<&'a [u8], Error = anyhow::Error>
    + Codec
    + Serialize
    + DeserializeOwned
{
    /// Number of bits needed to represent a field element.
    const NUM_BITS: usize;

    /// Identifier for the field in encoded messages.
    const FIELD_ID: FieldId;

    /// Number of bytes needed to represent a field element.
    fn num_bytes() -> usize {
        Self::NUM_BITS.div_ceil(8)
    }

    /// Generate a field element by rejection sampling.
    fn sample() -> Self {
        let mut buffer = vec![0; Self::num_bytes()];
        let mut rng = rand::rng();
        Self::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes))
    }

    /// Generate a field element by rejection sampling, sampling random bytes from the provided
    /// source.
    fn sample_from_source<F>(buffer: &mut [u8], source: F) -> Self
    where
        F: FnMut(&mut [u8]),
    {
        Self::sample_counting_rejections(buffer, source).0
    }

    /// Generate a field element by rejection sampling and return how many rejections were observed.
    fn sample_counting_rejections<F>(buffer: &mut [u8], mut source: F) -> (Self, usize)
    where
        F: FnMut(&mut [u8]),
    {
        let mut rejections = 0;
        let field_element = loop {
            // Some fields like P521 have a bit count that isn't congruent to 8. We sample
            // enough excess bits to get whole bytes and then mask off the excess, which can be
            // at most 7 bits.
            // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.3
            let num_sampled_bytes = Self::num_bytes();
            source(buffer);
            let excess_bits = num_sampled_bytes * 8 - Self::NUM_BITS;
            if excess_bits != 0 {
                buffer[num_sampled_bytes - 1] &= (1 << (8 - excess_bits)) - 1;
            }
            // FE::try_from rejects if the value is still too big after masking.
            // TODO: FE::try_from could fail for reasons besides the generated value being too big
            if let Ok(fe) = Self::try_from(buffer) {
                break fe;
            }
            rejections += 1;
        };

        (field_element, rejections)
    }

    /// Whether or not this field element fits in the subfield associated with the field.
    fn is_in_subfield(&self) -> bool {
        // By default, fields have no subfield, or put another way, they are their own subfield.
        true
    }

    /// Encode this element as an element of the subfield associated with the field.
    fn encode_in_subfield<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
        // By default, fields have no subfield, or put another way, they are their own subfield.
        self.encode(bytes)
    }

    /// Encode this value into a byte array on the stack.
    ///
    /// Ideally we would simply return `[u8; Self::NUM_BITS / 8]` here, but generic types aren't
    /// allowed in const contexts, so we need to indirect via `AsRef<[u8]>`.
    fn as_byte_array(&self) -> Result<impl AsRef<[u8]>, anyhow::Error>;

    /// Decode a fixed length array of elements from the subfield into the field.
    fn decode_fixed_array_in_subfield(
        bytes: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self>, anyhow::Error> {
        // By default, fields have no subfield, or put another way, they are their own subfield.
        Self::decode_fixed_array(bytes, count)
    }

    /// Update the provided [`Sha256`], which is assumed to be computing the ID of a circuit, with a
    /// description of this field. This matches what is done in [`longfellow-zk`][1].
    ///
    /// The default implementation is valid for prime order fields only.
    ///
    /// [1]: https://github.com/google/longfellow-zk/blob/v0.8.6/lib/sumcheck/circuit_id.h
    fn update_circuit_id(circuit_id: &mut Sha256) -> Result<(), anyhow::Error> {
        // Large characteristic fields are assumed to be prime order and indicated by an eight byte
        // LE array containing the single byte 1, then the encoding of -1 in the field.
        circuit_id.update(1u64.to_le_bytes());
        circuit_id.update((-Self::ONE).as_byte_array()?);

        Ok(())
    }
}

/// Enough bytes to fit the encoding of any [`CodecFieldElement`] implementation.
pub const CODEC_FIELD_ELEMENT_MAX_NUM_BYTES: usize = 32;

/// Field elements used directly in proofs.
///
/// This trait provides methods to interpolate polynomials in two different contexts. For the
/// Sumcheck sub-protocol, [`ProofFieldElement::lagrange_basis_polynomial_0()`],
/// [`ProofFieldElement::lagrange_basis_polynomial_1()`], and
/// [`ProofFieldElement::lagrange_basis_polynomial_2()`], provide the basis polynomials necessary to
/// interpolate degree two polynomials (see [Section 6.6][1] and [2] for details). For the Ligero
/// sub-protocol, [`ProofFieldElement::extend()`] performs Reed-Solomon encoding (see Section 3.2 of
/// [3] for details).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
/// [2]: https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
/// [3]: https://eprint.iacr.org/2024/2010.pdf
pub trait ProofFieldElement: CodecFieldElement {
    /// Evaluate the 0th Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_0(x: Self) -> Self {
        // (x - x_1) * (x - x_2)
        (x - Self::ONE) * (x - Self::SUMCHECK_P2)
            // (x_0 - x_1) * (x_0 - x_2) = (0 - 1) * (0 - SUMCHECK_P2) = SUMCHECK_P2
            * Self::SUMCHECK_P2_MUL_INV
    }

    /// Evaluate the 1st Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_1(x: Self) -> Self {
        // (x - x_0) * (x - x_2)
        (x - Self::ZERO) * (x - Self::SUMCHECK_P2)
            // (x_1 - x_0) * (x_1 - x_2) = (1 - 0) * (1 - SUMCHECK_P2) = 1 - SUMCHECK_P2
            * Self::ONE_MINUS_SUMCHECK_P2_MUL_INV
    }

    /// Evaluate the 2nd Lagrange basis polynomial at x.
    fn lagrange_basis_polynomial_2(x: Self) -> Self {
        // (x - x_0) * (x - x_1)
        (x - Self::ZERO) * (x - Self::ONE)
            // (x_2 - x_0) * (x_2 - x_1) = (SUMCHECK_P2 - 0) * (SUMCHECK_P2 - 1)
            //   = SUMCHECK_P2^2 - SUMCHECK_P2
            * Self::SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV
    }

    /// The third evaluation point used by sumcheck.
    ///
    /// This will be 2 for large characteristic fields, and x for fields of characteristic two.
    const SUMCHECK_P2: Self;

    /// The multiplicative inverse of `SUMCHECK_P2`. Denominator of the 0th Lagrange basis
    /// polynomial.
    const SUMCHECK_P2_MUL_INV: Self;

    /// The multiplicative inverse of `1 - SUMCHECK_P2`. Denominator of the 1st Lagrange basis
    /// polynomial.
    const ONE_MINUS_SUMCHECK_P2_MUL_INV: Self;

    /// The multiplicative inverse of `SUMCHECK_P2^2 - SUMCHECK_P2`. Denominator of the 2nd Lagrange
    /// basis polynomial.
    const SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV: Self;

    /// Precomputed values produced by `extend_precompute()`. This should be passed to `extend()`.
    type ExtendContext;

    /// Precompute values needed by `extend()`.
    ///
    /// This precomputes intermediate values needed by `extend()`, based on the input and output
    /// lengths. When `extend()` is called, the length of the input vector must match the
    /// corresponding `nodes_len` value used to construct the context.
    fn extend_precompute(nodes_len: usize, evaluations: usize) -> Self::ExtendContext;

    /// The extend method, as defined in [2.2.1][1] and [2.2.2][2]. We interpolate a polynomial of
    /// degree at most `nodes.len() - 1` from the provided evaluations and then evaluate that
    /// polynomial at additional points.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.1
    /// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
    fn extend(nodes: &[Self], context: &Self::ExtendContext) -> Vec<Self>;
}

pub fn field_element_iter<FE: CodecFieldElement>() -> impl Iterator<Item = FE> {
    let mut buffer = vec![0; FE::num_bytes()];
    let mut rng = rand::rng();
    std::iter::repeat_with(move || {
        FE::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes))
    })
}

pub fn field_element_iter_from_source<F, FE>(source: F) -> impl Iterator<Item = FE>
where
    FE: CodecFieldElement,
    F: FnMut() -> FE,
{
    std::iter::repeat_with(source)
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

    fn encode<W: Write>(&self, bytes: &mut W) -> Result<(), anyhow::Error> {
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
            FieldId::P521 => 66,
            FieldId::GF2_128 => Field2_128::num_bytes(),
            FieldId::GF2_16 => 2,
            FieldId::FP128 => FieldP128::num_bytes(),
        }
    }
}

pub mod field2_128;
pub mod fieldp128;
pub mod fieldp256;
pub mod fieldp256_2;
pub mod fieldp256_scalar;

mod quadratic_extension;
use quadratic_extension::QuadraticExtension;

mod addition_chains;

mod extend_p;
use extend_p::{ExtendContext, extend, extend_precompute};

mod ntt;
pub use ntt::NttFieldElement;

#[cfg(test)]
mod tests {
    use crate::{
        Codec, ParameterizedCodec,
        fields::{
            CODEC_FIELD_ELEMENT_MAX_NUM_BYTES, CodecFieldElement, FieldElement, ProofFieldElement,
            field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256,
            fieldp256_2::FieldP256_2, fieldp256_scalar::FieldP256Scalar,
        },
    };
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use rand::RngCore;
    use std::{io::Cursor, iter::repeat_with, ops::Range};
    use subtle::Choice;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn field_p128_from_bytes_accept() {
        FieldP128::try_from(
            &[
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ][..],
        )
        .expect("Exactly the length of a field element (16 bytes), but a legal field value.");
    }

    #[wasm_bindgen_test(unsupported = test)]
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

    #[wasm_bindgen_test(unsupported = test)]
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

    #[wasm_bindgen_test(unsupported = test)]
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

    #[wasm_bindgen_test(unsupported = test)]
    fn field_p256_roundtrip() {
        FieldP256::from_u128(111).roundtrip(&());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn field_p128_roundtrip() {
        FieldP128::from_u128(111).roundtrip(&());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn field_2_128_roundtrip() {
        Field2_128::from_u128(0xdeadbeef12345678f00faaaabbbbcccc).roundtrip(&());
    }

    /// Test methods of [`FieldElement`] implementations.
    fn field_element_test_common<F: FieldElement>() {
        field_element_test_mul_inv::<F>();
        field_element_test_exp_consistent::<F>();
        field_element_test_subtle::<F>();
    }

    /// Test [`FieldElement`] implementations, assuming the field has a large characteristic.
    #[allow(clippy::op_ref, clippy::eq_op)]
    fn field_element_test_large_characteristic<F: FieldElement>() {
        let two = F::from(2);
        let three = F::from(3);
        let nine = F::from(9);
        let neg_one = -F::ONE;

        assert_eq!(F::from(0), F::ZERO);
        assert_eq!(F::from(1), F::ONE);
        assert_eq!(F::from(2), two);

        assert_ne!(F::ZERO, F::ONE);
        assert_ne!(F::ONE, three);
        assert_ne!(three, nine);
        assert_ne!(nine, neg_one);

        assert_eq!(neg_one + &F::ONE, F::ZERO);
        assert_eq!(neg_one + F::ONE, F::ZERO);
        let mut temp = neg_one;
        temp += F::ONE;
        assert_eq!(temp, F::ZERO);

        assert_eq!(F::ONE + &F::ONE, two);
        assert_eq!(F::ONE + F::ONE, two);
        let mut temp = F::ONE;
        temp += F::ONE;
        assert_eq!(temp, two);

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
        assert_eq!(temp, two);

        for x in [F::ZERO, F::ONE, three, nine, neg_one] {
            assert_eq!(x.square(), x * x);
        }
        let mut value = F::from(u64::MAX);
        for _ in 0..20 {
            assert_eq!(value.square(), value * value);
            value *= value;
        }

        field_element_test_exp_large_characteristic::<F>();
    }

    /// Test implementations of [`CodecFieldElement`].
    fn field_element_test_codec<F: CodecFieldElement>(decode_is_fallible: bool) {
        assert!(F::num_bytes() <= CODEC_FIELD_ELEMENT_MAX_NUM_BYTES);

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

    /// Test implementations of [`ProofFieldElement`].
    fn field_element_test_proof<F: ProofFieldElement>() {
        field_element_test_proof_constants::<F>();
        lagrange_basis_polynomial_test::<F>();
    }

    /// Check the consistency of [`ProofFieldElement`] constants.
    fn field_element_test_proof_constants<F: ProofFieldElement>() {
        assert_eq!(F::SUMCHECK_P2_MUL_INV * F::SUMCHECK_P2, F::ONE);
        assert_eq!(
            F::ONE_MINUS_SUMCHECK_P2_MUL_INV * (F::ONE - F::SUMCHECK_P2),
            F::ONE
        );
        assert_eq!(
            F::SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV
                * ((F::SUMCHECK_P2 * F::SUMCHECK_P2) - F::SUMCHECK_P2),
            F::ONE
        );
    }

    fn field_element_test_mul_inv<F: FieldElement>() {
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

    fn field_element_test_exp_large_characteristic<F: FieldElement>() {
        for element in [3, 9] {
            let field_element = F::from(element);
            // odd exponent
            assert_eq!(
                field_element.exp_vartime(BigUint::from(11usize)),
                F::from(element.pow(11)),
                "field element: {field_element:?}"
            );

            // even exponent
            assert_eq!(
                field_element.exp_vartime(BigUint::from(12usize)),
                F::from(element.pow(12)),
                "field element: {field_element:?}"
            );
        }
    }

    fn field_element_test_exp_consistent<F: FieldElement>() {
        for element in [3, 9] {
            let field_element = F::from(element);
            assert_eq!(
                field_element.exp_vartime(BigUint::zero()),
                F::ONE,
                "field element: {field_element:?}"
            );

            assert_eq!(
                field_element.exp_vartime(BigUint::one()),
                field_element,
                "field element: {field_element:?}"
            );

            assert_eq!(
                field_element.exp_vartime(BigUint::from(2usize)),
                field_element.square(),
                "field element: {field_element:?}"
            );

            // odd exponent
            assert_eq!(
                field_element.exp_vartime(BigUint::from(3usize)),
                field_element * field_element * field_element,
                "field element: {field_element:?}"
            );

            // even exponent
            assert_eq!(
                field_element.exp_vartime(BigUint::from(4usize)),
                field_element.square().square(),
                "field element: {field_element:?}"
            );
        }
    }

    fn field_element_test_subtle<F: FieldElement>() {
        let elements = [F::ZERO, F::ONE, -F::ONE, F::from_u128(0xDEADBEEF)];
        for a in elements {
            for b in elements {
                assert_eq!(F::conditional_select(&a, &b, Choice::from(0)), a);
                assert_eq!(F::conditional_select(&a, &b, Choice::from(1)), b);
            }
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_field_p256() {
        field_element_test_common::<FieldP256>();
        field_element_test_large_characteristic::<FieldP256>();
        field_element_test_codec::<FieldP256>(true);
        field_element_test_proof::<FieldP256>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_field_p256_scalar() {
        field_element_test_common::<FieldP256Scalar>();
        field_element_test_large_characteristic::<FieldP256Scalar>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_field_p128() {
        field_element_test_common::<FieldP128>();
        field_element_test_large_characteristic::<FieldP128>();
        field_element_test_codec::<FieldP128>(true);
        field_element_test_proof::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_field_p256_squared() {
        field_element_test_common::<FieldP256>();
        field_element_test_large_characteristic::<FieldP256_2>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_field_2_128() {
        field_element_test_common::<Field2_128>();
        field_element_test_codec::<Field2_128>(false);
        field_element_test_proof::<Field2_128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sample_field_without_excess_bits() {
        // Crude test that checks the rejection rate is below 50%.
        let count = 100;
        let mut total_rejections = 0;
        for _ in 0..count {
            let (_, rejections) = FieldP256::sample_counting_rejections(
                &mut vec![0; FieldP256::num_bytes()],
                |bytes| rand::rng().fill_bytes(bytes),
            );

            total_rejections += rejections;
        }
        assert!(total_rejections as f64 / (total_rejections as f64 + count as f64) < 0.5);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sample_binary_field() {
        // GF(2^128) has an order that is a power of two, so we should never trigger rejection
        // sampling when generating random field elements.
        for _ in 0..100 {
            let (_, rejections) = Field2_128::sample_counting_rejections(
                &mut vec![0; Field2_128::num_bytes()],
                |bytes| rand::rng().fill_bytes(bytes),
            );
            assert_eq!(rejections, 0);
        }

        // Check that no bits are getting masked off when generating elements.
        let element =
            Field2_128::sample_from_source(&mut vec![0; Field2_128::num_bytes()], |bytes| {
                bytes.copy_from_slice(&vec![0xff; Field2_128::num_bytes()])
            });
        assert_eq!(element.get_encoded().unwrap(), vec![0xffu8; 16]);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sample() {
        FieldP128::sample();
    }

    fn lagrange_basis_polynomial_test<FE: ProofFieldElement>() {
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

    fn extend_x_2<FE: ProofFieldElement>() {
        let output = FE::extend(
            // x^2 evaluated at 0, 1, 2 => 0, 1, 4
            &[FE::ZERO, FE::ONE, FE::from_u128(4)],
            &FE::extend_precompute(3, 6),
        );

        assert_eq!(
            output,
            // x^2 evaluated at 0..6 = > 0, 1, 4, 9, 16, 25
            vec![
                FE::ZERO,
                FE::ONE,
                FE::from_u128(4),
                FE::from_u128(9),
                FE::from_u128(16),
                FE::from_u128(25),
            ]
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_x_2_p128() {
        extend_x_2::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_x_2_p256() {
        extend_x_2::<FieldP256>();
    }

    fn extend_many_sizes<FE: ProofFieldElement>() {
        // Evaluate a polynomial, given in the monomial basis, at a range of points.
        fn eval_horners_method<FE: ProofFieldElement>(
            polynomial: &[FE],
            eval_at: Range<u128>,
        ) -> Vec<FE> {
            eval_at
                .map(|x| {
                    let x = FE::from_u128(x);
                    let mut output = FE::ZERO;

                    for coefficient in polynomial.iter().rev() {
                        output = output * x + *coefficient;
                    }

                    output
                })
                .collect()
        }

        // Extend to various lengths, to ensure we exercise edge cases.
        for requested_evaluations in [1, 2, 3, 4, 5, 9, 10, 11, 15, 16, 17] {
            for input_points in 1..requested_evaluations {
                // Generate a random polynomial, in the monomial basis.
                let polynomial = repeat_with(FE::sample)
                    .take(input_points)
                    .collect::<Vec<_>>();

                // Evaluate the polynomial directly.
                let expected =
                    eval_horners_method(&polynomial, 0..requested_evaluations.try_into().unwrap());

                // Interpolate and evaluate with `extend()`.
                let extended = FE::extend(
                    &expected[..input_points],
                    &FE::extend_precompute(input_points, requested_evaluations),
                );

                assert_eq!(
                    extended, expected,
                    "interpolation mismatch when extending from {input_points} to {requested_evaluations}"
                );
            }
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_many_sizes_p128() {
        extend_many_sizes::<FieldP128>();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn extend_many_sizes_p256() {
        extend_many_sizes::<FieldP256>();
    }
}
