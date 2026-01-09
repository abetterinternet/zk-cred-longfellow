//! Elliptic curve cryptography utilities.

use crate::{
    Codec,
    fields::{
        CodecFieldElement, FieldElement, fieldp256::FieldP256, fieldp256_scalar::FieldP256Scalar,
    },
    mdoc_zk::EcdsaWitness,
};
use anyhow::anyhow;
use subtle::{Choice, ConditionallySelectable, CtOption};

/// An elliptic curve point, represented with affine coordinates.
#[derive(Debug)]
pub(super) struct AffinePoint {
    /// If this is `Some`, it contains the coordinates of the point. If this is `None`, this point
    /// is the point at infinity.
    coords: CtOption<[FieldP256; 2]>,
}

impl AffinePoint {
    /// Constructs a point from its coordinates.
    pub(super) fn new(x: FieldP256, y: FieldP256) -> Self {
        Self {
            coords: CtOption::new([x, y], Choice::from(1)),
        }
    }

    /// Constructs the point at infinity.
    pub(super) fn infinity() -> Self {
        Self {
            coords: CtOption::new(Default::default(), Choice::from(0)),
        }
    }

    /// Returns the coordinates of this point, or `None` if it is the point at infinity.
    ///
    /// Note that this is not constant time with respect to the discriminant for the point
    /// at infinity.
    pub(super) fn coordinates(&self) -> Option<[FieldP256; 2]> {
        self.coords.into()
    }

    /// Decodes an encoded P-256 elliptic curve point.
    ///
    /// Returns `None` if the encoding represents the point at infinity.
    ///
    /// See <https://www.secg.org/sec1-v2.pdf#page=17>.
    pub(super) fn decode(bytes: &[u8]) -> Result<AffinePoint, anyhow::Error> {
        if bytes == [0] {
            // Point at infinity.
            Ok(Self::infinity())
        } else if bytes.len() == FieldP256::num_bytes() + 1 {
            // Compressed encoding.
            //
            // Unwrap safety: we just checked the length.
            let (first, rest) = bytes.split_first().unwrap();
            let x = decode_field_element(rest.try_into().unwrap())?;
            let y_parity = match first {
                2 | 3 => Choice::from(*first & 1),
                _ => {
                    return Err(anyhow!(
                        "invalid elliptic curve point encoding, wrong prefix byte"
                    ));
                }
            };
            let alpha = x.square() * x + P256_A * x + P256_B;
            let beta = alpha
            .sqrt()
            .into_option()
            .ok_or_else(|| anyhow!("invalid elliptic curve point encoding, x-coordinate does not correspond to any points on the curve"))?;
            let beta_encoded = beta.get_encoded()?;
            let beta_parity = Choice::from(beta_encoded[0] & 1);
            let y = FieldP256::conditional_select(&beta, &-beta, y_parity ^ beta_parity);
            Ok(Self::new(x, y))
        } else if bytes.len() == 2 * FieldP256::num_bytes() + 1 {
            // Uncompressed encoding.
            //
            // Unwrap safety: we just checked the length.
            let (first, rest) = bytes.split_first().unwrap();
            let (bytes_x, bytes_y) = rest.split_at(FieldP256::num_bytes());
            if *first != 4 {
                return Err(anyhow!(
                    "invalid elliptic curve point encoding, wrong prefix byte"
                ));
            }
            let x = decode_field_element(bytes_x.try_into().unwrap())?;
            let y = decode_field_element(bytes_y.try_into().unwrap())?;
            if y.square() != x.square() * x + P256_A * x + P256_B {
                return Err(anyhow!(
                    "invalid elliptic curve point encoding, coordinates are not on the curve"
                ));
            }
            Ok(Self::new(x, y))
        } else {
            Err(anyhow!(
                "encoded elliptic curve point has an invalid length"
            ))
        }
    }
}

/// Decode a big-endian serialized field element.
fn decode_field_element(bytes: &[u8; 32]) -> Result<FieldP256, anyhow::Error> {
    // SEC 1 uses big-endian encoding, but fiat-crypto uses little-endian encoding.
    let mut reversed = [0u8; 32];
    reversed.copy_from_slice(bytes);
    reversed.reverse();
    FieldP256::try_from(&reversed)
}

/// One of the two coefficients of the P-256 elliptic curve.
const P256_A: FieldP256 = {
    match FieldP256::try_from_bytes_const(&[
        0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ]) {
        Ok(value) => value,
        Err(_) => panic!("could not convert constant to field element"),
    }
};
/// One of the two coefficients of the P-256 elliptic curve.
const P256_B: FieldP256 = {
    match FieldP256::try_from_bytes_const(&[
        0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d,
        0x65, 0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3, 0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35,
        0xc6, 0x5a,
    ]) {
        Ok(value) => value,
        Err(_) => panic!("could not convert constant to field element"),
    }
};

/// An ECDSA signature.
pub(super) struct Signature {
    pub(super) r: FieldP256Scalar,
    pub(super) s: FieldP256Scalar,
}

impl Signature {
    /// Deserialize a P-256 ECDSA signature from a byte string.
    ///
    /// See [RFC 9053, section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1).
    pub(super) fn decode(input: &[u8]) -> Result<Self, anyhow::Error> {
        if input.len() != 64 {
            return Err(anyhow!("signature length is incorrect"));
        }
        let mut buffer = [0; 32];
        buffer.copy_from_slice(&input[..32]);
        buffer.reverse();
        let r = FieldP256Scalar::try_from(&buffer)?;
        buffer.copy_from_slice(&input[32..]);
        buffer.reverse();
        let s = FieldP256Scalar::try_from(&buffer)?;
        Ok(Self { r, s })
    }
}

pub(super) fn fill_ecdsa_witness(
    witness: &mut EcdsaWitness<'_>,
    public_key: AffinePoint,
    signature: Signature,
    _hash: [u8; 32],
) -> Result<(), anyhow::Error> {
    let [qx, _qy] = public_key
        .coordinates()
        .ok_or_else(|| anyhow!("public key is the point at infinity"))?;
    let Signature { r, s } = signature;

    // TODO: Recover coordinates of R from the signature.

    *witness.r_x = embed_scalar_in_base_field(r);
    // TODO: r_y
    *witness.r_x_inverse = witness.r_x.mul_inv();
    *witness.neg_s_inverse = embed_scalar_in_base_field(-s).mul_inv();
    *witness.q_x_inverse = qx.mul_inv();

    // TODO: multi-scalar multiplication

    Ok(())
}

fn embed_scalar_in_base_field(scalar: FieldP256Scalar) -> FieldP256 {
    let mut encoded = Vec::with_capacity(32);
    // Unwrap safety: this implementation is infallible.
    scalar.encode(&mut encoded).unwrap();
    // Unwrap safety: this will succeed because the slice is the right size, and the size of the
    // scalar field is smaller than the base field.
    FieldP256::try_from(encoded.as_slice()).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::ec::AffinePoint;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_decode_point() {
        // Identity element
        assert_eq!(AffinePoint::decode(&[0]).unwrap().coordinates(), None);
        // Generator point, compressed form
        let gen_1 = AffinePoint::decode(&[
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96,
        ])
        .unwrap()
        .coordinates()
        .unwrap();
        // Generator point, uncompressed form
        let gen_2 = AffinePoint::decode(&[
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ])
        .unwrap()
        .coordinates()
        .unwrap();
        assert_eq!(gen_1, gen_2);
        // Off-curve point, uncompressed form
        AffinePoint::decode(&[
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap_err();
        // Coordinate beyond field modulus
        AffinePoint::decode(&[
            0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
        ])
        .unwrap_err();
        // Invalid encoded length
        AffinePoint::decode(&[0, 0]).unwrap_err();
        // Invalid prefixes
        AffinePoint::decode(&[0x5; 33]).unwrap_err();
        AffinePoint::decode(&[0x5; 65]).unwrap_err();
    }
}
