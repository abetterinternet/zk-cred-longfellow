//! Elliptic curve cryptography utilities.

use crate::{
    Codec, Sha256Digest,
    fields::{
        CodecFieldElement, FieldElement, fieldp256::FieldP256, fieldp256_scalar::FieldP256Scalar,
    },
    mdoc_zk::EcdsaWitness,
};
use anyhow::anyhow;
use std::ops::Add;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// An elliptic curve point, represented with affine coordinates.
#[derive(Debug, Clone, Copy)]
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

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.coords.is_some().ct_eq(&other.coords.is_some()))
            & (self
                .coords
                .unwrap_or(Default::default())
                .ct_eq(&other.coords.unwrap_or(Default::default())))
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() != 0
    }
}

impl Eq for AffinePoint {}

/// An elliptic curve point, represented with projective coordinates.
#[derive(Debug, Clone, Copy)]
pub(super) struct ProjectivePoint {
    pub(super) x: FieldP256,
    pub(super) y: FieldP256,
    pub(super) z: FieldP256,
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(value: AffinePoint) -> Self {
        value
            .coords
            .map(|[x, y]| ProjectivePoint {
                x,
                y,
                z: FieldP256::ONE,
            })
            .unwrap_or(Self::IDENTITY)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(value: ProjectivePoint) -> Self {
        // If Z is zero, we will still perform all the same operations, to ensure constant-time
        // behavior. The resulting `CtOption` will be `None`, representing the point at infinity.
        let is_identity = value.z.ct_eq(&FieldP256::ZERO);
        let reciprocal = value.z.mul_inv();
        Self {
            coords: CtOption::new([value.x * reciprocal, value.y * reciprocal], !is_identity),
        }
    }
}

/// Addition of two projective points.
///
/// See https://eprint.iacr.org/2015/1060, Algorithm 4, "Complete, projective point addition for
/// prime order short Weierstrass curves E/F_q: y^2=x^3 + ax + b with a = -3."
impl Add<Self> for ProjectivePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let Self {
            x: x1,
            y: y1,
            z: z1,
        } = self;
        let Self {
            x: x2,
            y: y2,
            z: z2,
        } = rhs;

        let t0 = x1 * x2; // 1
        let t1 = y1 * y2; // 2
        let t2 = z1 * z2; // 3
        let t3 = x1 + y1; // 4
        let t4 = x2 + y2; // 5
        let t3 = t3 * t4; // 6
        let t4 = t0 + t1; // 7
        let t3 = t3 - t4; // 8
        let t4 = y1 + z1; // 9
        let x3 = y2 + z2; // 10
        let t4 = t4 * x3; // 11
        let x3 = t1 + t2; // 12
        let t4 = t4 - x3; // 13
        let x3 = x1 + z1; // 14
        let y3 = x2 + z2; // 15
        let x3 = x3 * y3; // 16
        let y3 = t0 + t2; // 17
        let y3 = x3 - y3; // 18
        let z3 = P256_B * t2; // 19
        let x3 = y3 - z3; // 20
        let z3 = x3 + x3; // 21
        let x3 = x3 + z3; // 22
        let z3 = t1 - x3; // 23
        let x3 = t1 + x3; // 24
        let y3 = P256_B * y3; // 25
        let t1 = t2 + t2; // 26
        let t2 = t1 + t2; // 27
        let y3 = y3 - t2; // 28
        let y3 = y3 - t0; // 29
        let t1 = y3 + y3; // 30
        let y3 = t1 + y3; // 31
        let t1 = t0 + t0; // 32
        let t0 = t1 + t0; // 33
        let t0 = t0 - t2; // 34
        let t1 = t4 * y3; // 35
        let t2 = t0 * y3; // 36
        let y3 = x3 * z3; // 37
        let y3 = y3 + t2; // 38
        let x3 = t3 * x3; // 39
        let x3 = x3 - t1; // 40
        let z3 = t4 * z3; // 41
        let t1 = t3 * t0; // 42
        let z3 = z3 + t1; // 43

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Mixed addition of projective and affine points.
///
/// See https://eprint.iacr.org/2015/1060, Algorithm 5, "Complete, mixed point addition for prime
/// order short Weierstrass curves E/F_q: y^2 = x^3 + ax + b with a = -3."
impl Add<AffinePoint> for ProjectivePoint {
    type Output = Self;

    fn add(self, rhs: AffinePoint) -> Self {
        let Self {
            x: x1,
            y: y1,
            z: z1,
        } = self;
        rhs.coords
            .map(|[x2, y2]| {
                let t0 = x1 * x2; // 1
                let t1 = y1 * y2; // 2
                let t3 = x2 + y2; // 3
                let t4 = x1 + y1; // 4
                let t3 = t3 * t4; // 5
                let t4 = t0 + t1; // 6
                let t3 = t3 - t4; // 7
                let t4 = y2 * z1; // 8
                let t4 = t4 + y1; // 9
                let y3 = x2 * z1; // 10
                let y3 = y3 + x1; // 11
                let z3 = P256_B * z1; // 12
                let x3 = y3 - z3; // 13
                let z3 = x3 + x3; // 14
                let x3 = x3 + z3; // 15
                let z3 = t1 - x3; // 16
                let x3 = t1 + x3; // 17
                let y3 = P256_B * y3; // 18
                let t1 = z1 + z1; // 19
                let t2 = t1 + z1; // 20
                let y3 = y3 - t2; // 21
                let y3 = y3 - t0; // 22
                let t1 = y3 + y3; // 23
                let y3 = t1 + y3; // 24
                let t1 = t0 + t0; // 25
                let t0 = t1 + t0; // 26
                let t0 = t0 - t2; // 27
                let t1 = t4 * y3; // 28
                let t2 = t0 * y3; // 29
                let y3 = x3 * z3; // 30
                let y3 = y3 + t2; // 31
                let x3 = t3 * x3; // 32
                let x3 = x3 - t1; // 33
                let z3 = t4 * z3; // 34
                let t1 = t3 * t0; // 35
                let z3 = z3 + t1; // 36
                Self {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            })
            .unwrap_or(self)
    }
}

impl ProjectivePoint {
    /// The identity element of the projective point addition operation.
    ///
    /// This represents the point at infinity in the elliptic curve.
    pub(super) const IDENTITY: Self = Self {
        x: FieldP256::ZERO,
        y: FieldP256::ONE,
        z: FieldP256::ZERO,
    };

    /// Doubling of a projective point.
    ///
    /// See https://eprint.iacr.org/2015/1060, Algorithm 6, "Exception-free point doubling for prime
    /// order short Weierstrass curves E/F_q: y^2 = x^3 + ax + b with a = -3."
    pub(super) fn double(self) -> Self {
        let Self { x, y, z } = self;

        let t0 = x * x; // 1
        let t1 = y * y; // 2
        let t2 = z * z; // 3
        let t3 = x * y; // 4
        let t3 = t3 + t3; // 5
        let z3 = x * z; // 6
        let z3 = z3 + z3; // 7
        let y3 = P256_B * t2; // 8
        let y3 = y3 - z3; // 9
        let x3 = y3 + y3; // 10
        let y3 = x3 + y3; // 11
        let x3 = t1 - y3; // 12
        let y3 = t1 + y3; // 13
        let y3 = x3 * y3; // 14
        let x3 = x3 * t3; // 15
        let t3 = t2 + t2; // 16
        let t2 = t2 + t3; // 17
        let z3 = P256_B * z3; // 18
        let z3 = z3 - t2; // 19
        let z3 = z3 - t0; // 20
        let t3 = z3 + z3; // 21
        let z3 = z3 + t3; // 22
        let t3 = t0 + t0; // 23
        let t0 = t3 + t0; // 24
        let t0 = t0 - t2; // 25
        let t0 = t0 * z3; // 26
        let y3 = y3 + t0; // 27
        let t0 = y * z; // 28
        let t0 = t0 + t0; // 29
        let z3 = t0 * z3; // 30
        let x3 = x3 - z3; // 31
        let z3 = t0 * t1; // 32
        let z3 = z3 + z3; // 33
        let z3 = z3 + z3; // 34

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Perform an elliptic curve point scalar multiplication.
    pub(super) fn scalar_mult(self, scalar: impl Scalar) -> Self {
        let mut accumulator = Self::IDENTITY;
        for bit in scalar.bits() {
            let double = accumulator.double();
            let plus_one = double.add(self);
            accumulator = Self::conditional_select(&double, &plus_one, bit);
        }
        accumulator
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldP256::conditional_select(&a.x, &b.x, choice),
            y: FieldP256::conditional_select(&a.y, &b.y, choice),
            z: FieldP256::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// Values that can be used as a scalar in an elliptic curve point scalar multiplication.
pub(super) trait Scalar {
    /// Returns the bits of the scalar, starting with the most significant bit.
    fn bits(&self) -> impl Iterator<Item = Choice>;
}

impl Scalar for FieldP256Scalar {
    fn bits(&self) -> impl Iterator<Item = Choice> {
        let limbs = self.to_non_montgomery();
        limbs.into_iter().rev().flat_map(|limb| {
            (0..64)
                .rev()
                .map(move |i| Choice::from(((limb >> i) & 1) as u8))
        })
    }
}

/// Treat the output of SHA-256 as a scalar for an elliptic curve group.
///
/// This treats the hash as a big-endian integer, following the convention of ECDSA.
impl Scalar for Sha256Digest {
    fn bits(&self) -> impl Iterator<Item = Choice> {
        self.0
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1)))
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
///
/// Note that this is -3.
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
/// The generator of the P-256 elliptic curve group.
const P256_G: [FieldP256; 2] = {
    let x = match FieldP256::try_from_bytes_const(&[
        0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03,
        0x77, 0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8, 0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1,
        0x17, 0x6b,
    ]) {
        Ok(value) => value,
        Err(_) => panic!("could not convert constant to field element"),
    };
    let y = match FieldP256::try_from_bytes_const(&[
        0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb, 0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce,
        0x2b, 0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e, 0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42,
        0xe3, 0x4f,
    ]) {
        Ok(value) => value,
        Err(_) => panic!("could not convert constant to field element"),
    };
    [x, y]
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
        if r == FieldP256Scalar::ZERO {
            return Err(anyhow!("invalid signature, r is zero"));
        }

        buffer.copy_from_slice(&input[32..]);
        buffer.reverse();
        let s = FieldP256Scalar::try_from(&buffer)?;
        if s == FieldP256Scalar::ZERO {
            return Err(anyhow!("invalid signature, s is zero"));
        }

        Ok(Self { r, s })
    }
}

pub(super) fn fill_ecdsa_witness(
    witness: &mut EcdsaWitness<'_>,
    public_key: AffinePoint,
    signature: Signature,
    hash: Sha256Digest,
) -> Result<(), anyhow::Error> {
    let [qx, _qy] = public_key
        .coordinates()
        .ok_or_else(|| anyhow!("public key is the point at infinity"))?;
    let Signature { r, s } = signature;

    // Recover coordinates of R from the signature.
    let e = FieldP256Scalar::from_hash(hash);
    let s_inv = signature.s.mul_inv();
    let u1 = e * s_inv;
    let u2 = r * s_inv;
    let g = AffinePoint::new(P256_G[0], P256_G[1]);
    let r_point_proj = ProjectivePoint::from(g).scalar_mult(u1)
        + ProjectivePoint::from(public_key).scalar_mult(u2);
    let r_point_aff = AffinePoint::from(r_point_proj);

    let Some([r_x, r_y]) = r_point_aff.coordinates() else {
        return Err(anyhow!(
            "invalid signature, recomputation of R produced point at infinity"
        ));
    };
    // Sanity check: r = R.x
    if embed_scalar_in_base_field(r) != r_x {
        return Err(anyhow!(
            "invalid signature, recomputed R had incorrect x-coordinate"
        ));
    }

    *witness.r_x = r_x;
    *witness.r_y = r_y;
    *witness.r_x_inverse = r_x.mul_inv();
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
    use crate::{
        Sha256Digest,
        fields::{FieldElement, fieldp256_scalar::FieldP256Scalar},
        mdoc_zk::ec::{AffinePoint, P256_G, ProjectivePoint, Signature},
    };
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

    #[wasm_bindgen_test(unsupported = test)]
    fn test_decode_signature() {
        let sig = Signature::decode(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ])
        .unwrap();
        assert_eq!(sig.r, FieldP256Scalar::ONE);
        assert_eq!(sig.s, FieldP256Scalar::ONE + FieldP256Scalar::ONE);

        let error_message = Signature::decode(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ])
        .err()
        .unwrap()
        .to_string();
        assert!(error_message.contains("r is zero"));

        let error_message = Signature::decode(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .err()
        .unwrap()
        .to_string();
        assert!(error_message.contains("s is zero"));

        let error_message = Signature::decode(&[0xff; 64]).err().unwrap().to_string();
        assert!(error_message.contains("not less than the modulus"));

        let error_message = Signature::decode(&[0xab, 0xcd]).err().unwrap().to_string();
        assert!(error_message.contains("length is incorrect"));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_point_conversion() {
        let g_affine = AffinePoint::new(P256_G[0], P256_G[1]);
        let g_proj = ProjectivePoint::from(g_affine);
        assert_eq!(AffinePoint::from(g_proj), g_affine);

        let o_affine = AffinePoint::infinity();
        let o_proj = ProjectivePoint::from(o_affine);
        assert_eq!(AffinePoint::from(o_proj), o_affine);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_addition_consistent() {
        let g_affine = AffinePoint::new(P256_G[0], P256_G[1]);
        let g = ProjectivePoint::from(g_affine);
        let two_g = g + g;
        let three_g = two_g + g;
        let four_g = three_g + g;
        let five_g = four_g + g;
        let six_g = five_g + g;

        assert_eq!(AffinePoint::from(g.double()), AffinePoint::from(two_g));
        assert_eq!(AffinePoint::from(two_g.double()), AffinePoint::from(four_g));
        assert_eq!(
            AffinePoint::from(three_g.double()),
            AffinePoint::from(six_g)
        );

        assert_eq!(
            AffinePoint::from(three_g + two_g),
            AffinePoint::from(five_g)
        );

        assert_eq!(AffinePoint::from(g + g_affine), AffinePoint::from(two_g));
        assert_eq!(
            AffinePoint::from(three_g + AffinePoint::from(two_g)),
            AffinePoint::from(five_g)
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_scmul() {
        let g_affine = AffinePoint::new(P256_G[0], P256_G[1]);
        let g = ProjectivePoint::from(g_affine);

        let unity_scmul = g.scalar_mult(Sha256Digest([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]));
        assert_eq!(AffinePoint::from(unity_scmul), g_affine);

        let two_g = g + g;
        let double_scmul = g.scalar_mult(Sha256Digest([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]));
        assert_eq!(AffinePoint::from(double_scmul), AffinePoint::from(two_g));

        let result_1 = g.scalar_mult(-FieldP256Scalar::ONE);
        assert_eq!(
            AffinePoint::from(result_1 + g_affine),
            AffinePoint::infinity()
        );

        let result_2 = g.scalar_mult(Sha256Digest([
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x50,
        ]));
        assert_eq!(
            AffinePoint::from(result_2 + g_affine),
            AffinePoint::infinity()
        );
    }
}
