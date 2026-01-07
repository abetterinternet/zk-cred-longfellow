//! Elliptic curve cryptography utilities.

use crate::{
    Codec,
    fields::{CodecFieldElement, FieldElement, fieldp256::FieldP256},
};
use anyhow::anyhow;
use subtle::{Choice, ConditionallySelectable};

/// Decodes an encoded P-256 elliptic curve point.
///
/// Returns `None` if the encoding represents the point at infinity.
///
/// See <https://www.secg.org/sec1-v2.pdf#page=17>.
pub(super) fn decode_point(bytes: &[u8]) -> Result<Option<(FieldP256, FieldP256)>, anyhow::Error> {
    if bytes == [0] {
        // Point at infinity.
        Ok(None)
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
        Ok(Some((x, y)))
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
        Ok(Some((x, y)))
    } else {
        Err(anyhow!(
            "encoded elliptic curve point has an invalid length"
        ))
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

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::ec::decode_point;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_decode_point() {
        // Identity element
        assert_eq!(decode_point(&[0]).unwrap(), None);
        // Generator point, compressed form
        let gen_1 = decode_point(&[
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96,
        ])
        .unwrap()
        .unwrap();
        // Generator point, uncompressed form
        let gen_2 = decode_point(&[
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ])
        .unwrap()
        .unwrap();
        assert_eq!(gen_1, gen_2);
        // Off-curve point, uncompressed form
        decode_point(&[
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap_err();
        // Coordinate beyond field modulus
        decode_point(&[
            0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
        ])
        .unwrap_err();
        // Invalid encoded length
        decode_point(&[0, 0]).unwrap_err();
        // Invalid prefixes
        decode_point(&[0x5; 33]).unwrap_err();
        decode_point(&[0x5; 65]).unwrap_err();
    }
}
