//! Parsing of COSE CBOR structures.

use crate::mdoc_zk::mdoc::ByteString;
use serde::{
    Deserialize, Serialize,
    de::{Error, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
};
use std::fmt;

/// COSE_Sign1 from RFC 9052.
#[derive(Debug, Deserialize)]
#[serde(from = "CoseSign1Tuple")]
pub(super) struct CoseSign1 {
    /// Protected header parameters.
    ///
    /// If there are no protected header parameters, this will be the empty byte string. Otherwise,
    /// it will be the CBOR encoding of a map.
    #[allow(unused)]
    pub(super) protected: Vec<u8>,
    /// Unprotected header parameters.
    pub(super) unprotected: CoseUnprotectedHeaders,
    /// The message that is the subject of the signature.
    ///
    /// This will be `None` for detached signatures.
    pub(super) payload: Option<Vec<u8>>,
    /// The signature itself.
    pub(super) signature: Vec<u8>,
}

impl From<CoseSign1Tuple> for CoseSign1 {
    fn from(CoseSign1Tuple(protected, unprotected, payload, signature): CoseSign1Tuple) -> Self {
        Self {
            protected,
            unprotected,
            payload,
            signature,
        }
    }
}

/// Helper type for deserializing COSE_Sign1 from a CBOR list.
#[derive(Deserialize)]
struct CoseSign1Tuple(Vec<u8>, CoseUnprotectedHeaders, Option<Vec<u8>>, Vec<u8>);

/// Unprotected headers from a COSE_Sign1 message.
///
/// This is defined as a map from numbers or strings to various kinds of values. We only parse the
/// kinds of parameters that we care about.
#[derive(Debug)]
pub(super) struct CoseUnprotectedHeaders {
    pub(super) x5chain: Option<CoseX509>,
}

impl<'de> Deserialize<'de> for CoseUnprotectedHeaders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CoseUnprotectedHeadersVisitor)
    }
}

struct CoseUnprotectedHeadersVisitor;

impl<'de> Visitor<'de> for CoseUnprotectedHeadersVisitor {
    type Value = CoseUnprotectedHeaders;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut x5chain = None;

        while let Some(key) = map.next_key()? {
            match key {
                CoseLabel::Number(header_parameters::X5CHAIN) => {
                    x5chain = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(CoseUnprotectedHeaders { x5chain })
    }
}

/// Map keys used throughout COSE.
#[derive(Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(untagged)]
enum CoseLabel {
    Number(i64),
    String(String),
}

/// Labels for COSE header parameters.
///
/// See <https://www.iana.org/assignments/cose/cose.xhtml#header-parameters>.
mod header_parameters {
    /// The label for the alg header parameter.
    pub(super) const ALG: i64 = 1;
    /// The label for the x5chain header parameter.
    pub(super) const X5CHAIN: i64 = 33;
}

/// COSE_X509 from RFC 9360.
///
/// This can be either `bstr` or `[ bstr ]` on the wire. We represent both cases as a nested vector.
/// Note that we have to jump through some hoops to detect the difference via serde.
#[derive(Debug)]
pub(super) struct CoseX509(pub(super) Vec<Vec<u8>>);

impl<'de> Deserialize<'de> for CoseX509 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(CoseX509Visitor).map(Self)
    }
}

struct CoseX509Visitor;

impl<'de> Visitor<'de> for CoseX509Visitor {
    type Value = Vec<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array or a list of byte arrays")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(vec![v.to_vec()])
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(vec![v])
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let size_hint = seq.size_hint();
        match seq.next_element()? {
            Some(ByteOrBytes::Byte(byte)) => {
                let mut inner = Vec::with_capacity(size_hint.unwrap_or_default());
                inner.push(byte);
                while let Some(byte) = seq.next_element::<u8>()? {
                    inner.push(byte);
                }
                Ok(vec![inner])
            }
            Some(ByteOrBytes::Bytes(bytes)) => {
                let mut output = Vec::with_capacity(size_hint.unwrap_or_default());
                output.push(bytes);
                while let Some(bytes) = seq.next_element::<Vec<u8>>()? {
                    output.push(bytes);
                }
                Ok(output)
            }
            None => Ok(Vec::new()),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ByteOrBytes {
    Byte(u8),
    Bytes(Vec<u8>),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) struct CoseKey {
    pub(super) x: Vec<u8>,
    pub(super) y: Vec<u8>,
}

impl<'de> Deserialize<'de> for CoseKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CoseKeyVisitor)
    }
}

struct CoseKeyVisitor;

impl<'de> Visitor<'de> for CoseKeyVisitor {
    type Value = CoseKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut kty_seen = false;
        let mut crv_seen = false;
        let mut x = None;
        let mut y = None;

        while let Some(key) = map.next_key::<CoseLabel>()? {
            match key {
                CoseLabel::Number(key_parameters::KTY) => {
                    if kty_seen {
                        return Err(A::Error::duplicate_field("kty"));
                    }
                    kty_seen = true;
                    let key_type = map.next_value::<CoseLabel>()?;
                    let CoseLabel::Number(key_types::EC2) = key_type else {
                        return Err(A::Error::custom("unsupported COSE key type"));
                    };
                }
                CoseLabel::Number(key_parameters::KTY_2_CRV) => {
                    if crv_seen {
                        return Err(A::Error::duplicate_field("crv"));
                    }
                    crv_seen = true;
                    let curve = map.next_value::<CoseLabel>()?;
                    let CoseLabel::Number(elliptic_curves::P256) = curve else {
                        return Err(A::Error::custom("unsupported elliptic curve"));
                    };
                }
                CoseLabel::Number(key_parameters::KTY_2_X) => {
                    if x.is_some() {
                        return Err(A::Error::duplicate_field("x"));
                    }
                    x = Some(map.next_value()?);
                }
                CoseLabel::Number(key_parameters::KTY_2_Y) => {
                    if y.is_some() {
                        return Err(A::Error::duplicate_field("y"));
                    }
                    y = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        if !kty_seen {
            return Err(A::Error::missing_field("kty"));
        }
        if !crv_seen {
            return Err(A::Error::missing_field("crv"));
        }

        Ok(CoseKey {
            x: x.ok_or_else(|| A::Error::missing_field("x"))?,
            y: y.ok_or_else(|| A::Error::missing_field("y"))?,
        })
    }
}

/// Labels for COSE key parameters.
///
/// See <https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters> and
/// <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>.
mod key_parameters {
    /// The label for the key type parameter.
    pub(super) const KTY: i64 = 1;
    /// The label for the curve identifier parameter.
    pub(super) const KTY_2_CRV: i64 = -1;
    /// The label for the x-coordinate of the private key.
    pub(super) const KTY_2_X: i64 = -2;
    /// The label for the y-coordinate of the private key.
    pub(super) const KTY_2_Y: i64 = -3;
}

/// Labels for COSE key types.
///
/// See <https://www.iana.org/assignments/cose/cose.xhtml#key-type>.
mod key_types {
    /// The label for elliptic curve keys with x- and y-coordinates.
    pub(super) const EC2: i64 = 2;
}

/// Labels for elliptic curves.
///
/// See <https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves>.
mod elliptic_curves {
    /// The label for P-256.
    pub(super) const P256: i64 = 1;
}

/// Sig_structure from RFC 9052.
#[derive(Clone, Serialize)]
#[serde(into = "SigStructureTuple")]
pub(super) struct SigStructure {
    pub(super) body_protected: ByteString,
    pub(super) external_aad: ByteString,
    pub(super) payload: ByteString,
}

#[derive(Serialize)]
struct SigStructureTuple(&'static str, ByteString, ByteString, ByteString);

impl From<SigStructure> for SigStructureTuple {
    fn from(sig_structure: SigStructure) -> Self {
        let SigStructure {
            body_protected,
            external_aad,
            payload,
        } = sig_structure;
        Self("Signature1", body_protected, external_aad, payload)
    }
}

/// Protected headers encoding just an algorithm identifier, with value ES256.
pub(super) struct ProtectedHeadersEs256;

impl Serialize for ProtectedHeadersEs256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&header_parameters::ALG, &algorithms::EC256)?;
        map.end()
    }
}

/// Labels for COSE algorithms.
///
/// See <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>.
mod algorithms {
    /// The label for the ECDSA w/ SHA-256 algorithm.
    pub(super) const EC256: i64 = -7;
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::mdoc::{
        CoseKey, CoseSign1,
        cose::{CoseLabel, CoseUnprotectedHeaders, CoseX509, ProtectedHeadersEs256},
    };
    use assert_matches::assert_matches;
    use ciborium::{Value, cbor};
    use serde::de::DeserializeOwned;
    use std::io;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_cose_sign1() {
        let parsed = round_trip::<CoseSign1>(cbor!([b"", {}, b"payload", b"signature"]));
        assert_eq!(parsed.protected, b"");
        assert!(parsed.unprotected.x5chain.is_none());
        assert_eq!(parsed.payload.unwrap(), b"payload");
        assert_eq!(parsed.signature, b"signature");

        let parsed = round_trip::<CoseSign1>(cbor!([b"", {}, null, b"signature"]));
        assert!(parsed.payload.is_none());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_headers() {
        assert!(
            round_trip::<CoseUnprotectedHeaders>(cbor!({}))
                .x5chain
                .is_none()
        );
        assert!(
            round_trip::<CoseUnprotectedHeaders>(cbor!({-5 => {}}))
                .x5chain
                .is_none()
        );
        assert!(
            round_trip::<CoseUnprotectedHeaders>(cbor!({"other" => {}}))
                .x5chain
                .is_none()
        );
        assert_eq!(
            round_trip::<CoseUnprotectedHeaders>(cbor!({33 => b"cert"}))
                .x5chain
                .unwrap()
                .0,
            vec![b"cert"]
        );
    }

    #[wasm_bindgen_test(unsupported  =test)]
    fn test_label() {
        assert_matches!(round_trip::<>(cbor!(-1)), CoseLabel::Number(number) => assert_eq!(number, -1));
        assert_matches!(round_trip::<>(cbor!("other")), CoseLabel::String(string) => assert_eq!(string, "other"));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_cose_x509() {
        assert_eq!(round_trip::<CoseX509>(cbor!(b"test")).0, [b"test"]);
        assert_eq!(
            round_trip::<CoseX509>(cbor!([b't', b'e', b's', b't'])).0,
            [b"test"]
        );
        assert_eq!(round_trip::<CoseX509>(cbor!([b"test"])).0, [b"test"]);
        assert_eq!(
            round_trip::<CoseX509>(cbor!([b"cert1", b"cert2"])).0,
            [b"cert1", b"cert2"]
        );
        assert!(round_trip::<CoseX509>(cbor!([])).0.is_empty());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_cose_key() {
        let key = round_trip::<CoseKey>(cbor!({
            1 => 2, // kty = EC2
            -1 => 1, // crv = P-256
            -2 => b"x", // x-coordinate
            -3 => b"y", // y-coordinate
        }));
        assert_eq!(key.x, b"x");
        assert_eq!(key.y, b"y");

        // Wrong values for expected key parameters.
        round_trip_err::<CoseKey>(cbor!({
            1 => 1,
            -1 => 1,
            -2 => b"",
            -3 => b"",
        }));
        round_trip_err::<CoseKey>(cbor!({
            1 => 2,
            -1 => 2,
            -2 => b"",
            -3 => b"",
        }));

        // Extra key-value pair.
        round_trip_err::<CoseKey>(cbor!({
            1 => 2,
            -1 => 2,
            -2 => b"",
            -3 => b"",
            "other" => b"other",
            "map" => {
                1 => 2,
            },
        }));

        // Missing key parameters.
        round_trip_err::<CoseKey>(cbor!({
            -1 => 1,
            -2 => b"",
            -3 => b"",
        }));
        round_trip_err::<CoseKey>(cbor!({
            1 => 2,
            -2 => b"",
            -3 => b"",
        }));
        round_trip_err::<CoseKey>(cbor!({
            1 => 2,
            -1 => 1,
            -3 => b"",
        }));
        round_trip_err::<CoseKey>(cbor!({
            1 => 2,
            -1 => 1,
            -2 => b"",
        }));
    }

    fn round_trip<T: DeserializeOwned>(result: Result<Value, ciborium::value::Error>) -> T {
        let value = result.unwrap();
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer).unwrap();
        ciborium::from_reader(buffer.as_slice()).unwrap()
    }

    fn round_trip_err<T: DeserializeOwned>(
        result: Result<Value, ciborium::value::Error>,
    ) -> ciborium::de::Error<io::Error> {
        let value = result.unwrap();
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer).unwrap();
        ciborium::from_reader::<T, _>(buffer.as_slice())
            .err()
            .unwrap()
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_protected_headers_es256() {
        let mut buffer = Vec::new();
        ciborium::into_writer(&ProtectedHeadersEs256, &mut buffer).unwrap();
        assert_eq!(buffer, b"\xa1\x01\x26");
    }
}
