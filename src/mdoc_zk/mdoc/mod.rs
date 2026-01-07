//! Parsing of mdoc CBOR structures.

use crate::{
    fields::fieldp256::FieldP256,
    mdoc_zk::{
        ec::decode_point,
        mdoc::cose::{CoseKey, CoseSign1, ProtectedHeadersEs256, SigStructure},
        sha256::run_sha256,
    },
};
use anyhow::{Context, anyhow};
use ciborium::{Value, tag};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use std::{collections::HashMap, ops::Deref};
use x509_cert::{
    certificate::{CertificateInner, Raw},
    der::{Decode, SliceReader},
    spki::ObjectIdentifier,
};

mod cose;

/// Fields parsed from an mdoc credential.
pub(super) struct Mdoc {
    // Issuer signature information.
    pub(super) issuer_public_key_x: FieldP256,
    pub(super) issuer_public_key_y: FieldP256,
    #[allow(unused)]
    pub(super) issuer_signature_payload: Vec<u8>,
    #[allow(unused)]
    pub(super) issuer_signature: Vec<u8>,

    // Validity information.
    #[allow(unused)]
    pub(super) valid_from: String,
    #[allow(unused)]
    pub(super) valid_until: String,

    // Authentication of the mdoc.
    #[allow(unused)]
    pub(super) device_public_key_x: FieldP256,
    #[allow(unused)]
    pub(super) device_public_key_y: FieldP256,
    pub(super) doc_type: String,
    pub(super) device_name_spaces_bytes: Vec<u8>,
    #[allow(unused)]
    pub(super) device_signature: Vec<u8>,

    // Attributes.
    #[allow(unused)]
    pub(super) attribute_preimages: HashMap<String, Vec<Vec<u8>>>,
    #[allow(unused)]
    pub(super) attribute_digests: HashMap<String, HashMap<usize, Vec<u8>>>,
}

pub(super) fn parse_device_response(bytes: &[u8]) -> Result<Mdoc, anyhow::Error> {
    let device_response = ciborium::from_reader::<DeviceResponse, _>(bytes)
        .context("could not parse DeviceResponse")?;

    if device_response.status != 0 {
        return Err(anyhow!(
            "status of DeviceResponse was {}",
            device_response.status
        ));
    }

    let Some(documents) = device_response
        .documents
        .filter(|documents| !documents.is_empty())
    else {
        if device_response
            .zk_documents
            .is_some_and(|zk_documents| !zk_documents.is_empty())
        {
            return Err(anyhow!(
                "DeviceResponse contains a ZkDocument, not a Document"
            ));
        }
        return Err(anyhow!("DeviceResponse does not contain any Document"));
    };

    if documents.len() != 1 {
        return Err(anyhow!("DeviceResponse contains multiple Documents"));
    }
    let document = documents.into_iter().next().unwrap();

    let certificate_bytes = document
        .issuer_signed
        .issuer_auth
        .unprotected
        .x5chain
        .as_ref()
        .ok_or_else(|| anyhow!("missing certificate chain"))?
        .0
        .first()
        .ok_or_else(|| anyhow!("empty certificate chain"))?;
    let certificate = CertificateInner::<Raw>::decode(
        &mut SliceReader::new(certificate_bytes.as_slice()).context("certificate is too long")?,
    )
    .context("could not parse issuer certificate")?;

    let spki = &certificate.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(anyhow!("issuer certificate has wrong public key algorithm"));
    }
    let Some(public_key_params) = spki.algorithm.parameters.as_ref() else {
        return Err(anyhow!(
            "issuer certificate subject public key information is missing parameters"
        ));
    };
    let curve_oid = public_key_params
        .decode_as::<ObjectIdentifier>()
        .context("could not decode public key algorithm parameters")?;
    if curve_oid != OID_CURVE_P256 {
        return Err(anyhow!("issuer public key uses wrong elliptic curve"));
    }

    let public_key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("public key length is not octet aligned"))?;
    let (issuer_public_key_x, issuer_public_key_y) = decode_point(public_key_bytes)?
        .ok_or_else(|| anyhow!("issuer public key was the point at infinity"))?;

    let msob = ciborium::from_reader::<EncodedCbor, _>(
        document
            .issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("issuer signature is missing payload"))?
            .as_slice(),
    )
    .context("could not parse MobileSecurityObjectBytes")?;
    let mso = ciborium::from_reader::<MobileSecurityObject, _>(msob.0.as_slice())
        .context("could not parse MobileSecurityObject")?;
    // TODO: Need to use ciborium-ll to parse the MSO instead, so that we can get byte offsets of
    // its fields.

    let DeviceAuth::DeviceSignature(device_signature) = document.device_signed.device_auth else {
        return Err(anyhow!("DeviceAuth used MAC instead of signature"));
    };

    let attribute_preimages = document
        .issuer_signed
        .name_spaces
        .ok_or_else(|| anyhow!("issuer signed namespaces are missing"))?
        .into_iter()
        .map(|(namespace, items)| {
            (
                namespace,
                items.into_iter().map(|item| item.0.0).collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();

    // RFC 8152 encodes coordinates for EC2 keys according to SEC 1, in big-endian form.
    let mut device_public_key_x_bytes = <[u8; 32]>::try_from(mso.device_key_info.device_key.x)
        .ok()
        .context("device public key x-coordinate is of the wrong length")?;
    device_public_key_x_bytes.reverse();
    let device_public_key_x = FieldP256::try_from(device_public_key_x_bytes.as_slice())
        .context("device public key x-coordinate is invalid")?;
    let mut device_public_key_y_bytes = <[u8; 32]>::try_from(mso.device_key_info.device_key.y)
        .ok()
        .context("device public key y-coordinate is of the wrong length")?;
    device_public_key_y_bytes.reverse();
    let device_public_key_y = FieldP256::try_from(device_public_key_y_bytes.as_slice())
        .context("device public key y-coordinate is invalid")?;

    Ok(Mdoc {
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature_payload: document.issuer_signed.issuer_auth.payload.unwrap(),
        issuer_signature: document.issuer_signed.issuer_auth.signature,
        valid_from: mso.validity_info.valid_from.0,
        valid_until: mso.validity_info.valid_until.0,
        device_public_key_x,
        device_public_key_y,
        doc_type: document.doc_type,
        device_name_spaces_bytes: document.device_signed.name_spaces.0.0,
        device_signature: device_signature.signature,
        attribute_preimages,
        attribute_digests: mso.value_digests,
    })
}

/// The algorithm identifier for the elliptic curve public key type, from ANSI X9.62.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// The curve identifier for P-256/prime256v1/secp256r1.
const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// DeviceResponse from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceResponse {
    documents: Option<Vec<Document>>,
    zk_documents: Option<Vec<ZkDocument>>,
    status: u64,
}

/// Document from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    doc_type: String,
    issuer_signed: IssuerSigned,
    device_signed: DeviceSigned,
}

/// IssuerSigned from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuerSigned {
    issuer_auth: CoseSign1,
    name_spaces: Option<HashMap<String, Vec<EncodedCbor>>>,
}

/// DeviceSigned from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSigned {
    name_spaces: EncodedCbor,
    device_auth: DeviceAuth,
}

/// DeviceAuth from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum DeviceAuth {
    DeviceSignature(CoseSign1),
    DeviceMac(IgnoredAny),
}

/// ZkDocument from ISO 18013-5.
#[derive(Debug, Deserialize)]
struct ZkDocument {}

/// The encoded-cbor type from the CDDL standard prelude, in RFC 8610.
///
/// This is used for MobileSecurityObjectBytes, DeviceNameSpacesBytes, DeviceAuthenticationBytes,
/// and IssuerSignedItemBytes from ISO 18013-5.
type EncodedCbor = tag::Required<ByteString, 24>;

/// MobileSecurityObject from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobileSecurityObject {
    value_digests: HashMap<String, HashMap<usize, Vec<u8>>>,
    device_key_info: DeviceKeyInfo,
    validity_info: ValidityInfo,
}

/// DeviceKeyInfo from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceKeyInfo {
    device_key: CoseKey,
}

/// ValidityInfo from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidityInfo {
    valid_from: tag::Required<String, 0>,
    valid_until: tag::Required<String, 0>,
}

/// Compute the hash of the session transcript, for the mdoc signature.
pub(super) fn compute_session_transcript_hash(
    mdoc: &Mdoc,
    transcript: &[u8],
) -> Result<FieldP256, anyhow::Error> {
    let session_transcript = ciborium::from_reader::<Value, _>(transcript)
        .context("could not parse SessionTranscript")?;

    let device_authentication = DeviceAuthentication {
        session_transcript,
        doc_type: mdoc.doc_type.clone(),
        device_name_spaces_bytes: tag::Required(ByteString(mdoc.device_name_spaces_bytes.clone())),
    };
    let mut buffer = Vec::new();
    ciborium::into_writer(&device_authentication, &mut buffer)
        .context("could not encode DeviceAuthentication")?;

    let device_authentication_bytes: EncodedCbor = tag::Required(ByteString(buffer));
    let mut payload = ByteString(Vec::new());
    ciborium::into_writer(&device_authentication_bytes, &mut payload.0)
        .context("could not encode DeviceAuthenticationBytes")?;

    let mut body_protected = ByteString(Vec::new());
    ciborium::into_writer(&ProtectedHeadersEs256, &mut body_protected.0)
        .context("could not encode protected headers")?;

    let sig_structure = SigStructure {
        body_protected,
        external_aad: ByteString(Vec::new()),
        payload,
    };
    let mut message = Vec::new();
    ciborium::into_writer(&sig_structure, &mut message)
        .context("could not encode Sig_structure")?;

    let mut digest = run_sha256(message.as_slice());
    // SEC 1 uses big-endian encoding, but fiat-crypto uses little-endian encoding.
    digest.reverse();

    // TODO: should we reduce this in the scalar field before embedding it in the base field?
    // This may avoid spurious failures with probability 2^-32.
    //
    // Related issue: https://github.com/google/longfellow-zk/issues/120
    FieldP256::try_from(&digest).context(
        "could not convert session transcript hash to a field element \
        (see https://github.com/google/longfellow-zk/issues/120)",
    )
}

/// DeviceAuthentication from ISO 18013-5.
#[derive(Clone, Serialize)]
#[serde(into = "DeviceAuthenticationTuple")]
struct DeviceAuthentication {
    session_transcript: Value,
    doc_type: String,
    device_name_spaces_bytes: EncodedCbor,
}

#[derive(Serialize)]
struct DeviceAuthenticationTuple(&'static str, Value, String, EncodedCbor);

impl From<DeviceAuthentication> for DeviceAuthenticationTuple {
    fn from(device_authentication: DeviceAuthentication) -> Self {
        let DeviceAuthentication {
            session_transcript,
            doc_type,
            device_name_spaces_bytes,
        } = device_authentication;
        Self(
            "DeviceAuthentication",
            session_transcript,
            doc_type,
            device_name_spaces_bytes,
        )
    }
}

/// Helper type that represents a byte string.
///
/// This is necessary because `Vec<u8>` gets serialized as a list of unsigned integers by default.
/// The byte string tag is only emitted by the `serialize_bytes()` serializer method. The only
/// `Serialize` impls that `serde` provide which use this are for `CStr` and `CString`.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct ByteString(pub(super) Vec<u8>);

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl Deref for ByteString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::mdoc::ByteString;
    use serde_test::{Token, assert_ser_tokens};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_byte_string() {
        let byte_string = ByteString(b"hello".to_vec());

        assert_ser_tokens(&byte_string, &[Token::Bytes(b"hello")]);

        let mut buffer = Vec::new();
        ciborium::into_writer(&byte_string, &mut buffer).unwrap();
        assert_eq!(buffer, b"\x45hello");
    }
}
