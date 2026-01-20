//! Parsing of mdoc CBOR structures.

use crate::{
    Sha256Digest,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    mdoc_zk::{
        BitPlucker,
        ec::{AffinePoint, Signature},
        layout::{SHA_256_CREDENTIAL_WITNESS_WIRES, Sha256Witness},
        mdoc::cose::{CoseKey, CoseSign1, ProtectedHeadersEs256, SigStructure},
        sha256::{Sha256Result, run_sha256, run_sha256_witnessed},
    },
};
use anyhow::{Context, anyhow};
use ciborium::{Value, tag};
use ciborium_ll::{Decoder, Header};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use std::{
    collections::{HashMap, hash_map},
    ops::Deref,
};
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
    pub(super) issuer_signature_payload: Vec<u8>,
    pub(super) issuer_signature: Signature,

    // Validity information.
    #[allow(unused)]
    pub(super) valid_from: String,
    #[allow(unused)]
    pub(super) valid_until: String,

    // Authentication of the mdoc.
    pub(super) device_public_key: AffinePoint,
    pub(super) doc_type: String,
    pub(super) device_name_spaces_bytes: Vec<u8>,
    pub(super) device_signature: Signature,

    // Attributes.
    #[allow(unused)]
    pub(super) attribute_preimages: HashMap<String, Vec<Vec<u8>>>,
    #[allow(unused)]
    pub(super) attribute_digests: HashMap<String, HashMap<u64, Vec<u8>>>,

    pub(super) mso_offsets: MsoOffsets,
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
    let [issuer_public_key_x, issuer_public_key_y] = AffinePoint::decode(public_key_bytes)?
        .coordinates()
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
    let (mso, mso_offsets) =
        parse_mso(msob.0.as_slice()).context("could not parse MobileSecurityObject")?;

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
    let device_public_key = AffinePoint::new(device_public_key_x, device_public_key_y);

    let issuer_signature = Signature::decode(&document.issuer_signed.issuer_auth.signature)
        .context("invalid issuer signature")?;
    let device_signature =
        Signature::decode(&device_signature.signature).context("invalid device signature")?;

    Ok(Mdoc {
        issuer_public_key_x,
        issuer_public_key_y,
        issuer_signature_payload: document.issuer_signed.issuer_auth.payload.unwrap(),
        issuer_signature,
        valid_from: mso.validity_info.valid_from.0,
        valid_until: mso.validity_info.valid_until.0,
        device_public_key,
        doc_type: document.doc_type,
        device_name_spaces_bytes: document.device_signed.name_spaces.0.0,
        device_signature,
        attribute_preimages,
        attribute_digests: mso.value_digests,
        mso_offsets,
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
#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize, PartialEq, Eq))]
#[cfg_attr(test, serde(rename_all = "camelCase"))]
struct MobileSecurityObject {
    value_digests: HashMap<String, HashMap<u64, Vec<u8>>>,
    device_key_info: DeviceKeyInfo,
    validity_info: ValidityInfo,
}

/// Offsets of fields within the `MobileSecurityObject` structure.
#[derive(Debug)]
pub(super) struct MsoOffsets {
    /// Offset of the validFrom field.
    pub(super) valid_from: usize,
    /// Offset of the validUntil field.
    pub(super) valid_until: usize,
    /// Offset of the deviceKeyInfo field.
    pub(super) device_key_info: usize,
    /// Offset of the valueDigests field.
    pub(super) value_digests: usize,
    /// Offsets of the individual value digests.
    ///
    /// The outer `HashMap` is keyed by namespace, and the inner `HashMap` is keyed by `DigestID`.
    /// The values are offsets for each digest.
    #[allow(unused)]
    pub(super) value_digests_items: HashMap<String, HashMap<u64, usize>>,
}

/// DeviceKeyInfo from ISO 18013-5.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "camelCase")]
struct DeviceKeyInfo {
    device_key: CoseKey,
}

/// ValidityInfo from ISO 18013-5.
#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize, PartialEq, Eq))]
#[cfg_attr(test, serde(rename_all = "camelCase"))]
struct ValidityInfo {
    valid_from: tag::Required<String, TAG_TDATE>,
    valid_until: tag::Required<String, TAG_TDATE>,
}

/// The tag for the `tdate` type, as defined in the CDDL standard prelude, from RFC 8610.
const TAG_TDATE: u64 = 0;

/// Compute the hash of the session transcript, for the mdoc signature.
pub(super) fn compute_session_transcript_hash(
    mdoc: &Mdoc,
    transcript: &[u8],
) -> Result<Sha256Digest, anyhow::Error> {
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

    Ok(run_sha256(message.as_slice()))
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

/// Compute the hash of the credential, for the issuer signature.
///
/// This also returns the preimage of the hash, and writes SHA-256 witness values.
pub(super) fn compute_credential_hash<'a>(
    mdoc: &Mdoc,
    witness: &'a mut Sha256Witness<'a, SHA_256_CREDENTIAL_WITNESS_WIRES>,
    bit_plucker: &BitPlucker<4, Field2_128>,
) -> Result<Sha256Result, anyhow::Error> {
    let mut body_protected = ByteString(Vec::new());
    ciborium::into_writer(&ProtectedHeadersEs256, &mut body_protected.0)
        .context("could not encode protected headers")?;

    let sig_structure = SigStructure {
        body_protected,
        external_aad: ByteString(Vec::new()),
        payload: ByteString(mdoc.issuer_signature_payload.clone()),
    };
    let mut message = Vec::new();
    ciborium::into_writer(&sig_structure, &mut message)
        .context("could not encode Sig_structure")?;

    run_sha256_witnessed::<SHA_256_CREDENTIAL_WITNESS_WIRES>(
        message.as_slice(),
        witness,
        bit_plucker,
    )
}

/// Convert a SHA-256 hash from an ECDSA signature into a base field element for use as a circuit input.
pub(super) fn hash_to_field_element(mut digest: Sha256Digest) -> Result<FieldP256, anyhow::Error> {
    // SEC 1 uses big-endian encoding, but fiat-crypto uses little-endian encoding.
    digest.0.reverse();

    // TODO: should we reduce this in the scalar field before embedding it in the base field?
    // This may avoid spurious failures with probability 2^-32.
    //
    // Related issue: https://github.com/google/longfellow-zk/issues/120
    FieldP256::try_from(&digest.0)
}

/// Information about an attribute extracted from an mdoc.
#[derive(Debug, Clone)]
pub(super) struct ParsedAttribute {
    pub(super) _digest_id: u64,
    pub(super) _issuer_signed_item_data: Vec<u8>,
    pub(super) public_cbor_data: Vec<u8>,
    pub(super) _public_cbor_offset: usize,
}

/// Locate attributes by their identifier, and return their values and related witnesses.
pub(super) fn find_attributes(
    attribute_preimages: &HashMap<String, Vec<Vec<u8>>>,
    attribute_ids: &[String],
) -> Result<Vec<ParsedAttribute>, anyhow::Error> {
    let mut out: Vec<Option<ParsedAttribute>> = vec![None; attribute_ids.len()];
    let mut scratch = [0u8; 256];
    for bytes in attribute_preimages.values().flatten() {
        let mut decoder = Decoder::from(bytes.as_slice());

        let map_header = pull(&mut decoder, "reading attribute failed")?;
        let Header::Map(map_size_opt) = map_header else {
            return Err(anyhow!("IssuerSignedItem was not a map"));
        };

        // Version 6 of the circuit requires the elementIdentifier key-value pair to be immediately
        // followed by the elementValue key-value pair. We need to find those, and store an offset
        // in the middle of the first key-value pair. We also need to find the digestID, to
        // efficiently find the offset of the corresponding digest in the MSO.
        //
        // Read two items at a time. For maps of known size, stop after the expected number
        // of entries have been read. For maps of indefinite size, stop when encountering a `break`
        // header.

        let mut attribute_id = None;
        let mut digest_id = None;
        let mut public_cbor_data_and_offset = None;

        let mut last_entry_was_element_identifier = false;
        let mut last_value_offset = None;

        let mut entry_count = 0;
        loop {
            if let Some(map_size) = map_size_opt
                && entry_count >= map_size
            {
                break;
            }

            let key_header = pull(&mut decoder, "reading map entry key failed")?;
            let key_length = match key_header {
                Header::Text(key_length) => key_length,
                Header::Break => {
                    if map_size_opt.is_some() {
                        return Err(anyhow!("unexpected break in map of known size"));
                    }
                    break;
                }
                _ => {
                    return Err(anyhow!("unexpected map key type: {key_header:?}"));
                }
            };
            let key = slurp_string(&mut decoder, &mut scratch, key_length)
                .context("error reading key in IssuerSignedItem")?;

            let value_offset = decoder.offset();
            let value_header = pull(&mut decoder, "reading map entry value failed")?;
            let mut this_entry_element_identifier = false;
            match key.as_str() {
                "digestID" => {
                    if let Header::Positive(id) = value_header {
                        digest_id = Some(id)
                    } else {
                        return Err(anyhow!("unexpected value for digestID: {value_header:?}"));
                    }
                }
                "elementIdentifier" => {
                    this_entry_element_identifier = true;
                    if let Header::Text(len) = value_header {
                        attribute_id = Some(slurp_string(&mut decoder, &mut scratch, len)?);
                    } else {
                        return Err(anyhow!(
                            "unexpected value for elementIdentifier: {value_header:?}"
                        ));
                    }
                }
                "elementValue" => {
                    if !last_entry_was_element_identifier {
                        return Err(anyhow!(
                            "elementValue did not immediately follow elementIdentifier"
                        ));
                    }
                    skip_body(&mut decoder, &mut scratch, value_header)?;
                    let end_offset = decoder.offset();
                    let Some(start_offset) = last_value_offset else {
                        return Err(anyhow!("elementValue did not follow elementIdentifier"));
                    };
                    public_cbor_data_and_offset =
                        Some((bytes[start_offset..end_offset].to_vec(), start_offset));
                }
                _ => skip_body(&mut decoder, &mut scratch, value_header)?,
            }

            last_entry_was_element_identifier = this_entry_element_identifier;
            last_value_offset = Some(value_offset);

            entry_count += 1;
        }

        if decoder.offset() != bytes.len() {
            return Err(anyhow!("leftover data after reading IssuerSignedItem"));
        }

        for (opt, desired_attribute_id) in out.iter_mut().zip(attribute_ids) {
            if let Some(attribute_id) = &attribute_id
                && attribute_id == desired_attribute_id
            {
                let (public_cbor_data, public_cbor_offset) = public_cbor_data_and_offset
                    .take()
                    .ok_or_else(|| anyhow!("elementValue was missing for IssuerSignedItem"))?;
                *opt = Some(ParsedAttribute {
                    _digest_id: digest_id
                        .ok_or_else(|| anyhow!("digestID was missing for IssuerSignedItem"))?,
                    _issuer_signed_item_data: bytes.clone(),
                    public_cbor_data,
                    _public_cbor_offset: public_cbor_offset,
                });
                break;
            }
        }
    }

    out.into_iter()
        .zip(attribute_ids)
        .map(|(opt, attribute_id)| {
            opt.ok_or_else(|| anyhow!("attribute was not found in mdoc: {attribute_id}"))
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Advance the decoder past the body of an item, if applicable.
fn skip_body(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    header: Header,
) -> Result<(), anyhow::Error> {
    match header {
        Header::Positive(_) | Header::Negative(_) | Header::Float(_) | Header::Simple(_) => {}
        Header::Tag(_) => {
            let header = pull(decoder, "reading next item after tag failed")?;
            skip_body(decoder, scratch, header)?
        }
        Header::Break => return Err(anyhow!("unexpected break header when skipping value")),
        Header::Bytes(len) => {
            let mut segments = decoder.bytes(len);
            while let Some(mut segment) = segments
                .pull()
                .map_err(|e| anyhow!("error skipping past bytes: {e:?}"))?
            {
                while segment
                    .pull(scratch)
                    .map_err(|e| anyhow!("error skipping past bytes: {e:?}"))?
                    .is_some()
                {}
            }
        }
        Header::Text(len) => {
            let mut segments = decoder.text(len);
            while let Some(mut segment) = segments
                .pull()
                .map_err(|e| anyhow!("error skipping past text: {e:?}"))?
            {
                while segment
                    .pull(scratch)
                    .map_err(|e| anyhow!("error skipping past text: {e:?}"))?
                    .is_some()
                {}
            }
        }
        Header::Array(len) => {
            let mut element_count = 0;
            loop {
                if let Some(len) = len
                    && element_count >= len
                {
                    break;
                }

                let header = pull(decoder, "error skipping array")?;
                if let Header::Break = header {
                    if len.is_some() {
                        return Err(anyhow!("unexpected break in array of known size"));
                    }
                    break;
                }
                skip_body(decoder, scratch, header)?;

                element_count += 1;
            }
        }
        Header::Map(len) => {
            let mut entry_count = 0;
            loop {
                if let Some(len) = len
                    && entry_count >= len
                {
                    break;
                }

                let key_header = pull(decoder, "error skipping map")?;
                if let Header::Break = key_header {
                    if len.is_some() {
                        return Err(anyhow!("unexpected break in map of known size"));
                    }
                    break;
                }
                skip_body(decoder, scratch, key_header)?;

                let value_header = pull(decoder, "error skipping map")?;
                skip_body(decoder, scratch, value_header)?;

                entry_count += 1;
            }
        }
    }
    Ok(())
}

/// Read the body of a text string into a [`String`].
fn slurp_string(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    len: Option<usize>,
) -> Result<String, anyhow::Error> {
    let mut string = match len {
        Some(length) => String::with_capacity(length),
        None => String::new(),
    };
    let mut segments = decoder.text(len);
    while let Some(mut segment) = segments
        .pull()
        .map_err(|e| anyhow!("error reading string: {e:?}"))?
    {
        while let Some(chunk) = segment
            .pull(scratch)
            .map_err(|e| anyhow!("error reading string segment: {e:?}"))?
        {
            string.push_str(chunk);
        }
    }
    Ok(string)
}

/// Wrapper that calls `ciborium::Decoder::pull()` and converts errors.
fn pull(decoder: &mut Decoder<&[u8]>, error_reason: &str) -> Result<Header, anyhow::Error> {
    decoder.pull().map_err(|e| anyhow!("{error_reason}: {e:?}"))
}

/// Read the body of a byte string into a `Vec<u8>`.
fn slurp_bytes(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    len: Option<usize>,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut bytes = match len {
        Some(length) => Vec::with_capacity(length),
        None => Vec::new(),
    };
    let mut segments = decoder.bytes(len);
    while let Some(mut segment) = segments
        .pull()
        .map_err(|e| anyhow!("error reading bytes: {e:?}"))?
    {
        while let Some(chunk) = segment
            .pull(scratch)
            .map_err(|e| anyhow!("error reading bytes segment: {e:?}"))?
        {
            bytes.extend_from_slice(chunk);
        }
    }
    Ok(bytes)
}

/// Parses a MobileSecurityObject, and returns selected fields along with offsets of CBOR items.
fn parse_mso(data: &[u8]) -> Result<(MobileSecurityObject, MsoOffsets), anyhow::Error> {
    let mut scratch = [0u8; 256];
    let mut decoder = Decoder::from(data);

    let map_header = pull(&mut decoder, "reading MobileSecurityObject failed")?;
    let Header::Map(map_size_opt) = map_header else {
        return Err(anyhow!("MobileSecurityObject was not a map"));
    };

    // MSO fields.
    let mut valid_from = None;
    let mut valid_until = None;
    let mut device_key_info = None;
    let mut value_digests_items = HashMap::new();

    // Offsets to key-value pairs.
    let mut valid_from_offset = None;
    let mut valid_until_offset = None;
    let mut device_key_info_offset = None;
    let mut value_digests_offset = None;

    let mut value_digests_item_offsets = HashMap::new();

    let mut entry_count = 0;
    loop {
        if let Some(map_size) = map_size_opt
            && entry_count >= map_size
        {
            break;
        }

        let key_offset = decoder.offset();
        let key_header = pull(&mut decoder, "reading map entry key failed")?;
        let key_length = match key_header {
            Header::Text(key_length) => key_length,
            Header::Break => {
                if map_size_opt.is_some() {
                    return Err(anyhow!("unexpected break in map of known size"));
                }
                break;
            }
            _ => {
                return Err(anyhow!("unexpected map key type: {key_header:?}"));
            }
        };
        let key = slurp_string(&mut decoder, &mut scratch, key_length)
            .context("error reading key in MobileSecurityObject")?;

        let value_start_offset = decoder.offset();
        let value_header = pull(&mut decoder, "reading map entry value failed")?;
        match key.as_str() {
            "deviceKeyInfo" => {
                // Skip over the deviceKeyInfo value, then parse it again using serde. Doing this in
                // two passes is less efficient, but requires significantly less deserialization
                // code for the nested objects.
                device_key_info_offset = Some(key_offset);
                skip_body(&mut decoder, &mut scratch, value_header)?;
                let value_end_offset = decoder.offset();
                device_key_info = Some(
                    ciborium::from_reader::<DeviceKeyInfo, _>(
                        &data[value_start_offset..value_end_offset],
                    )
                    .context("parsing DeviceKeyInfo failed")?,
                );
            }
            "validityInfo" => {
                let Header::Map(len) = value_header else {
                    return Err(anyhow!(
                        "unexpected value for validityInfo: {value_header:?}"
                    ));
                };
                parse_validity_info(
                    &mut decoder,
                    &mut scratch,
                    len,
                    &mut valid_from,
                    &mut valid_from_offset,
                    &mut valid_until,
                    &mut valid_until_offset,
                )
                .context("error parsing ValidityInfo")?;
            }
            "valueDigests" => {
                value_digests_offset = Some(key_offset);
                let Header::Map(len) = value_header else {
                    return Err(anyhow!(
                        "unexpected value for valueDigests: {value_header:?}"
                    ));
                };
                parse_value_digests(
                    &mut decoder,
                    &mut scratch,
                    len,
                    &mut value_digests_items,
                    &mut value_digests_item_offsets,
                )
                .context("error parsing ValueDigests")?;
            }
            _ => skip_body(&mut decoder, &mut scratch, value_header)?,
        }

        entry_count += 1;
    }

    if decoder.offset() != data.len() {
        return Err(anyhow!("leftover data after reading MobileSecurityObject"));
    }

    let valid_from = valid_from.ok_or_else(|| anyhow!("validFrom missing from ValidityInfo"))?;
    let valid_from_offset =
        valid_from_offset.ok_or_else(|| anyhow!("validFrom missing from ValidityInfo"))?;
    let valid_until = valid_until.ok_or_else(|| anyhow!("validUntil missing from ValidityInfo"))?;
    let valid_until_offset =
        valid_until_offset.ok_or_else(|| anyhow!("validUntil missing from ValidityInfo"))?;
    let device_key_info = device_key_info
        .ok_or_else(|| anyhow!("deviceKeyInfo missing from MobileSecurityObject"))?;
    let device_key_info_offset = device_key_info_offset
        .ok_or_else(|| anyhow!("deviceKeyInfo missing from MobileSecurityObject"))?;
    let value_digests_offset = value_digests_offset
        .ok_or_else(|| anyhow!("valueDigests missing from MobileSecurityObject"))?;

    Ok((
        MobileSecurityObject {
            value_digests: value_digests_items,
            device_key_info,
            validity_info: ValidityInfo {
                valid_from,
                valid_until,
            },
        },
        MsoOffsets {
            valid_from: valid_from_offset,
            valid_until: valid_until_offset,
            device_key_info: device_key_info_offset,
            value_digests: value_digests_offset,
            value_digests_items: value_digests_item_offsets,
        },
    ))
}

/// Parses a `ValidityInfo` object.
///
/// This assigns the value and offset of `validFrom` and `validUntil` fields, through mutable
/// references.
///
/// This should be called after parsing a map header, and the header's length should be passed as
/// the `len` argument.
fn parse_validity_info(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    len: Option<usize>,
    valid_from: &mut Option<tag::Required<String, TAG_TDATE>>,
    valid_from_offset: &mut Option<usize>,
    valid_until: &mut Option<tag::Required<String, TAG_TDATE>>,
    valid_until_offset: &mut Option<usize>,
) -> Result<(), anyhow::Error> {
    let mut entry_count = 0;
    loop {
        if let Some(len) = len
            && entry_count >= len
        {
            break;
        }

        let key_offset = decoder.offset();
        let key_header = pull(decoder, "reading map entry key failed")?;
        let key_length = match key_header {
            Header::Text(key_length) => key_length,
            Header::Break => {
                if len.is_some() {
                    return Err(anyhow!("unexpected break in map of known size"));
                }
                break;
            }
            _ => {
                return Err(anyhow!("unexpected map key type: {key_header:?}"));
            }
        };
        let key = slurp_string(decoder, scratch, key_length)
            .context("error reading key in ValidityInfo")?;

        let value_header = pull(decoder, "reading map entry value failed")?;
        match key.as_str() {
            "validFrom" => {
                *valid_from_offset = Some(key_offset);
                *valid_from = Some(
                    parse_tdate(decoder, scratch, value_header)
                        .context("error parsing validFrom")?,
                );
            }
            "validUntil" => {
                *valid_until_offset = Some(key_offset);
                *valid_until = Some(
                    parse_tdate(decoder, scratch, value_header)
                        .context("error parsing validUntil")?,
                );
            }
            _ => skip_body(decoder, scratch, value_header)?,
        }

        entry_count += 1;
    }
    Ok(())
}

/// Parse a `tdate`.
///
/// This assumes the first header has already been read from the decoder, and verifies that it
/// represents the correct tag.
fn parse_tdate(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    header: Header,
) -> Result<tag::Required<String, TAG_TDATE>, anyhow::Error> {
    let Header::Tag(tag) = header else {
        return Err(anyhow!("unexpected value for tdate field: {header:?}"));
    };
    if tag != 0 {
        return Err(anyhow!("unexpected tag for tdate field: {tag}"));
    }

    let header = pull(decoder, "reading tdate failed")?;
    let Header::Text(len) = header else {
        return Err(anyhow!("unexpected value for tdate contents: {header:?}"));
    };
    Ok(tag::Required(slurp_string(decoder, scratch, len)?))
}

/// Parse `ValueDigests` and store both the digests and their offsets.
fn parse_value_digests(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    value_digests_len: Option<usize>,
    items: &mut HashMap<String, HashMap<u64, Vec<u8>>>,
    offsets: &mut HashMap<String, HashMap<u64, usize>>,
) -> Result<(), anyhow::Error> {
    let mut entry_count = 0;
    loop {
        if let Some(len) = value_digests_len
            && entry_count >= len
        {
            break;
        }

        let key_header = pull(decoder, "reading map entry key failed")?;
        let key_length = match key_header {
            Header::Text(key_length) => key_length,
            Header::Break => {
                if value_digests_len.is_some() {
                    return Err(anyhow!("unexpected break in map of known size"));
                }
                break;
            }
            _ => {
                return Err(anyhow!("unexpected map key type: {key_header:?}"));
            }
        };
        let key = slurp_string(decoder, scratch, key_length)
            .context("error reading key in ValueDigests")?;

        let value_header = pull(decoder, "reading map entry value failed")?;
        let Header::Map(digest_ids_len) = value_header else {
            return Err(anyhow!("unexpected value for DigestIDs: {value_header:?}"));
        };
        let hash_map::Entry::Vacant(items_vacant) = items.entry(key.clone()) else {
            return Err(anyhow!("duplicate namespace"));
        };
        let hash_map::Entry::Vacant(offsets_vacant) = offsets.entry(key) else {
            return Err(anyhow!("duplicate namespace"));
        };
        parse_digest_ids(
            decoder,
            scratch,
            digest_ids_len,
            items_vacant.insert(HashMap::new()),
            offsets_vacant.insert(HashMap::new()),
        )?;

        entry_count += 1;
    }
    Ok(())
}

/// Parse `DigestIDs` and store both the digests and their offsets.
fn parse_digest_ids(
    decoder: &mut Decoder<&[u8]>,
    scratch: &mut [u8],
    digest_ids_len: Option<usize>,
    items: &mut HashMap<u64, Vec<u8>>,
    offsets: &mut HashMap<u64, usize>,
) -> Result<(), anyhow::Error> {
    let mut entry_count = 0;
    loop {
        if let Some(len) = digest_ids_len
            && entry_count >= len
        {
            break;
        }

        let key_header = pull(decoder, "reading map entry key failed")?;
        let digest_id = match key_header {
            Header::Positive(digest_id) => digest_id,
            Header::Break => {
                if digest_ids_len.is_some() {
                    return Err(anyhow!("unexpected break in map of known size"));
                }
                break;
            }
            _ => {
                return Err(anyhow!("unexpected map key type: {key_header:?}"));
            }
        };

        let value_offset = decoder.offset();
        let value_header = pull(decoder, "reading map entry value failed")?;
        let Header::Bytes(len) = value_header else {
            return Err(anyhow!("unexpected value for Digest: {value_header:?}"));
        };
        let hash_map::Entry::Vacant(item_vacant) = items.entry(digest_id) else {
            return Err(anyhow!("duplicate DigestID"));
        };
        let hash_map::Entry::Vacant(offset_vacant) = offsets.entry(digest_id) else {
            return Err(anyhow!("duplicate DigestID"));
        };
        offset_vacant.insert(value_offset);
        item_vacant.insert(slurp_bytes(decoder, scratch, len).context("error reading Digest")?);

        entry_count += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{
        find_attributes,
        mdoc::{ByteString, EncodedCbor, MobileSecurityObject, parse_mso, skip_body},
        parse_device_response,
        tests::load_witness_test_vector,
    };
    use ciborium::{cbor, tag};
    use ciborium_ll::Decoder;
    use serde_test::{Token, assert_ser_tokens};
    use std::{collections::HashMap, io::Cursor};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_byte_string() {
        let byte_string = ByteString(b"hello".to_vec());

        assert_ser_tokens(&byte_string, &[Token::Bytes(b"hello")]);

        let mut buffer = Vec::new();
        ciborium::into_writer(&byte_string, &mut buffer).unwrap();
        assert_eq!(buffer, b"\x45hello");
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_skip_body() {
        let mut scratch = [0u8; 1024];
        for value_res in [
            cbor!({1 => null}),
            cbor!(null),
            cbor!(true),
            cbor!(-1),
            cbor!([["a"], {-1 => -1}]),
            cbor!(tag::Required::<_, 1>(["abc", "def"])),
            cbor!([ByteString(b"123".to_vec())]),
        ] {
            let value = value_res.unwrap();
            let mut buffer = Vec::new();
            ciborium::into_writer(&value, &mut buffer).unwrap();

            let mut decoder = Decoder::from(buffer.as_slice());
            let header = decoder.pull().unwrap();
            skip_body(&mut decoder, &mut scratch, header).unwrap();
            assert_eq!(
                decoder.offset(),
                buffer.len(),
                "skip_body() did not consume all of the input"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_find_attributes_simple() {
        let mut data = Vec::new();
        ciborium::into_writer(
            &cbor!({
                "digestID" => 0,
                "random" => ByteString(b"0123456789012345".to_vec()),
                "elementIdentifier" => "age_over_21",
                "elementValue" => true,
            })
            .unwrap(),
            &mut Cursor::new(&mut data),
        )
        .unwrap();

        let attributes = find_attributes(
            &HashMap::from([("org.iso.18013.5.1.aamva".to_string(), Vec::from([data]))]),
            &["age_over_21".to_string()],
        )
        .unwrap();
        let attribute = &attributes[0];
        assert_eq!(attribute._digest_id, 0);
        assert!(attribute.public_cbor_data.ends_with(&[0xf5])); // primitive(21), i.e. true
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_find_attributes_complex() {
        let mut data = Vec::new();
        ciborium::into_writer(
            &cbor!({
                "digestID" => 0,
                "random" => ByteString(b"0123456789012345".to_vec()),
                "elementIdentifier" => "domestic_driving_privileges",
                "elementValue" => [{
                    "domestic_vehicle_endorsements" => [{
                        "domestic_vehicle_endorsement_description" => "Passenger"
                    }],
                }],
            })
            .unwrap(),
            &mut Cursor::new(&mut data),
        )
        .unwrap();

        let attributes = find_attributes(
            &HashMap::from([("org.iso.18013.5.1.aamva".to_string(), Vec::from([data]))]),
            &["domestic_driving_privileges".to_string()],
        )
        .unwrap();
        let attribute = &attributes[0];
        assert_eq!(attribute._digest_id, 0);
        let needle = b"Passenger";
        assert!(
            attribute
                .public_cbor_data
                .windows(needle.len())
                .any(|window| window == needle)
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_find_attributes_wrong_order() {
        let mut data = Vec::new();
        ciborium::into_writer(
            &cbor!({
                "elementValue" => true,
                "elementIdentifier" => "age_over_21",
                "random" => ByteString(b"0123456789012345".to_vec()),
                "digestID" => 0,
            })
            .unwrap(),
            &mut Cursor::new(&mut data),
        )
        .unwrap();

        let error_message = find_attributes(
            &HashMap::from([("org.iso.18013.5.1.aamva".to_string(), Vec::from([data]))]),
            &["age_over_21".to_string()],
        )
        .unwrap_err()
        .to_string();
        assert!(error_message.contains("follow elementIdentifier"));
    }

    /// Check that the manual deserialization code in [`parse_mso`] is equivalent to the generated
    /// serde implementation (except for the offsets).
    #[wasm_bindgen_test(unsupported = test)]
    fn test_parse_mso() {
        let test_vector = load_witness_test_vector();
        let mdoc = parse_device_response(&test_vector.mdoc).unwrap();
        let msob: EncodedCbor =
            ciborium::from_reader(mdoc.issuer_signature_payload.as_slice()).unwrap();

        let expected: MobileSecurityObject = ciborium::from_reader(msob.0.as_slice()).unwrap();

        let (mso, offsets) = parse_mso(msob.0.as_slice()).unwrap();

        assert_eq!(mso, expected);

        // Perform some basic sanity checks on the offsets.
        assert!(offsets.valid_from > 0);
        assert!(offsets.valid_until > 0);
        assert!(offsets.device_key_info > 0);
        assert!(offsets.value_digests > 0);
        assert!(!offsets.value_digests_items.is_empty());
        assert!(
            !offsets
                .value_digests_items
                .values()
                .next()
                .unwrap()
                .is_empty()
        );
        assert!(
            offsets
                .value_digests_items
                .values()
                .all(|ns| { ns.values().all(|offset| *offset > offsets.value_digests) })
        );
    }
}
