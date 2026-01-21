//! Parsing of mdoc CBOR structures.

use crate::{
    Sha256Digest,
    fields::fieldp256::FieldP256,
    mdoc_zk::{
        ec::{AffinePoint, Signature},
        mdoc::cose::{CoseKey, CoseSign1, ProtectedHeadersEs256, SigStructure},
        sha256::run_sha256,
    },
};
use anyhow::{Context, anyhow};
use ciborium::{Value, tag};
use ciborium_ll::{Decoder, Header};
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
pub(super) fn compute_credential_hash(mdoc: &Mdoc) -> Result<Sha256Digest, anyhow::Error> {
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

    Ok(run_sha256(message.as_slice()))
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
    let mut scratch = [0u8; 4096];
    for bytes in attribute_preimages.values().flatten() {
        let mut decoder = ciborium_ll::Decoder::from(bytes.as_slice());

        let map_header = decoder
            .pull()
            .map_err(|e| anyhow!("reading attribute failed: {e:?}"))?;
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

            let key_header = decoder
                .pull()
                .map_err(|e| anyhow!("reading map entry key failed: {e:?}"))?;
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
            let value_header = decoder
                .pull()
                .map_err(|e| anyhow!("reading map entry value failed: {e:?}"))?;
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
            let header = decoder
                .pull()
                .map_err(|e| anyhow!("reading next item after tag failed: {e:?}"))?;
            skip_body(decoder, scratch, header)?
        }
        Header::Break => return Err(anyhow!("unexpected break header when skipping value")),
        Header::Bytes(len) => {
            let mut segments = decoder.bytes(len);
            while let Some(mut segment) = segments
                .pull()
                .map_err(|e| anyhow!("erorr skipping past bytes: {e:?}"))?
            {
                while segment
                    .pull(scratch)
                    .map_err(|e| anyhow!("erorr skipping past bytes: {e:?}"))?
                    .is_some()
                {}
            }
        }
        Header::Text(len) => {
            let mut segments = decoder.text(len);
            while let Some(mut segment) = segments
                .pull()
                .map_err(|e| anyhow!("erorr skipping past text: {e:?}"))?
            {
                while segment
                    .pull(scratch)
                    .map_err(|e| anyhow!("erorr skipping past text: {e:?}"))?
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

                let header = decoder
                    .pull()
                    .map_err(|e| anyhow!("error skipping array: {e:?}"))?;
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

                let key_header = decoder
                    .pull()
                    .map_err(|e| anyhow!("error skipping map: {e:?}"))?;
                if let Header::Break = key_header {
                    if len.is_some() {
                        return Err(anyhow!("unexpected break in map of known size"));
                    }
                    break;
                }
                skip_body(decoder, scratch, key_header)?;

                let value_header = decoder
                    .pull()
                    .map_err(|e| anyhow!("error skipping map: {e:?}"))?;
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

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{
        find_attributes,
        mdoc::{ByteString, skip_body},
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
}
