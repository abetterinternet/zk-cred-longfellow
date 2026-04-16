use crate::{
    ParameterizedCodec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    ligero::verifier::LigeroVerifier,
    mdoc_zk::{
        CircuitStatements, CircuitVersion, MdocZkProof, ProofContext, PublicAttribute,
        prover::common_initialization,
    },
    sumcheck::{SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
};
use anyhow::{Context, anyhow};
use std::borrow::Cow;

/// Zero-knowledge verifier for mdoc credential presentations.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MdocZkVerifier {
    circuit_version: CircuitVersion,
    num_attributes: usize,
    hash_circuit: Circuit<Field2_128>,
    hash_ligero_verifier: LigeroVerifier<Field2_128>,
    signature_circuit: Circuit<FieldP256>,
    signature_ligero_verifier: LigeroVerifier<FieldP256>,
}

impl MdocZkVerifier {
    /// Construct a verifier using the given circuit file and metadata.
    pub fn new(
        circuit: &[u8],
        circuit_version: CircuitVersion,
        num_attributes: usize,
    ) -> Result<Self, anyhow::Error> {
        let (signature_circuit, signature_ligero_parameters, hash_circuit, hash_ligero_parameters) =
            common_initialization(circuit, circuit_version, num_attributes)?;

        let hash_ligero_verifier = LigeroVerifier::new(&hash_circuit, hash_ligero_parameters);
        let signature_ligero_verifier =
            LigeroVerifier::new(&signature_circuit, signature_ligero_parameters);

        Ok(Self {
            circuit_version,
            num_attributes,
            hash_circuit,
            hash_ligero_verifier,
            signature_circuit,
            signature_ligero_verifier,
        })
    }

    /// Verify a proof of possession of a credential and a device binding signature.
    ///
    /// # Parameters
    ///
    /// * `issuer_public_key_sec_1`: Issuer public key, as encoded in the public key field of an
    ///   X.509 `SubjectPublicKeyInfo`.
    /// * `attributes`: The attributes disclosed in this presentation. For each attribute, the
    ///   attribute's identifier is given, along with the CBOR encoding if the attribute's value.
    /// * `doc_type`: The document type of the credential.
    /// * `device_name_spaces_bytes`: The CBOR-encoded `DeviceNameSpacesBytes` from the
    ///   `DeviceResponse`. This part of a credential is only used for attributes that are asserted
    ///   by the mdoc, not the issuer, but it still needs to be communicated in order to check mdoc
    ///   authentication.
    /// * `session_transcript`: The CBOR-encoded `SessionTranscript`, containing information about
    ///   protocol handover.
    /// * `time`: The current time, in RFC 3339 format.
    /// * `proof`: The serialized proof.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        issuer_public_key_sec_1: &[u8],
        attributes: &[Attribute],
        doc_type: &str,
        device_name_spaces_bytes: &[u8],
        session_transcript: &[u8],
        time: &str,
        proof: &[u8],
    ) -> Result<(), anyhow::Error> {
        if attributes.len() != self.num_attributes {
            return Err(anyhow!("wrong number of attributes"));
        }

        // Parse the proof.
        let context = self.proof_context();
        let proof = MdocZkProof::get_decoded_with_param(&context, proof)
            .context("could not parse proof")?;

        // Initialize Fiat-Shamir transcript.
        let mut transcript = Transcript::new(session_transcript, TranscriptMode::Normal)?;

        // Write commitments to the transcript.
        transcript.write_byte_array(proof.hash_commitment.as_bytes())?;
        transcript.write_byte_array(proof.signature_commitment.as_bytes())?;

        // Generate MAC verifier key share.
        let mac_verifier_key_share = transcript.generate_challenge(1)?;
        let mac_verifier_key_share = mac_verifier_key_share[0];

        // Prepare circuit statements.
        let statements = CircuitStatements::new(
            self.circuit_version,
            issuer_public_key_sec_1,
            attributes,
            doc_type,
            device_name_spaces_bytes,
            session_transcript,
            time,
            &proof,
            mac_verifier_key_share,
        )?;

        // Check public input sizes against circuit metadata.
        if statements.hash_statement().len() != self.hash_circuit.num_public_inputs() {
            return Err(anyhow!("statement length does not match hash circuit"));
        }
        if statements.signature_statement().len() != self.signature_circuit.num_public_inputs() {
            return Err(anyhow!("statement length does not match signature circuit"));
        }

        // Run Sumcheck and Ligero on hash circuit.
        initialize_transcript(
            &mut transcript,
            &self.hash_circuit,
            statements.hash_statement(),
        )?;
        let hash_linear_constraints = SumcheckProtocol::new(&self.hash_circuit)
            .linear_constraints(
                statements.hash_statement(),
                &mut transcript,
                &proof.hash_sumcheck_proof,
            )?;

        self.hash_ligero_verifier.verify(
            proof.hash_commitment,
            &proof.hash_ligero_proof,
            &mut transcript,
            &hash_linear_constraints,
        )?;

        // Run Sumcheck and Ligero on signature circuit.
        initialize_transcript(
            &mut transcript,
            &self.signature_circuit,
            statements.signature_statement(),
        )?;
        let signature_linear_constraints = SumcheckProtocol::new(&self.signature_circuit)
            .linear_constraints(
                statements.signature_statement(),
                &mut transcript,
                &proof.signature_sumcheck_proof,
            )?;

        self.signature_ligero_verifier.verify(
            proof.signature_commitment,
            &proof.signature_ligero_proof,
            &mut transcript,
            &signature_linear_constraints,
        )?;

        Ok(())
    }

    /// Decoding context needed to serialize or deserialize proofs.
    pub fn proof_context(&self) -> ProofContext<'_> {
        ProofContext {
            hash_circuit: &self.hash_circuit,
            signature_circuit: &self.signature_circuit,
            hash_layout: self.hash_ligero_verifier.tableau_layout(),
            signature_layout: self.signature_ligero_verifier.tableau_layout(),
        }
    }
}

/// Identifier and value of an attribute.
///
/// This represents the verifier's view of a selectively disclosed attribute, with ergonomic
/// handling of the element identifier as a `String`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Attribute {
    /// Attribute identifier.
    pub identifier: String,
    /// CBOR encoding of the attribute value.
    pub value_cbor: Vec<u8>,
}

impl Attribute {
    pub(super) fn as_public_attribute(&self) -> Result<PublicAttribute<'_>, anyhow::Error> {
        let mut identifier_cbor = Vec::with_capacity(self.identifier.len() + 2);
        ciborium::into_writer(&self.identifier, &mut identifier_cbor)
            .context("failed to serialize identifier")?;
        Ok(PublicAttribute {
            identifier: Cow::Owned(identifier_cbor),
            value: Cow::Borrowed(&self.value_cbor),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{
        CircuitVersion,
        tests::{ISSUER_PUBLIC_KEY, load_v6_v7_test_vector_inputs},
        verifier::{Attribute, MdocZkVerifier},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Test the verifier against a proof generated by the C++ implementation.
    #[wasm_bindgen_test(unsupported = test)]
    fn test_verify_interop_v6() {
        let proof = include_bytes!("../../test-vectors/mdoc_zk/v6_1attr_issue_date.proof");

        let compressed = include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let verifier = MdocZkVerifier::new(&decompressed, CircuitVersion::V6, 1).unwrap();

        let test_vector_inputs = load_v6_v7_test_vector_inputs();

        verifier
            .verify(
                ISSUER_PUBLIC_KEY,
                &[Attribute {
                    identifier: "issue_date".to_owned(),
                    value_cbor: b"\xd9\x03\xec\x6a2024-03-15".to_vec(),
                }],
                "org.iso.18013.5.1.mDL",
                b"\xA0", // Empty CBOR map
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
                proof,
            )
            .unwrap();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_verify_interop_v7() {
        let proof = include_bytes!("../../test-vectors/mdoc_zk/v7_1attr_issue_date.proof");

        let compressed = include_bytes!("../../test-vectors/mdoc_zk/7_1_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let verifier = MdocZkVerifier::new(&decompressed, CircuitVersion::V7, 1).unwrap();

        let test_vector_inputs = load_v6_v7_test_vector_inputs();

        verifier
            .verify(
                ISSUER_PUBLIC_KEY,
                &[Attribute {
                    identifier: "issue_date".to_owned(),
                    value_cbor: b"\xd9\x03\xec\x6a2024-03-15".to_vec(),
                }],
                "org.iso.18013.5.1.mDL",
                b"\xA0", // Empty CBOR map
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
                proof,
            )
            .unwrap();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_verify_interop_siros() {
        let json = include_bytes!("../../test-vectors/mdoc_zk/params.json");
        let params = serde_json::from_slice::<serde_json::Value>(json.as_slice()).unwrap();
        let proof = STANDARD.decode(params["proof"].as_str().unwrap()).unwrap();
        let transcript = STANDARD
            .decode(params["transcript"].as_str().unwrap())
            .unwrap();
        let now = params["now"].as_str().unwrap();

        let compressed = include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let verifier = MdocZkVerifier::new(&decompressed, CircuitVersion::V6, 1).unwrap();

        verifier
            .verify(
                ISSUER_PUBLIC_KEY,
                &[Attribute {
                    identifier: "age_over_18".to_owned(),
                    value_cbor: b"\xF5".to_vec(),
                }],
                "org.iso.18013.5.1.mDL",
                b"\xA0",
                &transcript,
                now,
                &proof,
            )
            .unwrap();
    }
}
