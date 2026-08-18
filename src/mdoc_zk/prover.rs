use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    ligero::{LigeroParameters, prover::LigeroProver},
    mdoc_zk::{
        CircuitInputs, CircuitVersion, MdocZkProof, ProofContext, hash_ligero_parameters,
        signature_ligero_parameters,
    },
    sumcheck::{ProverResult, SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
    witness::Witness,
};
use anyhow::anyhow;
use rand::RngCore;
use std::io::Cursor;
use wasm_bindgen::prelude::wasm_bindgen;

/// Zero-knowledge prover for mdoc credential presentations.
#[wasm_bindgen]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MdocZkProver {
    circuit_version: CircuitVersion,
    num_attributes: usize,
    hash_circuit: Circuit<Field2_128>,
    hash_ligero_prover: LigeroProver<Field2_128>,
    signature_circuit: Circuit<FieldP256>,
    signature_ligero_prover: LigeroProver<FieldP256>,
}

/// Common initialization used by both the prover and verifier constructors.
#[allow(clippy::type_complexity)]
pub(super) fn common_initialization(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: usize,
) -> Result<
    (
        Circuit<FieldP256>,
        LigeroParameters,
        Circuit<Field2_128>,
        LigeroParameters,
    ),
    anyhow::Error,
> {
    if !(1..=4).contains(&num_attributes) {
        return Err(anyhow!("unsupported number of attributes"));
    }

    let mut cursor = Cursor::new(circuit);
    let signature_circuit = Circuit::decode(&mut cursor)?;
    let hash_circuit = Circuit::decode(&mut cursor)?;
    if cursor.position() as usize != circuit.len() {
        return Err(anyhow!("extra data left over after decoding circuits"));
    }

    let hash_ligero_parameters = hash_ligero_parameters(circuit_version, num_attributes);
    let signature_ligero_parameters = signature_ligero_parameters(circuit_version);

    Ok((
        signature_circuit,
        signature_ligero_parameters,
        hash_circuit,
        hash_ligero_parameters,
    ))
}

impl MdocZkProver {
    /// Construct a prover using the given circuit file and metadata.
    pub fn new(
        circuit: &[u8],
        circuit_version: CircuitVersion,
        num_attributes: usize,
    ) -> Result<Self, anyhow::Error> {
        let (signature_circuit, signature_ligero_parameters, hash_circuit, hash_ligero_parameters) =
            common_initialization(circuit, circuit_version, num_attributes)?;

        let hash_ligero_prover = LigeroProver::new(&hash_circuit, hash_ligero_parameters);
        let signature_ligero_prover =
            LigeroProver::new(&signature_circuit, signature_ligero_parameters);

        Ok(Self {
            circuit_version,
            num_attributes,
            hash_circuit,
            hash_ligero_prover,
            signature_circuit,
            signature_ligero_prover,
        })
    }

    /// Create a proof of possession of a credential and a device binding signature.
    ///
    /// For V8 circuits, use [`Self::prove_with_ppid`] instead to provide the
    /// verifier context required for PPID.
    pub fn prove(
        &self,
        device_response: &[u8],
        namespace: &str,
        requested_claims: &[&str],
        session_transcript: &[u8],
        time: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.prove_internal(
            device_response,
            namespace,
            requested_claims,
            session_transcript,
            time,
            None,
        )
    }

    /// Create a proof with PPID support (V8 circuits).
    ///
    /// `verifier_context` is a 32-byte value that binds the pseudonym to a
    /// specific verifier, ensuring different verifiers see different pseudonyms
    /// for the same credential holder.
    pub fn prove_with_ppid(
        &self,
        device_response: &[u8],
        namespace: &str,
        requested_claims: &[&str],
        session_transcript: &[u8],
        time: &str,
        verifier_context: &[u8; 32],
    ) -> Result<Vec<u8>, anyhow::Error> {
        if !matches!(self.circuit_version, CircuitVersion::V8) {
            return Err(anyhow::anyhow!(
                "prove_with_ppid requires a V8 circuit, got {:?}",
                self.circuit_version
            ));
        }
        self.prove_internal(
            device_response,
            namespace,
            requested_claims,
            session_transcript,
            time,
            Some(verifier_context),
        )
    }

    fn prove_internal(
        &self,
        device_response: &[u8],
        namespace: &str,
        requested_claims: &[&str],
        session_transcript: &[u8],
        time: &str,
        verifier_context: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if requested_claims.len() != self.num_attributes {
            return Err(anyhow!("wrong number of attributes"));
        }

        // V8 requires a verifier_context
        if matches!(self.circuit_version, CircuitVersion::V8) && verifier_context.is_none() {
            return Err(anyhow!(
                "V8 circuits require a verifier_context; use prove_with_ppid"
            ));
        }

        let hash_sumcheck_prover = SumcheckProtocol::new(&self.hash_circuit);
        let signature_sumcheck_prover = SumcheckProtocol::new(&self.signature_circuit);

        // Pick MAC prover key shares.
        let mut mac_prover_key_shares = [Field2_128::ZERO; 6];
        for key_share in mac_prover_key_shares.iter_mut() {
            *key_share = Field2_128::sample();
        }

        // Prepare witness inputs and most statement inputs.
        let mut inputs = CircuitInputs::new(
            self.circuit_version,
            device_response,
            session_transcript,
            namespace,
            requested_claims,
            time,
            &mac_prover_key_shares,
            verifier_context,
        )?;

        // Check input sizes against circuit metadata.
        if inputs.hash_input().len() != self.hash_circuit.num_inputs() {
            return Err(anyhow!("input length does not match hash circuit"));
        }
        if inputs.signature_input().len() != self.signature_circuit.num_inputs() {
            return Err(anyhow!("input length does not match signature circuit"));
        }

        // Initialize Fiat-Shamir transcript.
        let mut transcript = Transcript::new(session_transcript, TranscriptMode::Normal)?;

        // Select one-time-pads, and produce Ligero witnesses.
        let mut rng = rand::rng();
        let mut buffer = vec![0; Field2_128::num_bytes()];
        let hash_witness = Witness::fill_witness(
            self.hash_ligero_prover.witness_layout().clone(),
            &inputs.hash_input()[self.hash_circuit.num_public_inputs()..],
            || Field2_128::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes)),
        );
        let mut buffer = vec![0; FieldP256::num_bytes()];
        let signature_witness = Witness::fill_witness(
            self.signature_ligero_prover.witness_layout().clone(),
            &inputs.signature_input()[self.signature_circuit.num_public_inputs()..],
            || FieldP256::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes)),
        );

        // Commit to the hash circuit witness.
        let hash_commitment_state = self.hash_ligero_prover.commit(&hash_witness)?;
        transcript.write_byte_array(hash_commitment_state.commitment().as_bytes())?;

        // Commit to the signature circuit witness.
        let signature_commitment_state = self.signature_ligero_prover.commit(&signature_witness)?;
        transcript.write_byte_array(signature_commitment_state.commitment().as_bytes())?;

        // Generate MAC verifier key share.
        let mac_verifier_key_share = transcript.generate_challenge(1)?;
        let mac_verifier_key_share = mac_verifier_key_share[0];

        // Compute MAC tags.
        let mac_tags = compute_mac_tags(
            &inputs.mac_messages,
            &mac_prover_key_shares,
            &mac_verifier_key_share,
        );

        // Set remaining statement inputs for MAC verifier key share and MAC tags.
        inputs.update_macs(mac_verifier_key_share, mac_tags);

        // Evaluate the circuits to produce extended witnesses.
        let hash_evaluation = self.hash_circuit.evaluate(inputs.hash_input())?;
        let signature_evaluation = self.signature_circuit.evaluate(inputs.signature_input())?;

        // Run Sumcheck and Ligero on hash circuit.
        initialize_transcript(
            &mut transcript,
            &self.hash_circuit,
            hash_evaluation.public_inputs(self.hash_circuit.num_public_inputs()),
        )?;
        let ProverResult {
            proof: hash_sumcheck_proof,
            linear_constraints: hash_linear_constraints,
        } = hash_sumcheck_prover.prove(&hash_evaluation, &mut transcript, &hash_witness)?;

        let hash_ligero_proof = self.hash_ligero_prover.prove(
            &mut transcript,
            &hash_commitment_state,
            &hash_linear_constraints,
        )?;

        // Run Sumcheck and Ligero on signature circuit.
        initialize_transcript(
            &mut transcript,
            &self.signature_circuit,
            signature_evaluation.public_inputs(self.signature_circuit.num_public_inputs()),
        )?;
        let ProverResult {
            proof: signature_sumcheck_proof,
            linear_constraints: signature_linear_constraints,
        } = signature_sumcheck_prover.prove(
            &signature_evaluation,
            &mut transcript,
            &signature_witness,
        )?;

        let signature_ligero_proof = self.signature_ligero_prover.prove(
            &mut transcript,
            &signature_commitment_state,
            &signature_linear_constraints,
        )?;

        // Serialize MAC tags and proofs.
        let mut proof_buffer = Vec::with_capacity(1 << 19);
        let proof = MdocZkProof {
            mac_tags,
            hash_commitment: *hash_commitment_state.commitment(),
            hash_sumcheck_proof,
            hash_ligero_proof,
            signature_commitment: *signature_commitment_state.commitment(),
            signature_sumcheck_proof,
            signature_ligero_proof,
        };
        let context = ProofContext {
            hash_circuit: &self.hash_circuit,
            signature_circuit: &self.signature_circuit,
            hash_layout: hash_commitment_state.tableau().layout(),
            signature_layout: signature_commitment_state.tableau().layout(),
        };
        proof.encode_with_param(&context, &mut proof_buffer)?;

        Ok(proof_buffer)
    }
}

/// Computes MAC tags from key shares and messages.
pub(super) fn compute_mac_tags(
    messages: &[Field2_128; 6],
    prover_key_shares: &[Field2_128; 6],
    verifier_key_share: &Field2_128,
) -> [Field2_128; 6] {
    let mut tags = [Field2_128::ZERO; 6];
    for ((message, prover_key_share), tag) in
        messages.iter().zip(prover_key_shares).zip(tags.iter_mut())
    {
        let key = *prover_key_share + verifier_key_share;
        *tag = key * message;
    }
    tags
}

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{
        CircuitVersion, prover::MdocZkProver, tests::load_v6_v7_test_vector_inputs,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_generate_proof() {
        let compressed = include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let prover = MdocZkProver::new(&decompressed, CircuitVersion::V6, 1).unwrap();
        let test_vector_inputs = load_v6_v7_test_vector_inputs();
        prover
            .prove(
                &test_vector_inputs.mdoc,
                "org.iso.18013.5.1",
                &[&test_vector_inputs.attributes[0].id],
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
            )
            .unwrap();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_generate_proof_wrong_circuit_a() {
        let compressed = include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let prover = MdocZkProver::new(&decompressed, CircuitVersion::V7, 1).unwrap();
        let test_vector_inputs = load_v6_v7_test_vector_inputs();
        prover
            .prove(
                &test_vector_inputs.mdoc,
                "org.iso.18013.5.1",
                &[&test_vector_inputs.attributes[0].id],
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
            )
            .unwrap_err();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_generate_proof_wrong_circuit_b() {
        let compressed = include_bytes!("../../test-vectors/mdoc_zk/7_1_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let prover = MdocZkProver::new(&decompressed, CircuitVersion::V6, 1).unwrap();
        let test_vector_inputs = load_v6_v7_test_vector_inputs();
        prover
            .prove(
                &test_vector_inputs.mdoc,
                "org.iso.18013.5.1",
                &[&test_vector_inputs.attributes[0].id],
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
            )
            .unwrap_err();
    }

    /// Test V8 prover rejects missing verifier_context.
    #[wasm_bindgen_test(unsupported = test)]
    fn test_v8_requires_verifier_context() {
        let compressed = include_bytes!("../../test-vectors/mdoc_zk/8_1_4259_2945_bd2d720cef03fe633646d66b510ea9a3b8515b645a76b5f71c9bc52e0220c8c7").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let prover = MdocZkProver::new(&decompressed, CircuitVersion::V8, 1).unwrap();
        let test_vector_inputs = load_v6_v7_test_vector_inputs();
        // prove() without verifier_context should fail for V8
        prover
            .prove(
                &test_vector_inputs.mdoc,
                "org.iso.18013.5.1",
                &[&test_vector_inputs.attributes[0].id],
                &test_vector_inputs.transcript,
                &test_vector_inputs.now,
            )
            .unwrap_err();
    }
}
/// Create a proof with PPID support (V8 circuits).
///
/// @param {MdocZkProver} prover - The prover returned from `initialize_prover()`.
/// @param {Uint8Array} device_response - The mdoc's DeviceResponse, as CBOR data.
/// @param {string} namespace - The namespace of the attributes to be disclosed.
/// @param {string[]} requested_claims - The identifiers of the attributes to disclose.
/// @param {Uint8Array} session_transcript - The session transcript binding the presentation.
/// @param {string} time - The current time in RFC 3339 format (e.g. "2026-03-05T22:39:45Z").
/// @param {Uint8Array} verifier_context - 32-byte verifier context for PPID derivation.
/// @returns {Uint8Array} The serialized proof.
#[wasm_bindgen]
pub fn prove_with_ppid_wasm(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: Vec<String>,
    session_transcript: &[u8],
    time: &str,
    verifier_context: &[u8],
) -> Result<Vec<u8>, wasm_bindgen::JsError> {
    if verifier_context.len() != 32 {
        return Err(wasm_bindgen::JsError::new(
            "verifier_context must be 32 bytes",
        ));
    }
    let ctx: &[u8; 32] = verifier_context
        .try_into()
        .map_err(|_| wasm_bindgen::JsError::new("verifier_context must be 32 bytes"))?;
    let claims: Vec<&str> = requested_claims.iter().map(|s| s.as_str()).collect();
    prover
        .prove_internal(
            device_response,
            namespace,
            &claims,
            session_transcript,
            time,
            Some(ctx),
        )
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

/// Initialize a V8 verifier from a circuit binary.
#[wasm_bindgen]
pub fn initialize_verifier(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: usize,
) -> Result<crate::mdoc_zk::verifier::MdocZkVerifier, wasm_bindgen::JsError> {
    crate::mdoc_zk::verifier::MdocZkVerifier::new(circuit, circuit_version, num_attributes)
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

/// Verify a V8 proof with PPID support.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_with_ppid_wasm(
    verifier: &crate::mdoc_zk::verifier::MdocZkVerifier,
    issuer_public_key_sec1: &[u8],
    given_name_cbor: &[u8],
    ppid_cbor: &[u8],
    _namespace: &str,
    doc_type: &str,
    session_transcript: &[u8],
    time: &str,
    verifier_context: &[u8],
    proof: &[u8],
) -> Result<(), wasm_bindgen::JsError> {
    if verifier_context.len() != 32 {
        return Err(wasm_bindgen::JsError::new(
            "verifier_context must be 32 bytes",
        ));
    }
    let ctx: &[u8; 32] = verifier_context
        .try_into()
        .map_err(|_| wasm_bindgen::JsError::new("verifier_context must be 32 bytes"))?;
    verifier
        .verify_with_ppid(
            issuer_public_key_sec1,
            &[
                crate::mdoc_zk::verifier::Attribute {
                    identifier: "given_name".to_owned(),
                    value_cbor: given_name_cbor.to_vec(),
                },
                crate::mdoc_zk::verifier::Attribute {
                    identifier: "pairwise_pseudonym".to_owned(),
                    value_cbor: ppid_cbor.to_vec(),
                },
            ],
            doc_type,
            b"\xa0",
            session_transcript,
            time,
            ctx,
            proof,
        )
        .map_err(|e| wasm_bindgen::JsError::new(&e.to_string()))
}

// The plain C-ABI export for a Go (cgo) verifier ("rust_verify_with_ppid"
// and friends) now lives in `crate::go_ffi`: it has grown well beyond a
// hardcoded, single-purpose stub (variable-length attribute arrays, real
// device_name_spaces_bytes, a cacheable verifier handle, and richer error
// reporting), so it earns its own module rather than living inline here
// alongside the WASM bindings.
