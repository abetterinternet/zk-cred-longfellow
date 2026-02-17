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
    pub fn prove(
        &self,
        device_response: &[u8],
        namespace: &str,
        requested_claims: &[&str],
        session_transcript: &[u8],
        time: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if requested_claims.len() != self.num_attributes {
            return Err(anyhow!("wrong number of attributes"));
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
        )?;

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
    use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver, tests::load_witness_test_vector};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_generate_proof() {
        let compressed = include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice();
        let decompressed = zstd::decode_all(compressed).unwrap();
        let prover = MdocZkProver::new(&decompressed, CircuitVersion::V6, 1).unwrap();

        let witness_test_vector = load_witness_test_vector();

        prover
            .prove(
                &witness_test_vector.mdoc,
                "org.iso.18013.5.1",
                &[&witness_test_vector.attributes[0].id],
                &witness_test_vector.transcript,
                &witness_test_vector.now,
            )
            .unwrap();
    }
}
