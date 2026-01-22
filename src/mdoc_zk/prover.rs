use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    constraints::proof_constraints::{
        LinearConstraints, QuadraticConstraint, quadratic_constraints,
    },
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    ligero::{LigeroCommitment, LigeroParameters, prover::ligero_prove, tableau::Tableau},
    mdoc_zk::{CircuitInputs, CircuitVersion, hash_ligero_parameters, signature_ligero_parameters},
    sumcheck::{initialize_transcript, prover::SumcheckProver},
    transcript::Transcript,
    witness::{Witness, WitnessLayout},
};
use anyhow::anyhow;
use std::io::Cursor;

/// Zero-knowledge prover for mdoc credential presentations.
pub struct MdocZkProver {
    circuit_version: CircuitVersion,
    num_attributes: usize,
    hash_circuit: Circuit<Field2_128>,
    hash_ligero_parameters: LigeroParameters,
    hash_witness_layout: WitnessLayout,
    hash_quadratic_constraints: Vec<QuadraticConstraint>,
    signature_circuit: Circuit<FieldP256>,
    signature_ligero_parameters: LigeroParameters,
    signature_witness_layout: WitnessLayout,
    signature_quadratic_constraints: Vec<QuadraticConstraint>,
}

impl MdocZkProver {
    /// Construct a prover using the given circuit file and metadata.
    pub fn new(
        circuit: &[u8],
        circuit_version: CircuitVersion,
        num_attributes: usize,
    ) -> Result<Self, anyhow::Error> {
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

        let hash_witness_layout = WitnessLayout::from_circuit(&hash_circuit);
        let signature_witness_layout = WitnessLayout::from_circuit(&signature_circuit);

        let hash_quadratic_constraints = quadratic_constraints(&hash_circuit);
        let signature_quadratic_constraints = quadratic_constraints(&signature_circuit);

        Ok(Self {
            circuit_version,
            num_attributes,
            hash_circuit,
            hash_ligero_parameters,
            hash_witness_layout,
            hash_quadratic_constraints,
            signature_circuit,
            signature_ligero_parameters,
            signature_witness_layout,
            signature_quadratic_constraints,
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

        let hash_sumcheck_prover = SumcheckProver::new(&self.hash_circuit);
        let signature_sumcheck_prover = SumcheckProver::new(&self.signature_circuit);

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
        let mut transcript = Transcript::new(session_transcript)?;

        // Select one-time-pads, and produce Ligero witnesses.
        let hash_witness = Witness::fill_witness(
            self.hash_witness_layout.clone(),
            &inputs.hash_input()[self.hash_circuit.num_public_inputs()..],
            Field2_128::sample,
        );
        let signature_witness = Witness::fill_witness(
            self.signature_witness_layout.clone(),
            &inputs.signature_input()[self.signature_circuit.num_public_inputs()..],
            FieldP256::sample,
        );

        // Commit to the hash circuit witness.
        let hash_tableau = Tableau::build(
            &self.hash_ligero_parameters,
            &hash_witness,
            &self.hash_quadratic_constraints,
        );
        let hash_merkle_tree = hash_tableau.commit()?;
        let hash_commitment = LigeroCommitment::from(hash_merkle_tree.root());
        transcript.write_byte_array(hash_commitment.as_bytes())?;

        // Commit to the signature circuit witness.
        let signature_tableau = Tableau::build(
            &self.signature_ligero_parameters,
            &signature_witness,
            &self.signature_quadratic_constraints,
        );
        let signature_merkle_tree = signature_tableau.commit()?;
        let signature_commitment = LigeroCommitment::from(signature_merkle_tree.root());
        transcript.write_byte_array(signature_commitment.as_bytes())?;

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
        let hash_evaluation = self.hash_circuit.evaluate(&inputs.hash_input()[1..])?;
        let signature_evaluation = self
            .signature_circuit
            .evaluate(&inputs.signature_input()[1..])?;

        // Run Sumcheck and Ligero on hash circuit.
        initialize_transcript(
            &mut transcript,
            &self.hash_circuit,
            hash_evaluation.public_inputs(self.hash_circuit.num_public_inputs()),
        )?;
        let mut constraint_transcript = transcript.clone();
        let hash_sumcheck_proof = hash_sumcheck_prover
            .prove(&hash_evaluation, &mut transcript, &hash_witness)?
            .proof;
        let hash_linear_constraints = LinearConstraints::from_proof(
            &self.hash_circuit,
            hash_evaluation.public_inputs(self.hash_circuit.num_public_inputs()),
            &mut constraint_transcript,
            &hash_sumcheck_proof,
        )?;

        let hash_ligero_proof = ligero_prove(
            &mut transcript,
            &hash_tableau,
            &hash_merkle_tree,
            &hash_linear_constraints,
            &self.hash_quadratic_constraints,
        )?;

        // Run Sumcheck and Ligero on signature circuit.
        initialize_transcript(
            &mut transcript,
            &self.signature_circuit,
            signature_evaluation.public_inputs(self.signature_circuit.num_public_inputs()),
        )?;
        let mut constraint_transcript = transcript.clone();
        let signature_sumcheck_proof = signature_sumcheck_prover
            .prove(&signature_evaluation, &mut transcript, &signature_witness)?
            .proof;
        let signature_linear_constraints = LinearConstraints::from_proof(
            &self.signature_circuit,
            signature_evaluation.public_inputs(self.signature_circuit.num_public_inputs()),
            &mut constraint_transcript,
            &signature_sumcheck_proof,
        )?;

        let signature_ligero_proof = ligero_prove(
            &mut transcript,
            &signature_tableau,
            &signature_merkle_tree,
            &signature_linear_constraints,
            &self.signature_quadratic_constraints,
        )?;

        // Serialize MAC tags and proofs.
        let mut proof = Vec::with_capacity(1 << 19);
        for mac_tag in mac_tags {
            mac_tag.encode(&mut proof)?;
        }
        hash_commitment.encode(&mut proof)?;
        hash_sumcheck_proof.encode_with_param(&self.hash_circuit, &mut proof)?;
        hash_ligero_proof.encode_with_param(hash_tableau.layout(), &mut proof)?;
        signature_commitment.encode(&mut proof)?;
        signature_sumcheck_proof.encode_with_param(&self.signature_circuit, &mut proof)?;
        signature_ligero_proof.encode_with_param(signature_tableau.layout(), &mut proof)?;

        Ok(proof)
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

    #[ignore = "slow test"]
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
