use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{CodecFieldElement, ProofFieldElement},
    ligero::{
        LigeroParameters,
        merkle::Root,
        prover::{LigeroProof, LigeroProver},
    },
    sumcheck::{
        initialize_transcript,
        prover::{ProverResult, SumcheckProof, SumcheckProtocol},
    },
    transcript::{Transcript, TranscriptMode},
    witness::Witness,
    zk_one_circuit::verifier::Verifier,
};
use anyhow::anyhow;
use std::io::{Cursor, Write};

/// Longfellow ZK prover.
pub struct Prover<'a, FE: ProofFieldElement> {
    sumcheck_prover: SumcheckProtocol<'a, FE>,
    ligero_prover: LigeroProver<FE>,
}

impl<'a, FE: ProofFieldElement> Prover<'a, FE> {
    /// Construct a new prover from a circuit and a choice of Ligero parameters.
    pub fn new(circuit: &'a Circuit<FE>, ligero_parameters: LigeroParameters) -> Self {
        let sumcheck_prover = SumcheckProtocol::new(circuit);
        let ligero_prover = LigeroProver::new(circuit, ligero_parameters);
        Self {
            sumcheck_prover,
            ligero_prover,
        }
    }

    /// Construct a proof for the given statement and witness.
    ///
    /// The `inputs` argument represents all inputs to the circuit defining the theorem being
    /// proven. This includes both the statement, or public inputs, and the witness, or private
    /// inputs. The definition of the circuit determines which inputs are which.
    pub fn prove(&self, session_id: &[u8], inputs: &[FE]) -> Result<Proof<FE>, anyhow::Error> {
        // Evaluate circuit.
        let circuit = self.sumcheck_prover.circuit();
        let evaluation = circuit.evaluate(inputs)?;

        // Select one-time-pad, and combine with circuit witness into the Ligero witness.
        let witness = Witness::fill_witness(
            self.ligero_prover.witness_layout().clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            FE::sample,
        );

        // Construct Ligero commitment.
        let commitment_state = self.ligero_prover.commit(&witness)?;

        // Start of Fiat-Shamir transcript.
        let mut transcript = Transcript::new(session_id, TranscriptMode::V3Compatibility).unwrap();
        transcript.write_byte_array(commitment_state.commitment().as_bytes())?;
        initialize_transcript(
            &mut transcript,
            circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )?;

        // Sumcheck: generate proof and linear constraints.
        let ProverResult {
            proof: sumcheck_proof,
            linear_constraints,
        } = self
            .sumcheck_prover
            .prove(&evaluation, &mut transcript, &witness)?;

        // Generate Ligero proof.
        let ligero_proof =
            self.ligero_prover
                .prove(&mut transcript, &commitment_state, &linear_constraints)?;

        Ok(Proof {
            oracle: session_id.to_vec(),
            sumcheck_proof,
            ligero_commitment: *commitment_state.commitment(),
            ligero_proof,
        })
    }
}

/// Longfellow ZK proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<FE> {
    oracle: Vec<u8>,
    sumcheck_proof: SumcheckProof<FE>,
    ligero_commitment: Root,
    ligero_proof: LigeroProof<FE>,
}

impl<FE> Proof<FE> {
    /// Returns the byte string used to select a random oracle.
    pub fn oracle(&self) -> &[u8] {
        &self.oracle
    }

    /// Returns the Sumcheck component of the proof.
    pub fn sumcheck_proof(&self) -> &SumcheckProof<FE> {
        &self.sumcheck_proof
    }

    /// Returns the Ligero commitment.
    pub fn ligero_commitment(&self) -> Root {
        self.ligero_commitment
    }

    /// Returns the Ligero component of the proof.
    pub fn ligero_proof(&self) -> &LigeroProof<FE> {
        &self.ligero_proof
    }
}

impl<'a, F: CodecFieldElement + ProofFieldElement> ParameterizedCodec<Verifier<'a, F>>
    for Proof<F>
{
    /// Deserialize a Longfellow ZK proof.
    ///
    /// See section [7.5][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.5
    fn decode_with_param(
        verifier: &Verifier<F>,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let oracle = u8::decode_fixed_array(bytes, 32)?.to_vec();
        let ligero_commitment = Root::decode(bytes)?;
        let sumcheck_proof = SumcheckProof::<F>::decode_with_param(verifier.circuit, bytes)?;
        let ligero_proof = LigeroProof::<F>::decode_with_param(verifier.tableau_layout(), bytes)?;

        Ok(Self {
            oracle,
            sumcheck_proof,
            ligero_commitment,
            ligero_proof,
        })
    }

    /// Encode a Longfellow ZK proof.
    ///
    /// See section [7.5][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.5
    fn encode_with_param<W: Write>(
        &self,
        verifier: &Verifier<F>,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        let oracle: &[u8; 32] = self
            .oracle
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("oracle is not 32 bytes long"))?;
        u8::encode_fixed_array(oracle, bytes)?;
        self.ligero_commitment.encode(bytes)?;
        self.sumcheck_proof
            .encode_with_param(verifier.circuit, bytes)?;
        self.ligero_proof
            .encode_with_param(verifier.tableau_layout(), bytes)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ParameterizedCodec,
        test_vector::load_rfc,
        zk_one_circuit::{prover::Prover, verifier::Verifier},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn proof_round_trip() {
        let (test_vector, circuit) = load_rfc();
        let session_id = b"testtesttesttesttesttesttesttest";

        let prover = Prover::new(&circuit, *test_vector.ligero_parameters());
        let proof = prover
            .prove(session_id, test_vector.valid_inputs())
            .unwrap();
        assert_eq!(session_id, proof.oracle());

        proof.roundtrip(&Verifier::new(&circuit, *test_vector.ligero_parameters()));
    }
}
