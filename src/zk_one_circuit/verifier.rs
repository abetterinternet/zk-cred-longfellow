use crate::{
    circuit::Circuit,
    fields::ProofFieldElement,
    ligero::{LigeroParameters, tableau::TableauLayout, verifier::LigeroVerifier},
    sumcheck::{SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
    zk_one_circuit::prover::Proof,
};

/// Longfellow ZK verifier.
pub struct Verifier<'a, FE: ProofFieldElement> {
    pub(super) circuit: &'a Circuit<FE>,
    pub(super) ligero_verifier: LigeroVerifier<FE>,
}

impl<'a, FE: ProofFieldElement> Verifier<'a, FE> {
    /// Construct a new verifier from a circuit and a choice of Ligero parameters.
    pub fn new(circuit: &'a Circuit<FE>, ligero_parameters: LigeroParameters) -> Self {
        let ligero_verifier = LigeroVerifier::new(circuit, ligero_parameters);
        Self {
            circuit,
            ligero_verifier,
        }
    }

    /// Return the Ligero tableau layout.
    pub fn tableau_layout(&self) -> &TableauLayout {
        self.ligero_verifier.tableau_layout()
    }

    /// Verify a Longfellow ZK proof.
    pub fn verify(&self, statement: &[FE], proof: &Proof<FE>) -> Result<(), anyhow::Error>
    where
        FE: ProofFieldElement,
    {
        // Start of Fiat-Shamir transcript.
        let mut transcript =
            Transcript::new(proof.oracle(), TranscriptMode::V3Compatibility).unwrap();

        transcript.write_byte_array(proof.ligero_commitment().as_bytes())?;
        initialize_transcript(&mut transcript, self.circuit, statement)?;

        // Run sumcheck verifier, and produce deferred linear constraints.
        let linear_constraints = SumcheckProtocol::new(self.circuit).linear_constraints(
            statement,
            &mut transcript,
            proof.sumcheck_proof(),
        )?;

        // Run Ligero verifier.
        self.ligero_verifier.verify(
            proof.ligero_commitment(),
            proof.ligero_proof(),
            &mut transcript,
            &linear_constraints,
        )?;

        Ok(())
    }
}
