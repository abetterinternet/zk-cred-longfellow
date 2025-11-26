use crate::{
    circuit::Circuit,
    constraints::proof_constraints::{
        LinearConstraints, QuadraticConstraint, quadratic_constraints,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{
        LigeroCommitment, LigeroParameters,
        prover::{LigeroProof, ligero_prove},
        tableau::Tableau,
    },
    sumcheck::prover::{SumcheckProof, SumcheckProver},
    transcript::Transcript,
    witness::{Witness, WitnessLayout},
};

/// Longfellow ZK prover.
pub struct Prover<'a> {
    sumcheck_prover: SumcheckProver<'a>,
    witness_layout: WitnessLayout,
    quadratic_constraints: Vec<QuadraticConstraint>,
    ligero_parameters: LigeroParameters,
}

impl<'a> Prover<'a> {
    /// Construct a new prover from a circuit and a choice of Ligero parameters.
    pub fn new(circuit: &'a Circuit, ligero_parameters: LigeroParameters) -> Self {
        let sumcheck_prover = SumcheckProver::new(circuit);
        let witness_layout = WitnessLayout::from_circuit(circuit);
        let quadratic_constraints = quadratic_constraints(circuit);
        Self {
            sumcheck_prover,
            witness_layout,
            quadratic_constraints,
            ligero_parameters,
        }
    }

    /// Construct a proof for the given statement and witness.
    ///
    /// The `inputs` argument represents all inputs to the circuit defining the theorem being
    /// proven. This includes both the statement, or public inputs, and the witness, or private
    /// inputs. The definition of the circuit determines which inputs are which.
    pub fn prove<FE>(&self, session_id: &[u8], inputs: &[FE]) -> Result<Proof<FE>, anyhow::Error>
    where
        FE: CodecFieldElement + LagrangePolynomialFieldElement,
    {
        // Evaluate circuit.
        let circuit = self.sumcheck_prover.circuit();
        let evaluation = circuit.evaluate(inputs)?;

        // Select one-time-pad, and combine with circuit witness into the Ligero witness.
        let witness = Witness::fill_witness(
            self.witness_layout.clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            FE::sample,
        );

        // Construct Ligero commitment.
        let tableau = Tableau::build(
            &self.ligero_parameters,
            &witness,
            &self.quadratic_constraints,
        );
        let merkle_tree = tableau.commit()?;
        let commitment = LigeroCommitment::from(merkle_tree.root());

        // Start of Fiat-Shamir transcript.
        let mut transcript = Transcript::new(session_id).unwrap();
        let mut constraint_transcript = transcript.clone();

        // Sumcheck, first time through: generate proof.
        let sumcheck_proof = self
            .sumcheck_prover
            .prove(&evaluation, &mut transcript, &commitment, &witness)?
            .proof;

        // Sumcheck, second time through: produce linear constraints.
        let linear_constraints = LinearConstraints::from_proof(
            circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &commitment,
            &sumcheck_proof,
        )?;

        // Generate Ligero proof.
        let ligero_proof = ligero_prove(
            &mut transcript,
            &tableau,
            &merkle_tree,
            &linear_constraints,
            &self.quadratic_constraints,
        )?;

        Ok(Proof {
            sumcheck_proof,
            ligero_commitment: commitment,
            ligero_proof,
        })
    }
}

/// Longfellow ZK proof.
pub struct Proof<FE> {
    sumcheck_proof: SumcheckProof<FE>,
    ligero_commitment: LigeroCommitment,
    ligero_proof: LigeroProof<FE>,
}

impl<FE> Proof<FE> {
    /// Returns the Sumcheck component of the proof.
    pub fn sumcheck_proof(&self) -> &SumcheckProof<FE> {
        &self.sumcheck_proof
    }

    /// Returns the Ligero commitment.
    pub fn ligero_commitment(&self) -> LigeroCommitment {
        self.ligero_commitment
    }

    /// Returns the Ligero component of the proof.
    pub fn ligero_proof(&self) -> &LigeroProof<FE> {
        &self.ligero_proof
    }
}
