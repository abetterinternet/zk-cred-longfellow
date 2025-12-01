use crate::{
    circuit::Circuit,
    constraints::proof_constraints::{
        LinearConstraints, QuadraticConstraint, quadratic_constraints,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{LigeroParameters, tableau::TableauLayout, verifier::ligero_verify},
    transcript::Transcript,
    witness::WitnessLayout,
    zk_one_circuit::prover::Proof,
};

/// Longfellow ZK verifier.
pub struct Verifier<'a> {
    pub(super) circuit: &'a Circuit,
    pub(super) witness_length: usize,
    pub(super) quadratic_constraints: Vec<QuadraticConstraint>,
    pub(super) ligero_parameters: LigeroParameters,
}

impl<'a> Verifier<'a> {
    /// Construct a new verifier from a circuit and a choice of Ligero parameters.
    pub fn new(circuit: &'a Circuit, ligero_parameters: LigeroParameters) -> Self {
        let witness_layout = WitnessLayout::from_circuit(circuit);
        let quadratic_constraints = quadratic_constraints(circuit);
        Self {
            circuit,
            witness_length: witness_layout.length(),
            quadratic_constraints,
            ligero_parameters,
        }
    }

    /// Verify a Longfellow ZK proof.
    pub fn verify<FE>(&self, statement: &[FE], proof: &Proof<FE>) -> Result<(), anyhow::Error>
    where
        FE: CodecFieldElement + LagrangePolynomialFieldElement,
    {
        // Prepend 1 to public inputs, just like Circuit::evaluate() does.
        let mut inputs = Vec::with_capacity(statement.len() + 1);
        inputs.push(FE::ONE);
        inputs.extend(statement);

        // Construct tableau layout struct.
        let tableau_layout = TableauLayout::new(
            &self.ligero_parameters,
            self.witness_length,
            self.quadratic_constraints.len(),
        );

        // Start of Fiat-Shamir transcript.
        let mut transcript = Transcript::new(proof.oracle()).unwrap();

        transcript.write_byte_array(proof.ligero_commitment().as_bytes())?;

        // Run sumcheck verifier, and produce deferred linear constraints.
        let linear_constraints = LinearConstraints::from_proof(
            self.circuit,
            &inputs,
            &mut transcript,
            proof.sumcheck_proof(),
        )?;

        // Run Ligero verifier.
        ligero_verify(
            proof.ligero_commitment(),
            proof.ligero_proof(),
            &mut transcript,
            &linear_constraints,
            &self.quadratic_constraints,
            &tableau_layout,
        )?;

        Ok(())
    }
}
