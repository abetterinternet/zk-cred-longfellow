use crate::{
    circuit::Circuit,
    constraints::proof_constraints::{LinearConstraints, quadratic_constraints},
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{LigeroParameters, TableauLayout, verifier::ligero_verify},
    transcript::Transcript,
    witness::WitnessLayout,
    zk_one_circuit::prover::Proof,
};

/// Verify a Longfellow ZK proof.
pub fn verify<FE>(
    circuit: &Circuit,
    ligero_parameters: &LigeroParameters,
    session_id: &[u8],
    statement: &[FE],
    proof: &Proof<FE>,
) -> Result<(), anyhow::Error>
where
    FE: CodecFieldElement + LagrangePolynomialFieldElement,
{
    // Prepend 1 to public inputs, just like Circuit::evaluate() does.
    let mut inputs = Vec::with_capacity(statement.len() + 1);
    inputs.push(FE::ONE);
    inputs.extend(statement);

    // Perform other pre-processing based on the circuit and Ligero parameters.
    let quadratic_constraints = quadratic_constraints(circuit);
    let witness_layout = WitnessLayout::from_circuit(circuit);
    let tableau_layout = TableauLayout::new(
        ligero_parameters,
        witness_layout.length(),
        quadratic_constraints.len(),
    );

    // Start of Fiat-Shamir transcript.
    let mut transcript = Transcript::new(session_id).unwrap();

    // Run sumcheck verifier, and produce deferred linear constraints.
    let linear_constraints = LinearConstraints::from_proof(
        circuit,
        &inputs,
        &mut transcript,
        &proof.ligero_commitment(),
        proof.sumcheck_proof(),
    )?;

    // Run Ligero verifier.
    ligero_verify(
        proof.ligero_commitment(),
        proof.ligero_proof(),
        &mut transcript,
        &linear_constraints,
        &quadratic_constraints,
        &tableau_layout,
    )?;

    Ok(())
}
