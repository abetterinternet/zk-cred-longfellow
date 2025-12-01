use crate::{
    Codec,
    circuit::Circuit,
    constraints::proof_constraints::{
        LinearConstraints, QuadraticConstraint, quadratic_constraints,
    },
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    ligero::{
        LigeroCommitment, LigeroParameters,
        merkle::Node,
        prover::{LigeroProof, ligero_prove},
        tableau::{Tableau, TableauLayout},
    },
    sumcheck::{
        initialize_transcript,
        prover::{SumcheckProof, SumcheckProver},
    },
    transcript::Transcript,
    witness::{Witness, WitnessLayout},
    zk_one_circuit::verifier::Verifier,
};
use anyhow::anyhow;

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
        transcript.write_byte_array(commitment.as_bytes())?;
        initialize_transcript(
            &mut transcript,
            circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )?;
        let mut constraint_transcript = transcript.clone();

        // Sumcheck, first time through: generate proof.
        let sumcheck_proof = self
            .sumcheck_prover
            .prove(&evaluation, &mut transcript, &witness)?
            .proof;

        // Sumcheck, second time through: produce linear constraints.
        let linear_constraints = LinearConstraints::from_proof(
            circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
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
            oracle: session_id.to_vec(),
            sumcheck_proof,
            ligero_commitment: commitment,
            ligero_proof,
        })
    }
}

/// Longfellow ZK proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<FE> {
    oracle: Vec<u8>,
    sumcheck_proof: SumcheckProof<FE>,
    ligero_commitment: LigeroCommitment,
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
    pub fn ligero_commitment(&self) -> LigeroCommitment {
        self.ligero_commitment
    }

    /// Returns the Ligero component of the proof.
    pub fn ligero_proof(&self) -> &LigeroProof<FE> {
        &self.ligero_proof
    }
}

impl<F> Proof<F>
where
    F: CodecFieldElement,
{
    /// Deserialize a Longfellow ZK proof.
    ///
    /// See section [7.5][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.5
    pub fn decode(
        verifier: &Verifier,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let layout = TableauLayout::new(
            &verifier.ligero_parameters,
            verifier.witness_length,
            verifier.quadratic_constraints.len(),
        );
        let oracle = <[u8; 32] as Codec>::decode(bytes)?.to_vec();
        let ligero_commitment = LigeroCommitment::from(Node::decode(bytes)?);
        let sumcheck_proof = SumcheckProof::<F>::decode(verifier.circuit, bytes)?;
        let ligero_proof = LigeroProof::<F>::decode(&layout, bytes)?;
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
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let oracle: &[u8; 32] = self
            .oracle
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("oracle is not 32 bytes long"))?;
        oracle.encode(bytes)?;
        Node::from(self.ligero_commitment.into_bytes()).encode(bytes)?;
        self.sumcheck_proof.encode(bytes)?;
        self.ligero_proof.encode(bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        fields::fieldp128::FieldP128,
        test_vector::load_rfc,
        zk_one_circuit::{
            prover::{Proof, Prover},
            verifier::Verifier,
        },
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn proof_round_trip() {
        let (test_vector, circuit) = load_rfc();
        let ligero_parameters = test_vector.ligero_parameters();
        let all_inputs: Vec<FieldP128> = test_vector.valid_inputs();
        let session_id = b"testtesttesttesttesttesttesttest";

        let prover = Prover::new(&circuit, ligero_parameters.clone());
        let proof = prover.prove(session_id, &all_inputs).unwrap();
        assert_eq!(session_id, proof.oracle());

        let mut encoded = Vec::new();
        proof.encode(&mut encoded).unwrap();

        let verifier = Verifier::new(&circuit, ligero_parameters);
        let decoded = Proof::<FieldP128>::decode(&verifier, &mut Cursor::new(&encoded)).unwrap();
        assert_eq!(proof, decoded);
    }
}
