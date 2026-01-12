//! Test vectors for the Longfellow protocol.

use crate::{
    Codec,
    circuit::Circuit,
    constraints::proof_constraints::QuadraticConstraint,
    fields::{CodecFieldElement, field2_128::Field2_128, fieldp128::FieldP128},
    ligero::{
        LigeroCommitment, LigeroParameters, merkle::Node, prover::LigeroProof,
        tableau::TableauLayout,
    },
    sumcheck::prover::SumcheckProof,
};
use serde::Deserialize;
use std::io::Cursor;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Constraints {
    /// Right hand side terms of linear constraints (vector of serialzied field elements in
    /// hex).
    pub(crate) linear_rhs: Vec<String>,
    // Quadratic constraints.
    pub(crate) quadratic: Vec<QuadraticConstraint>,
}

impl Constraints {
    pub(crate) fn linear_constraint_rhs<FE: CodecFieldElement>(&self) -> Vec<FE> {
        self.linear_rhs
            .iter()
            .map(|element| FE::try_from(hex::decode(element).unwrap().as_slice()).unwrap())
            .collect()
    }
}

/// Includes test vector files at compile time, and passes them to [`CircuitTestVector::decode()`].
#[macro_export]
macro_rules! decode_test_vector {
    ($test_vector_name:expr $(,)?) => {
        CircuitTestVector::decode(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-vectors/one-circuit/",
                $test_vector_name,
                ".json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-vectors/one-circuit/",
                $test_vector_name,
                ".circuit.zst"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-vectors/one-circuit/",
                $test_vector_name,
                ".sumcheck-proof"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-vectors/one-circuit/",
                $test_vector_name,
                ".ligero-proof"
            )),
        )
    };
}

/// Load the test vector for the "rfc" circuit.
pub(crate) fn load_rfc() -> (CircuitTestVector<FieldP128>, Circuit<FieldP128>) {
    decode_test_vector!("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b")
}

/// Load the test vector for the "mac" circuit.
pub(crate) fn load_mac() -> (CircuitTestVector<Field2_128>, Circuit<Field2_128>) {
    decode_test_vector!("longfellow-mac-circuit-66aeaf09a9cc98e36873e868307ac07279d5f7e0-1")
}

/// JSON descriptor of a circuit test vector.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CircuitTestVector<FieldElement> {
    #[allow(dead_code)]
    pub(crate) description: String,
    /// Depth of the circuit. This is wire layers, not gate layers.
    pub(crate) depth: u32,
    /// Total quads in the circuit.
    pub(crate) quads: u32,
    /// Not yet clear what this is.
    pub(crate) _terms: u32,
    /// Inputs which evaluate to 0 in this circuit. Encoded as hex strings of the serialization of
    /// each input.
    pub(crate) valid_inputs: Vec<FieldElement>,
    /// Inputs which evaluate to non-zero in this circuit. Encoded as hex strings of the
    /// serialization of each input.
    pub(crate) invalid_inputs: Vec<FieldElement>,
    /// The serialized circuit, decompressed from a file alongside the JSON descriptor.
    #[serde(default)]
    pub(crate) serialized_circuit: Vec<u8>,
    /// The serialized padded sumcheck proof of the circuit's execution.
    #[serde(default)]
    pub(crate) serialized_sumcheck_proof: Vec<u8>,
    /// The constraints on the proof.
    pub(crate) constraints: Constraints,
    /// The Ligero commitment to the witness.
    pub(crate) ligero_commitment: String,
    /// The serialized Ligero proof.
    #[serde(default)]
    // TODO: test against this proof.
    #[allow(dead_code)]
    pub(crate) serialized_ligero_proof: Vec<u8>,
    /// The fixed pad value to use during constraint generation.
    pub(crate) pad: u64,
    /// Parameters for the Ligero proof.
    ligero_parameters: LigeroParameters,
}

impl<FE: CodecFieldElement> CircuitTestVector<FE> {
    pub(crate) fn decode(
        json: &[u8],
        compressed_circuit: &[u8],
        sumcheck_proof: &[u8],
        ligero_proof: &[u8],
    ) -> (Self, Circuit<FE>) {
        let mut test_vector: Self = serde_json::from_slice(json).unwrap();

        test_vector.serialized_circuit = zstd::decode_all(compressed_circuit).unwrap();
        let mut cursor = Cursor::new(test_vector.serialized_circuit.as_slice());
        let circuit = Circuit::decode(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            test_vector.serialized_circuit.len(),
            "bytes left over after parsing circuit"
        );

        test_vector.serialized_sumcheck_proof = sumcheck_proof.to_vec();

        test_vector.serialized_ligero_proof = ligero_proof.to_vec();

        assert_eq!(circuit.num_quads(), test_vector.quads as usize);

        (test_vector, circuit)
    }

    pub(crate) fn pad(&self) -> FE {
        FE::from_u128(self.pad.into())
    }

    pub(crate) fn ligero_commitment(&self) -> LigeroCommitment {
        LigeroCommitment::from(Node::from_hex(&self.ligero_commitment).unwrap())
    }

    pub(crate) fn valid_inputs(&self) -> &[FE] {
        &self.valid_inputs
    }

    pub(crate) fn invalid_inputs(&self) -> &[FE] {
        &self.invalid_inputs
    }

    pub(crate) fn ligero_parameters(&self) -> &LigeroParameters {
        &self.ligero_parameters
    }

    pub(crate) fn sumcheck_proof(&self, circuit: &Circuit<FE>) -> SumcheckProof<FE> {
        SumcheckProof::decode(circuit, &mut Cursor::new(&self.serialized_sumcheck_proof)).unwrap()
    }

    pub(crate) fn ligero_proof(&self, tableau_layout: &TableauLayout) -> LigeroProof<FE> {
        LigeroProof::decode(
            tableau_layout,
            &mut Cursor::new(&self.serialized_ligero_proof),
        )
        .unwrap()
    }
}
