//! Test vectors for the Longfellow protocol.

use crate::{
    Codec,
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement},
    sumcheck::constraints::QuadraticConstraint,
};
use serde::Deserialize;
use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Constraints {
    /// Right hand side terms of lienar constraints (vector of serialzied field elements in
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

/// JSON descriptor of a circuit test vector.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CircuitTestVector {
    #[allow(dead_code)]
    pub(crate) description: String,
    /// Field used by the circuit.
    pub(crate) field: u8,
    /// Depth of the circuit. This is wire layers, not gate layers.
    pub(crate) depth: u32,
    /// Total quads in the circuit.
    pub(crate) quads: u32,
    /// Not yet clear what this is.
    pub(crate) _terms: u32,
    /// Inputs which evaluate to 0 in this circuit.
    pub(crate) valid_inputs: Option<Vec<u128>>,
    /// Inputs which evaluate to non-zero in this circuit.
    pub(crate) invalid_inputs: Option<Vec<u128>>,
    /// The serialized circuit, decompressed from a file alongside the JSON descriptor.
    #[serde(default)]
    pub(crate) serialized_circuit: Vec<u8>,
    /// The serialized padded sumcheck proof of the circuit's execution.
    #[serde(default)]
    pub(crate) serialized_sumcheck_proof: Vec<u8>,
    /// The constraints on the proof.
    pub(crate) constraints: Option<Constraints>,
    /// The Ligero commitment to the witness.
    pub(crate) ligero_commitment: Option<String>,
    /// The serialized Ligero proof.
    #[serde(default)]
    // TODO: test against this proof.
    #[allow(dead_code)]
    pub(crate) serialized_ligero_proof: Vec<u8>,
    /// The fixed pad value to use during constraint generation.
    pub(crate) pad: Option<u64>,
}

impl CircuitTestVector {
    pub(crate) fn decode(test_vector_name: &'static str) -> (Self, Circuit) {
        let test_vector_path = format!("test-vectors/circuit/{test_vector_name}");

        let mut test_vector: Self = serde_json::from_reader(BufReader::new(
            File::open(format!("{test_vector_path}.json")).unwrap(),
        ))
        .unwrap();

        let mut compressed_circuit = Vec::new();
        File::open(format!("{test_vector_path}.circuit.zst"))
            .unwrap()
            .read_to_end(&mut compressed_circuit)
            .unwrap();

        test_vector.serialized_circuit = zstd::decode_all(compressed_circuit.as_slice()).unwrap();
        let mut cursor = Cursor::new(test_vector.serialized_circuit.as_slice());
        let circuit = Circuit::decode(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            test_vector.serialized_circuit.len(),
            "bytes left over after parsing circuit"
        );

        // Not all test vectors have serialized sumcheck proofs
        if let Ok(mut file) = File::open(format!("{test_vector_path}.sumcheck-proof")) {
            file.read_to_end(&mut test_vector.serialized_sumcheck_proof)
                .unwrap();
        }

        // Not all test vectors have serialized Ligero proofs
        if let Ok(mut file) = File::open(format!("{test_vector_path}.ligero-proof")) {
            file.read_to_end(&mut test_vector.serialized_ligero_proof)
                .unwrap();
        }

        assert_eq!(circuit.num_quads(), test_vector.quads as usize);

        (test_vector, circuit)
    }

    pub(crate) fn pad<FE: FieldElement>(&self) -> Option<FE> {
        self.pad.map(|pad| FE::from_u128(pad.into()))
    }

    pub(crate) fn ligero_commitment(&self) -> Option<Vec<u8>> {
        self.ligero_commitment
            .as_ref()
            .map(|ref string| hex::decode(string).unwrap())
    }
}
