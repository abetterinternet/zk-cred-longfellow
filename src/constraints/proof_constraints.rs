//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    fields::{CodecFieldElement, ProofFieldElement},
    witness::WitnessLayout,
};
use serde::Deserialize;

/// A term of a linear constraint consisting of a triple (c, j, k), per [4.4.2][1]. This is one
/// element of the constraint matrix A for verifying that A * W = b. Several of these terms sum
/// together into one of the elements of `LinearConstraints::rhs`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearConstraintLhsTerm<FieldElement> {
    /// The constraint number or row of A. This is an index into the vector `b`, which we represent
    /// as `LinearConstraints::rhs`. This is `c` in the specification.
    pub constraint_number: usize,
    /// The index into the witness vector W. This is `j` in the specification.
    pub witness_index: usize,
    /// The constant factor `k`.
    pub constant_factor: FieldElement,
}

/// A quadratic constraint consisting of a triple (x, y, z), per [4.4.2][1]. For an array of
/// witnesses W, this constrains `W[x] * W[y] = W[z]`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct QuadraticConstraint {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

/// Construct quadratic constraints from the circuit. Since quadratic constraints are purely in
/// terms of witness values, they can be determined from nothing but the circuit.
pub fn quadratic_constraints<FE: CodecFieldElement>(
    circuit: &Circuit<FE>,
) -> Vec<QuadraticConstraint> {
    let witness_layout = WitnessLayout::from_circuit(circuit);

    (0..circuit.num_layers())
        .map(|layer_index| {
            let (vl_witness, vr_witness, vl_vr_witness) =
                witness_layout.wire_witness_indices(layer_index);

            // Output quadratic constraint sym_layer_pad.vl * sym_layer_pad.vr = sym_layer_pad.vl_vr
            QuadraticConstraint {
                x: vl_witness,
                y: vr_witness,
                z: vl_vr_witness,
            }
        })
        .collect()
}

/// Ligero linear constraints generated from a Sumcheck proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearConstraints<FieldElement> {
    /// Terms contributing to the left hand sides of linear constraints.
    pub(crate) lhs_terms: Vec<LinearConstraintLhsTerm<FieldElement>>,

    /// Vector of right hand sides of linear constraints.
    pub(crate) rhs: Vec<FieldElement>,
}

impl<FE: ProofFieldElement> LinearConstraints<FE> {
    /// The number of linear constraints.
    pub fn len(&self) -> usize {
        self.rhs.len()
    }

    /// Whether this contains no linear constraints.
    ///
    /// Unused, but clippy complains if we provide method `len()` but not this.
    pub fn is_empty(&self) -> bool {
        self.rhs.is_empty()
    }

    /// Left hand side terms of the linear constraints.
    pub fn left_hand_side_terms(&self) -> &[LinearConstraintLhsTerm<FE>] {
        &self.lhs_terms
    }

    /// Right hand side terms of the linear constraints.
    pub fn right_hand_side_terms(&self) -> &[FE] {
        &self.rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Evaluation,
        fields::{CodecFieldElement, fieldp128::FieldP128},
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        witness::Witness,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn quadratic_constraints_self_consistent() {
        let (test_vector, circuit) = load_rfc();

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let witness = Witness::fill_witness(
            witness_layout.clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            FieldP128::sample,
        );

        let quadratic_constraints = quadratic_constraints(&circuit);

        assert_eq!(quadratic_constraints.len(), circuit.num_layers());

        for QuadraticConstraint { x, y, z } in quadratic_constraints {
            assert_eq!(witness.element(x) * witness.element(y), witness.element(z));
        }
    }

    fn test_quadratic_constraints<FE: ProofFieldElement>(
        test_vector: CircuitTestVector<FE>,
        circuit: Circuit<FE>,
    ) {
        assert_eq!(
            quadratic_constraints(&circuit),
            test_vector.constraints.quadratic
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn quadratic_constraints_longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        test_quadratic_constraints(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn quadratic_constraints_longfellow_mac() {
        let (test_vector, circuit) = load_mac();
        test_quadratic_constraints(test_vector, circuit);
    }
}
