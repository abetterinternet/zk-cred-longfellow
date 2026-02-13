//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement, ProofFieldElement},
    witness::WitnessLayout,
};
use serde::Deserialize;
use std::ops::{Add, AddAssign, Mul, MulAssign};

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
    witness_layout: &WitnessLayout,
) -> Vec<QuadraticConstraint> {
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

/// A symbolic expression, used to accumulate symbolic terms that contribute to a circuit layer's
/// linear constraint.
#[derive(Debug, Clone)]
pub struct SymbolicExpression<FieldElement> {
    known: FieldElement,
    constraint_number: usize,
    terms: Vec<Symbolic<FieldElement>>,
}

impl<FE: FieldElement> SymbolicExpression<FE> {
    /// A new, empty symbolic expression contributing to a linear constraint for the specified
    /// circuit layer.
    pub fn new(layer_index: usize) -> Self {
        Self {
            known: FE::ZERO,
            constraint_number: layer_index,
            terms: Vec::new(),
        }
    }

    /// The known portion of this expression. Its contribution to the linear constraint's right hand
    /// side.
    pub fn known(&self) -> FE {
        self.known
    }

    /// The linear constraint LHS terms for this expression.
    pub fn lhs_terms(&self) -> Vec<LinearConstraintLhsTerm<FE>> {
        self.terms
            .iter()
            // Terms with no witness index do not contribute to LHS
            .filter_map(|term| {
                term.witness_index
                    .map(|witness_index| LinearConstraintLhsTerm {
                        constraint_number: self.constraint_number,
                        witness_index,
                        constant_factor: term.constant_factor,
                    })
            })
            .collect()
    }
}

impl<FE: FieldElement> AddAssign<Term<FE>> for SymbolicExpression<FE> {
    fn add_assign(&mut self, rhs: Term<FE>) {
        self.known += rhs.known;
        self.terms.push(rhs.symbolic);
    }
}

impl<FE: FieldElement> MulAssign<FE> for SymbolicExpression<FE> {
    fn mul_assign(&mut self, rhs: FE) {
        self.known *= rhs;
        self.terms.iter_mut().for_each(|term| *term *= rhs);
    }
}

/// The symbolic portion of a [`Term`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Symbolic<FieldElement> {
    /// The index into the witness vector W. This is `j` in the specification.
    witness_index: Option<usize>,
    /// The constant factor `k`.
    constant_factor: FieldElement,
}

impl<FE: FieldElement> MulAssign<FE> for Symbolic<FE> {
    fn mul_assign(&mut self, rhs: FE) {
        self.constant_factor *= rhs;
    }
}

/// A symbolic term in a symbolic expression, consisting of `known` if `symbolic.witness_index` is
/// `None`, or `known + symbolic.constant_factor * W[symbolic.witness_index]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term<FieldElement> {
    /// The known portion of the expression.
    known: FieldElement,
    /// The symbolic portion of the expression.
    symbolic: Symbolic<FieldElement>,
}

impl<FE: FieldElement> Term<FE> {
    pub fn new(witness_index: usize) -> Self {
        Self {
            known: FE::ZERO,
            symbolic: Symbolic {
                witness_index: Some(witness_index),
                constant_factor: FE::ONE,
            },
        }
    }

    pub fn from_known(known: FE) -> Self {
        Self {
            known,
            symbolic: Symbolic {
                witness_index: None,
                constant_factor: FE::ONE,
            },
        }
    }

    pub fn with_witness(&mut self, index: usize) {
        self.symbolic.witness_index = Some(index);
    }
}

impl<FE: FieldElement> Add<FE> for Term<FE> {
    type Output = Self;

    fn add(self, rhs: FE) -> Self::Output {
        Self {
            known: self.known + rhs,
            ..self
        }
    }
}

impl<FE: FieldElement> Mul<FE> for Term<FE> {
    type Output = Self;

    fn mul(self, rhs: FE) -> Self::Output {
        Self {
            symbolic: Symbolic {
                constant_factor: self.symbolic.constant_factor * rhs,
                ..self.symbolic
            },
            known: self.known * rhs,
        }
    }
}

impl<FE: FieldElement> MulAssign<FE> for Term<FE> {
    fn mul_assign(&mut self, rhs: FE) {
        self.known *= rhs;
        self.symbolic *= rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Evaluation,
        fields::{CodecFieldElement, fieldp128::FieldP128, fieldp256::FieldP256},
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

        let quadratic_constraints = quadratic_constraints(&circuit, &witness_layout);

        assert_eq!(quadratic_constraints.len(), circuit.num_layers());

        for QuadraticConstraint { x, y, z } in quadratic_constraints {
            assert_eq!(witness.element(x) * witness.element(y), witness.element(z));
        }
    }

    fn test_quadratic_constraints<FE: ProofFieldElement>(
        test_vector: CircuitTestVector<FE>,
        circuit: Circuit<FE>,
    ) {
        let witness_layout = WitnessLayout::from_circuit(&circuit);
        assert_eq!(
            quadratic_constraints(&circuit, &witness_layout),
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

    #[wasm_bindgen_test(unsupported = test)]
    fn term_ops() {
        let term = Term::new(1);

        let term = term + FieldP256::from_u128(2);

        assert_eq!(
            term,
            Term {
                known: FieldP256::from_u128(2),
                symbolic: Symbolic {
                    witness_index: Some(1),
                    constant_factor: FieldP256::ONE,
                }
            }
        );

        let mut term = term * FieldP256::from_u128(5);

        assert_eq!(
            term,
            Term {
                known: FieldP256::from_u128(10),
                symbolic: Symbolic {
                    witness_index: Some(1),
                    constant_factor: FieldP256::from_u128(5),
                }
            }
        );

        term *= FieldP256::from_u128(6);

        assert_eq!(
            term,
            Term {
                known: FieldP256::from_u128(60),
                symbolic: Symbolic {
                    witness_index: Some(1),
                    constant_factor: FieldP256::from_u128(30),
                }
            }
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn expression_ops() {
        let mut expression = SymbolicExpression::new(11);
        assert_eq!(expression.lhs_terms(), vec![]);
        assert_eq!(expression.known(), FieldP256::ZERO);

        // Term with both known and symbolic part
        expression += Term::new(22) + FieldP256::from_u128(11);

        // Term with only symbolic part
        expression += Term::new(33);

        // Term with only known part
        expression += Term::from_known(FieldP256::from_u128(3));

        assert_eq!(
            expression.lhs_terms(),
            vec![
                LinearConstraintLhsTerm {
                    constraint_number: 11,
                    witness_index: 22,
                    constant_factor: FieldP256::ONE,
                },
                LinearConstraintLhsTerm {
                    constraint_number: 11,
                    witness_index: 33,
                    constant_factor: FieldP256::ONE,
                },
            ]
        );
        assert_eq!(expression.known(), FieldP256::from_u128(14));

        expression *= FieldP256::from_u128(6);

        assert_eq!(
            expression.lhs_terms(),
            vec![
                LinearConstraintLhsTerm {
                    constraint_number: 11,
                    witness_index: 22,
                    constant_factor: FieldP256::from_u128(6),
                },
                LinearConstraintLhsTerm {
                    constraint_number: 11,
                    witness_index: 33,
                    constant_factor: FieldP256::from_u128(6),
                },
            ]
        );
        assert_eq!(expression.known(), FieldP256::from_u128(14 * 6));
    }
}
