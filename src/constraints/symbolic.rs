use crate::{constraints::proof_constraints::LinearConstraintLhsTerm, fields::FieldElement};
use std::ops::{Add, AddAssign, Mul, MulAssign};

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
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::fields::fieldp256::FieldP256;

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
