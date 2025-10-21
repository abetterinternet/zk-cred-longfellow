use crate::fields::FieldElement;
use std::ops::{Add, Mul, Sub};

/// A scalar, symbolic expression of the form `known + SUM_{0<=i<j} coefficient[i] * symbolic[i]`.
/// This allows verifiers to manipulate unknown quantities, such as proof pads or private inputs.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
#[derive(Clone, Debug, Copy)]
pub(crate) struct SymbolicExpression<const SIZE: usize, FieldElement> {
    /// The known portion of the expression as a single scalar.
    known: FieldElement,
    /// The symbolic portion of the expression, represented as a vector of coefficients multiplying
    /// the corresponding element of the unknown array.
    symbolic: [FieldElement; SIZE],
}

impl<const SIZE: usize, FE: FieldElement> SymbolicExpression<SIZE, FE> {
    /// Create a `SymbolicExpression` with the provided `known` part.
    pub(crate) fn new(known: FE) -> Self {
        Self {
            known,
            symbolic: [FE::ONE; SIZE],
        }
    }
}

impl<const SIZE: usize, FE: FieldElement> Sub for SymbolicExpression<SIZE, FE> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut symbolic = [FE::ZERO; SIZE];

        for (index, (lhs, rhs)) in self.symbolic.iter().zip(rhs.symbolic.iter()).enumerate() {
            symbolic[index] = *lhs - rhs;
        }

        Self {
            known: self.known - rhs.known,
            symbolic,
        }
    }
}

impl<const SIZE: usize, FE: FieldElement> Add for SymbolicExpression<SIZE, FE> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut symbolic = [FE::ZERO; SIZE];

        for (index, (lhs, rhs)) in self.symbolic.iter().zip(rhs.symbolic.iter()).enumerate() {
            symbolic[index] = *lhs + rhs;
        }

        Self {
            known: self.known + rhs.known,
            symbolic,
        }
    }
}

impl<const SIZE: usize, FE: FieldElement> Mul<FE> for SymbolicExpression<SIZE, FE> {
    type Output = Self;

    fn mul(self, rhs: FE) -> Self::Output {
        let mut symbolic = [FE::ZERO; SIZE];

        for (index, lhs) in self.symbolic.iter().enumerate() {
            symbolic[index] = *lhs * rhs;
        }

        Self {
            known: self.known * rhs,
            symbolic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fieldp256::FieldP256;

    #[test]
    fn add() {
        let lhs = SymbolicExpression::<2, _>::new(FieldP256::from_u128(10));
        let rhs = SymbolicExpression::<2, _>::new(FieldP256::from_u128(9));

        let sum = lhs + rhs;

        assert_eq!(sum.known, FieldP256::from_u128(19));
        assert_eq!(sum.symbolic, [FieldP256::TWO; 2]);

        let rhs = SymbolicExpression::<2, _>::new(-FieldP256::ONE);
        let sum = lhs + rhs;

        assert_eq!(sum.known, FieldP256::from_u128(9));
        assert_eq!(sum.symbolic, [FieldP256::TWO; 2]);
    }

    #[test]
    fn sub() {
        let lhs = SymbolicExpression::<2, _>::new(FieldP256::from_u128(10));
        let rhs = SymbolicExpression::<2, _>::new(FieldP256::from_u128(9));

        let sum = lhs - rhs;

        assert_eq!(sum.known, FieldP256::ONE);
        assert_eq!(sum.symbolic, [FieldP256::ZERO; 2]);

        let rhs = SymbolicExpression::<2, _>::new(-FieldP256::ONE);
        let sum = lhs - rhs;

        assert_eq!(sum.known, FieldP256::from_u128(11));
        assert_eq!(sum.symbolic, [FieldP256::ZERO; 2]);
    }

    #[test]
    fn mul() {
        let lhs = SymbolicExpression::<2, _>::new(FieldP256::from_u128(10));
        let product = lhs * FieldP256::from_u128(10);

        assert_eq!(product.known, FieldP256::from_u128(100));
        assert_eq!(product.symbolic, [FieldP256::from_u128(10); 2]);

        let product = product * -FieldP256::TWO;

        assert_eq!(product.known, -FieldP256::from_u128(200),);
        assert_eq!(product.symbolic, [-FieldP256::from_u128(20); 2]);
    }
}
