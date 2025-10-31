//! Ligero committer, specified in [Section 4.3][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3

use crate::{
    constraints::proof_constraints::QuadraticConstraint, fields::FieldElement,
    ligero::LigeroParameters, witness::Witness,
};
use anyhow::Context;

/// A commitment to a witness vector, as specified in [1]. Concretely, this is the root of a Merkle
/// tree of SHA-256 hashes.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LigeroCommitment([u8; 32]);

impl LigeroCommitment {
    /// The commitment as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A fake but well-formed commitment for tests.
    #[cfg(test)]
    pub fn test_commitment() -> Self {
        Self::try_from([1u8; 32].as_slice()).unwrap()
    }
}

impl TryFrom<&[u8]> for LigeroCommitment {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let commitment: [u8; 32] = value
            .try_into()
            .context("byte slice wrong size for commitment")?;
        Ok(LigeroCommitment(commitment))
    }
}

impl LigeroCommitment {
    /// Compute a Ligero commitment to the witness vector and the quadratic constraints. The layout
    /// of the commitment is specified in [1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
    pub fn commit<FE: FieldElement>(
        _parameters: &LigeroParameters,
        _witness: &Witness<FE>,
        _quadratic_constraints: &[QuadraticConstraint],
    ) -> Result<Self, anyhow::Error> {
        // Construct the tableau matrix from the witness and the constraints

        // Construct a Merkle tree from the tableau
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::Evaluation,
        constraints::proof_constraints::quadratic_constraints,
        fields::fieldp128::FieldP128,
        test_vector::CircuitTestVector,
        witness::{Witness, WitnessLayout},
    };

    use super::*;

    #[test]
    #[ignore]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(test_vector.valid_inputs.as_deref().unwrap())
            .unwrap();

        let quadratic_constraints = quadratic_constraints::<FieldP128>(&circuit);
        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad().unwrap(),
        );

        let ligero_commitment = LigeroCommitment::commit::<FieldP128>(
            test_vector.ligero_parameters.as_ref().unwrap(),
            &witness,
            &quadratic_constraints,
        )
        .unwrap();

        assert_eq!(ligero_commitment, test_vector.ligero_commitment().unwrap());
    }
}
