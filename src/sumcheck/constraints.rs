//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    fields::{CodecFieldElement, LagrangePolynomialFieldElement},
    sumcheck::{
        Proof,
        bind::{ElementwiseSum, SumcheckArray, bindeq},
        symbolic::{SymbolicExpression, Term},
        witness::WitnessLayout,
    },
    transcript::Transcript,
};
use serde::Deserialize;

/// A term of a linear constraint consisting of a triple (c, j, k), per [4.4.2][1]. This is one
/// element of the constraint matrix A for verifying that A * W = b. Several of these terms sum
/// together into one of the elements of `ProofConstraints::linear_constraint_rhs`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearConstraintLhsTerm<FieldElement> {
    /// The constraint number or row of A. This is an index into the vector `b`, which we represent
    /// as `ProofConstraints::linear_constraint_rhs`. This is `c` in the specification.
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

/// Ligero constraints generated from a Sumcheck proof.
pub struct ProofConstraints<FieldElement> {
    /// Terms contributing to the left hand sides of linear constraints.
    linear_constraint_lhs: Vec<LinearConstraintLhsTerm<FieldElement>>,

    /// Vector of right hand sides of linear constraints.
    linear_constraint_rhs: Vec<FieldElement>,

    /// Quadratic constraints: one per circuit layer.
    quadratic_constraints: Vec<QuadraticConstraint>,
}

impl<FE: CodecFieldElement + LagrangePolynomialFieldElement> ProofConstraints<FE> {
    /// Construct constraints from the provided proof of execution for the circuit and public
    /// inputs.
    ///
    /// Corresponds to `constraints_circuit` in [1]. That definition takes arguments `sym_pad` and
    /// `sym_private_inputs`, but since the whole point is that we don't know what those values are,
    /// it doesn't make sense to represent them as arguments.
    ///
    /// `ligero_commitment` is the commitment computed per [4.3][2], which is needed to initialize
    /// the transcript.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
    /// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
    pub fn from_proof(
        circuit: &Circuit,
        public_inputs: &[FE],
        transcript: &mut Transcript,
        ligero_commitment: &[u8],
        proof: &Proof<FE>,
    ) -> Result<Self, anyhow::Error> {
        let mut constraints = Self {
            linear_constraint_lhs: Vec::with_capacity(
                // On each layer, 3 terms for vl, vr, vl * vr
                3 * circuit.num_layers()
                // On each layer past the first, 2 terms for the previous layer's vl, vr
                + 2 * (circuit.num_layers() - 1)
                    + circuit.logw_sum()
                        * 2 // witness elements per polynomial
                        * 2 // hands per round/logw
                    + circuit.num_private_inputs()
                    + 2, // sym_layer_pad.vl and sym_layer_pad.vr
            ),
            linear_constraint_rhs: Vec::with_capacity(1 + circuit.num_layers()),
            quadratic_constraints: Vec::with_capacity(circuit.num_layers()),
        };

        let witness_layout = WitnessLayout::from_circuit(circuit);

        transcript.initialize(Some(ligero_commitment), circuit, public_inputs)?;

        // Choose the bindings for the output layer.
        let output_wire_bindings = transcript.generate_output_wire_bindings::<FE>(circuit)?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        // Claims for left and right hand variables. Initially, these correspond to the output layer
        // of the circuit, and thus are zeroes and don't have any symbolic part. As we iterate over
        // the circuit layers, the claims will be updated and will include symbolic parts.
        let mut claims = [FE::ZERO; 2];

        for (layer_index, (circuit_layer, proof_layer)) in
            circuit.layers.iter().zip(proof.layers.iter()).enumerate()
        {
            // Choose alpha and beta for this layer
            let alpha = transcript.generate_challenge(1)?[0];
            let beta = transcript.generate_challenge(1)?[0];

            // The combined quad, aka QZ[g, l, r], a three dimensional array.
            let combined_quad = circuit.combined_quad(layer_index, beta)?;

            // Bind the combined quad to G.
            let mut bound_quad = combined_quad
                .bind(&bindings[0])
                .elementwise_sum(&combined_quad.bind(&bindings[1]).scale(alpha));

            // Reduce bound_quad to a Vec<Vec<FE>> so that we can later bind to the correct
            // dimension.
            let mut bound_quad = bound_quad.remove(0);

            // Allocate room for the new bindings this layer will generate
            let mut new_bindings = [
                vec![FE::ZERO; circuit_layer.logw()],
                vec![FE::ZERO; circuit_layer.logw()],
            ];

            // For each layer, we output a linear constraint:
            //
            //  LET known_part + symbolic_part = sym_claim
            //  symbolic_part
            //  - (Q * layer_proof.vr) * sym_layer_pad.vl
            //  - (Q * layer_proof.vl) * sym_layer_pad.vr
            //  - Q * sym_layer_pad.vl_vr
            // =
            //  Q * layer_proof.vl * layer_proof.vr - known_part
            //
            // The LHS of this constraint will consist of two SymbolicTerms for the previous layer's
            // vl and vr (to compute this layer's claims), plus two terms (p0 and p2) for each
            // polynomial in the layer, plus three more terms for this layer's vl, vr, vl*vr.
            //
            // The RHS can be computed straightforwardly and so we get one element per layer.
            //
            // Q is the quad once reduced down to a single value, which is bound_quad[0][0] for us.

            let mut layer_claim = SymbolicExpression::new(layer_index);

            let mut claim_0 = Term::from_known(claims[0]);
            let mut claim_1 = Term::from_known(claims[1]) * alpha;

            if layer_index > 0 {
                // For layers past the first, claims is computed from the previous layer's vl and
                // vr, so we need linear constraint terms for that symbolic manipulation.
                let (vl_witness, vr_witness, _) =
                    witness_layout.wire_witness_indices(layer_index - 1);

                claim_0.with_witness(vl_witness);
                claim_1.with_witness(vr_witness);
            }

            layer_claim += claim_0;
            layer_claim += claim_1;

            for (round, polynomial_pair) in proof_layer.polynomials.iter().enumerate() {
                for (hand, polynomial) in polynomial_pair.iter().enumerate() {
                    transcript.write_polynomial(polynomial)?;

                    let challenge = transcript.generate_challenge(1)?;
                    new_bindings[hand][round] = challenge[0];

                    let (p0_witness, p2_witness) =
                        witness_layout.polynomial_witness_indices(layer_index, round, hand);

                    // The proof contains padded polynomial points p0_hat and p2_hat where
                    // p0 = p0_hat - p0_pad and p2 = p2_hat - p2_pad. p1 is interpolated and so its
                    // padded polynomial does not appear in the proof, but we still have constraint
                    // terms for its symbolic manipulation.
                    //
                    // Compute the current claim:
                    //
                    //   claim = p0 * lag_0(challenge)
                    //     + p1 * lag_1(challenge)
                    //     + p2 * lag_2(challenge)
                    //
                    // Expanding p1 = prev_claim - p0 and rearranging:
                    //
                    //   claim = prev_claim * lag_1(challenge)
                    //     + p0 * (lag_0(challenge) - lag_1(challenge))
                    //     + p2 * lag_2(challenge)

                    // lag_1(challenge) * prev_claim
                    layer_claim *= FE::lagrange_basis_polynomial_1(challenge[0]);

                    // p0 * (lag_0(challenge) - lag_1(challenge)):
                    layer_claim += (Term::new(p0_witness) + polynomial.p0)
                        * (FE::lagrange_basis_polynomial_0(challenge[0])
                            - FE::lagrange_basis_polynomial_1(challenge[0]));

                    // p2 * lag_2(challenge):
                    layer_claim += (Term::new(p2_witness) + polynomial.p2)
                        * FE::lagrange_basis_polynomial_2(challenge[0]);

                    bound_quad = bound_quad.bind(&challenge).transpose();
                }
            }

            // Specification interpretation verification: over the course of the loop above, we bind
            // bound_quad to single field elements enough times that it should be reduced to a
            // single non-zero element.
            for (i, row) in bound_quad.iter().enumerate() {
                for (j, element) in row.iter().enumerate() {
                    if i != 0 && j != 0 {
                        assert_eq!(*element, FE::ZERO, "bound quad: {bound_quad:?}");
                    }
                }
            }

            let (vl_witness, vr_witness, vl_vr_witness) =
                witness_layout.wire_witness_indices(layer_index);

            // Output the three remaining terms of the linear constraint for this layer.
            // - (Q * layer_proof.vr) * sym_layer_pad.vl
            layer_claim += Term::new(vl_witness) * -bound_quad[0][0] * proof_layer.vr;
            // - (Q * layer_proof.vl) * sym_layer_pad.vr
            layer_claim += Term::new(vr_witness) * -bound_quad[0][0] * proof_layer.vl;
            // - Q * sym_layer_pad.vl_vr
            layer_claim += Term::new(vl_vr_witness) * -bound_quad[0][0];

            // Output the LHS terms of the layer linear constraint
            constraints
                .linear_constraint_lhs
                .extend(layer_claim.lhs_terms());

            // Output linear constraint RHS Q * layer_proof.vl * layer_proof.vr - known
            constraints
                .linear_constraint_rhs
                .push(bound_quad[0][0] * proof_layer.vl * proof_layer.vr - layer_claim.known());

            // Output quadratic constraint sym_layer_pad.vl * sym_layer_pad.vr = sym_layer_pad.vl_vr
            constraints.quadratic_constraints.push(QuadraticConstraint {
                x: vl_witness,
                y: vr_witness,
                z: vl_vr_witness,
            });

            // Commit to the padded evaluations of l and r. The specification implies they are
            // written as individual field elements, but longfellow-zk writes them as an array.
            transcript.write_field_element_array(&[proof_layer.vl, proof_layer.vr])?;

            // Update claims and bindings for the next layer.
            claims = [proof_layer.vl, proof_layer.vr];
            bindings = new_bindings;
        }

        // Output the linear constraint that the final claims match the binding of the inputs:
        //
        //      SUM_{i} (eq2[i + npub] * sym_private_inputs[i])
        //      - sym_layer_pad.vl
        //      - gamma * sym_layer_pad.vr
        //    =
        //      - SUM_{i} (eq2[i] * public_inputs[i])
        //      + claims[0]
        //      + gamma * claims[1]
        //
        // where sym_layer_pad is the padding on the input layer
        let gamma = transcript.generate_challenge(1)?[0];
        let eq2 = bindeq(&bindings[0]).elementwise_sum(&bindeq(&bindings[1]).scale(gamma));
        let input_layer_index = circuit.num_layers();

        let mut final_claim = SymbolicExpression::new(input_layer_index);

        // One linear constraint term for each private input
        for (private_input_index, private_input_witness) in
            witness_layout.private_input_witness_indices().enumerate()
        {
            final_claim += Term::new(private_input_witness)
                * eq2[private_input_index + circuit.num_public_inputs()];
        }

        let (vl_witness, vr_witness, _) =
            witness_layout.wire_witness_indices(input_layer_index - 1);

        // Linear constraint term for sym_layer_pad.vl
        final_claim += Term::new(vl_witness) * -FE::ONE;

        // Linear constraint term for sym_layer_pad.vr
        final_claim += Term::new(vr_witness) * -gamma;

        // Linear constraint RHS
        let rhs = claims[0] + gamma * claims[1]
            - public_inputs
                .iter()
                .zip(eq2.iter())
                .fold(FE::ZERO, |sum, (public_input_i, eq2_i)| {
                    sum + *public_input_i * eq2_i
                });

        constraints
            .linear_constraint_lhs
            .extend(final_claim.lhs_terms());
        constraints.linear_constraint_rhs.push(rhs);

        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{Evaluation, tests::CircuitTestVector},
        fields::{FieldElement, fieldp128::FieldP128},
        sumcheck::Prover,
    };

    #[test]
    fn self_consistent() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let witness_layout = WitnessLayout::from_circuit(&circuit);

        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(&test_vector.valid_inputs.unwrap())
            .unwrap();

        let mut proof_transcript = Transcript::new(b"test").unwrap();

        // Fork the transcript
        let mut constraint_transcript = proof_transcript.clone();

        let proof = Prover::new(&circuit, FieldP128::sample)
            .prove(&evaluation, &mut proof_transcript, Some(b"fake commitment"))
            .unwrap();

        // Ensure our witness vector length is consistent with witness layout, and with the
        // witnesses described in test vector constraints.
        assert_eq!(witness_layout.length(), proof.witness.len());

        let constraints = ProofConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            b"fake commitment",
            &proof.proof,
        )
        .unwrap();

        // Transcripts should have received the same sequence of writes.
        assert_eq!(proof_transcript, constraint_transcript);

        // Check that we allocated appropriate size for LHS terms. Ideally we won't reallocate in
        // the constraint generator loop.
        assert_eq!(
            constraints.linear_constraint_lhs.len(),
            3 * circuit.num_layers()
                + 2 * (circuit.num_layers() - 1)
                + circuit.logw_sum() * 2 * 2
                + circuit.num_private_inputs()
                + 2
        );

        for lhs_term in &constraints.linear_constraint_lhs {
            // All LHS terms should refer to elements of the RHS and witness vectors.
            assert!(lhs_term.constraint_number < constraints.linear_constraint_rhs.len());
            assert!(lhs_term.witness_index < witness_layout.length());
            // No LHS element should have a constant factor of 0.
            assert_ne!(lhs_term.constant_factor, FieldP128::ZERO);
        }

        let mut lhs_summed = vec![FieldP128::ZERO; constraints.linear_constraint_rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in constraints.linear_constraint_lhs
        {
            lhs_summed[constraint_number] += proof.witness[witness_index] * constant_factor;
        }

        assert_eq!(lhs_summed, constraints.linear_constraint_rhs);

        assert_eq!(
            constraints.linear_constraint_rhs.len(),
            circuit.num_layers() + 1
        );

        assert_eq!(
            constraints.quadratic_constraints.len(),
            circuit.num_layers()
        );

        for QuadraticConstraint { x, y, z } in constraints.quadratic_constraints {
            assert_eq!(proof.witness[x] * proof.witness[y], proof.witness[z]);
        }
    }

    #[test]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let test_vector_constraints = test_vector.constraints.unwrap();
        let test_vector_ligero_commitment =
            hex::decode(test_vector.ligero_commitment.as_ref().unwrap()).unwrap();

        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(&test_vector.valid_inputs.unwrap())
            .unwrap();

        let mut proof_transcript = Transcript::new(b"test").unwrap();

        // Fork the transcript
        let mut constraint_transcript = proof_transcript.clone();

        let proof = Prover::new(&circuit, || {
            FieldP128::from_u128(test_vector.pad.unwrap().into())
        })
        .prove(
            &evaluation,
            &mut proof_transcript,
            Some(&test_vector_ligero_commitment),
        )
        .unwrap();

        let constraints = ProofConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &test_vector_ligero_commitment,
            &proof.proof,
        )
        .unwrap();

        let test_vector_rhs_terms = test_vector_constraints.linear_constraint_rhs();

        assert_eq!(constraints.linear_constraint_rhs, test_vector_rhs_terms);

        let mut lhs_summed = vec![FieldP128::ZERO; constraints.linear_constraint_rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in constraints.linear_constraint_lhs
        {
            lhs_summed[constraint_number] += proof.witness[witness_index] * constant_factor;
        }
        assert_eq!(lhs_summed, test_vector_constraints.linear_constraint_rhs());

        assert_eq!(
            constraints.quadratic_constraints,
            test_vector_constraints.quadratic
        );
    }
}
