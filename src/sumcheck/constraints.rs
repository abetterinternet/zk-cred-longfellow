//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    fields::CodecFieldElement,
    sumcheck::{
        Proof,
        bind::{ElementwiseSum, SumcheckArray, bindeq},
        witness::WitnessLayout,
    },
    transcript::Transcript,
};

/// A term of a  linear constraint consisting of a triple (c, j, k), per [4.4.2][1]. This is one
/// element of the the constraint matrix A for verifying that A * W = b. Several of these terms sum
/// together into one of the elements of `ProofConstraints::linear_constraint_rhs`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
// We don't yet examine these outside of test code, so allow dead code for now.
#[allow(dead_code)]
pub struct LinearConstraintTerm<FieldElement> {
    /// The constraint number or row of A. This is an index into the vector `b`, which we represent
    /// as `ProofConstraints::linear_constraint_rhs`. This is `c` in the specification.
    constraint_number: usize,
    /// The index into the witness vector W. This is `j` in the specification.
    witness_index: usize,
    /// The constant factor `k`.
    constant_factor: FieldElement,
}

/// A quadratic constraint consisting of a triple (x, y, z), per [4.4.2][1]. For an array of
/// witnesses W, this constrains `W[x] * W[y] = W[z]`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
pub struct QuadraticConstraint {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

pub struct ProofConstraints<FieldElement> {
    /// Terms contributing to the left hand sides of linear constraints.
    linear_constraint_lhs: Vec<LinearConstraintTerm<FieldElement>>,

    /// Vector of right hand sides of linear constraints.
    linear_constraint_rhs: Vec<FieldElement>,

    /// Quadratic constraints: one per circuit layer.
    quadratic_constraints: Vec<QuadraticConstraint>,
}

impl<FE: CodecFieldElement> ProofConstraints<FE> {
    /// Construct constraints from the provided proof of execution for the circuit and public
    /// inputs.
    ///
    /// Corresponds to `constraints_circuit` in [1]. That definition takes arguments `sym_pad` and
    /// `sym_private_inputs`, but since the whole point is that we don't know what those values are,
    /// it doesn't make sense to represent them as arguments.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
    pub fn from_proof(
        circuit: &Circuit,
        public_inputs: &[FE],
        transcript: &mut Transcript,
        proof: &Proof<FE>,
    ) -> Result<Self, anyhow::Error> {
        let mut constraints = Self {
            linear_constraint_lhs: Vec::with_capacity(
                // On each layer, 3 terms for vl, vr, vl * vr
                3 * circuit.num_layers()
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

        transcript.initialize(circuit, public_inputs)?;

        // Choose the bindings for the output layer.
        // The spec says to generate "circuit.lv" field elements, which I think has to mean the
        // number of bits needed to describe an output wire, because the idea is that binding to
        // challenges of this length will reduce the 3D quad down to 2D.
        let output_wire_bindings = transcript.generate_challenge::<FE>(circuit.logw())?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        transcript.generate_output_wire_bindings::<FE>(circuit)?;

        // Initial claims for left and right hand variables, corresponding to the output layer of
        // the circuit, and thus are zeroes.
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
            //  Q * layer_proof.vl * layer_proof.vl - known_part
            //
            // The LHS of this constraint will consist of two LinearConstraintTerms (p0 and p2) for
            // each polynomial (for the symbolic manipulations needed to compute symbolic_part),\
            // plus three more terms for this layer's vl, vr, vl*vr.
            //
            // The RHS can be computed straightforwardly and so we get one element per layer.
            //
            // Q is the quad once reduced down to a single value, which is bound_quad[0][0] for us.

            // Known portion of initial claim.
            let mut claim_known = claims[0] + alpha * claims[1];

            for (round, polynomial_pair) in proof_layer.polynomials.iter().enumerate() {
                for (hand, polynomial) in polynomial_pair.iter().enumerate() {
                    transcript.write_polynomial(polynomial)?;

                    let challenge = transcript.generate_challenge(1)?;
                    new_bindings[hand][round] = challenge[0];

                    let (p0_witness_index, p2_witness_index) =
                        witness_layout.polynomial_witness_indices(layer_index, round, hand);

                    // The proof contains padded polynomial points p0_hat and p1_hat where
                    // p0 = p0_hat - p0_pad and p2 = p2_hat - p2_pad.
                    //
                    // p1 is interpolated and not serialized.
                    let p1_known = claim_known - polynomial.p0;

                    // From Section 6.6:
                    // LET lag_i(x) =
                    //                the quadratic polynomial such that
                    //                       lag_i(P_k) = 1  if i = k
                    //                                    0  otherwise
                    //                for 0 <= k < 3
                    //
                    // https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
                    let lag_i = |i: FE, x: FE| {
                        // only lag_0, _1, _2 are defined
                        assert!(i == FE::ZERO || i == FE::ONE || i == FE::SUMCHECK_P2);

                        if x == i { FE::ONE } else { FE::ZERO }
                    };

                    // Directly manipulate the known portions p0_hat and p2_hat to compute the known
                    // portion of the  next claim, which will eventually contribute to the layer's
                    // linear constraint RHS.
                    claim_known = polynomial.p0 * lag_i(FE::ZERO, challenge[0])
                        + p1_known * lag_i(FE::ONE, challenge[0])
                        + polynomial.p2 * lag_i(FE::SUMCHECK_P2, challenge[0]);

                    // Manipulate the unknown portions p0_pad and p2_pad symbolically, accumulating
                    // linear constraint LHS terms.
                    constraints
                        .linear_constraint_lhs
                        .push(LinearConstraintTerm {
                            constraint_number: layer_index,
                            witness_index: p0_witness_index,
                            constant_factor: lag_i(FE::ZERO, challenge[0]),
                        });
                    // No constraint for P1, because it gets interpolated.
                    constraints
                        .linear_constraint_lhs
                        .push(LinearConstraintTerm {
                            constraint_number: layer_index,
                            witness_index: p2_witness_index,
                            constant_factor: lag_i(FE::SUMCHECK_P2, challenge[0]),
                        });

                    bound_quad = bound_quad.bind(&challenge).transpose();
                }
            }

            // Specification interpretation verification: over the course of the loop above, we bind
            // bound_quad to single field elements enough times that it should be reduced to a
            // single non-zero element.
            for i in 1..bound_quad.len() {
                for j in 1..bound_quad[i].len() {
                    assert_eq!(bound_quad[i][j], FE::ZERO, "bound quad: {bound_quad:?}");
                }
            }

            let (vl_witness, vr_witness, vl_vr_witness) =
                witness_layout.wire_witness_indices(layer_index);

            // Output the three remaining LHS terms of the linear constraint for this layer.
            // - (Q * layer_proof.vr) * sym_layer_pad.vl
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintTerm {
                    constraint_number: layer_index,
                    witness_index: vl_witness,
                    constant_factor: -bound_quad[0][0] * proof_layer.vr,
                });
            // - (Q * layer_proof.vl) * sym_layer_pad.vr
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintTerm {
                    constraint_number: layer_index,
                    witness_index: vr_witness,
                    constant_factor: -bound_quad[0][0] * proof_layer.vl,
                });
            // - Q * sym_layer_pad.vl_vr
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintTerm {
                    constraint_number: layer_index,
                    witness_index: vl_vr_witness,
                    constant_factor: -bound_quad[0][0],
                });

            // Output linear constraint RHS Q * layer_proof.vl * layer_proof.vl - known
            constraints
                .linear_constraint_rhs
                .push(bound_quad[0][0] * proof_layer.vl * proof_layer.vr - claim_known);

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
        let input_layer_index = circuit.num_layers() - 1;

        // One linear constraint LHS term for each private input
        for (private_input_index, private_input_witness) in
            witness_layout.private_input_witness_indices().enumerate()
        {
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintTerm {
                    constraint_number: input_layer_index,
                    witness_index: private_input_witness,
                    constant_factor: eq2[private_input_index + circuit.num_public_inputs()],
                });
        }

        let (vl_witness, vr_witness, _) = witness_layout.wire_witness_indices(input_layer_index);

        // Linear constraint LHS term for sym_layer_pad.vl
        constraints
            .linear_constraint_lhs
            .push(LinearConstraintTerm {
                constraint_number: input_layer_index,
                witness_index: vl_witness,
                constant_factor: -FE::ONE,
            });

        // Linear constraint LHS term for sym_layer_pad.vr
        constraints
            .linear_constraint_lhs
            .push(LinearConstraintTerm {
                constraint_number: input_layer_index,
                witness_index: vr_witness,
                constant_factor: -gamma,
            });

        // Linear constraint RHS
        constraints.linear_constraint_rhs.push(
            public_inputs
                .iter()
                .zip(eq2.iter())
                .fold(FE::ZERO, |sum, (eq2_i, public_input_i)| {
                    sum + *eq2_i * public_input_i
                })
                + claims[0]
                + gamma * claims[1],
        );

        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{Evaluation, tests::CircuitTestVector},
        fields::fieldp128::FieldP128,
        sumcheck::Prover,
    };

    #[test]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (_, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let witness_layout = WitnessLayout::from_circuit(&circuit);

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit.evaluate(&[45, 5, 6]).unwrap();

        let proof = Prover::new(
            &circuit,
            // Here we do _not_ fix the pad to zeroes in order to exercise symbolic manipulation.
            FieldP128::sample,
            "test",
        )
        .prove(&evaluation)
        .unwrap();

        let mut constraint_transcript = Transcript::new(b"test").unwrap();
        let constraints = ProofConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &proof.proof,
        )
        .unwrap();

        assert_eq!(
            constraints.linear_constraint_lhs.len(),
            3 * circuit.num_layers()
                + circuit.logw_sum() * 2 * 2
                + circuit.num_private_inputs()
                + 2
        );

        for lhs_term in constraints.linear_constraint_lhs {
            // All LHS terms should refer to an element of the RHS vector.
            assert!(lhs_term.constraint_number < constraints.linear_constraint_rhs.len());
            assert!(lhs_term.witness_index < witness_layout.length());
        }

        assert_eq!(
            constraints.linear_constraint_rhs.len(),
            circuit.num_layers() + 1
        );

        assert_eq!(
            constraints.quadratic_constraints.len(),
            circuit.num_layers()
        );

        // Transcripts should have received the same sequence of writes.
        assert_eq!(proof.transcript, constraint_transcript);
    }
}
