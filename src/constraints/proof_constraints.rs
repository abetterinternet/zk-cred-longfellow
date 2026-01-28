//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    constraints::symbolic::{SymbolicExpression, Term},
    fields::{CodecFieldElement, ProofFieldElement},
    sumcheck::{
        bind::{bindeq, sparse::Hand},
        prover::SumcheckProof,
    },
    transcript::Transcript,
    witness::WitnessLayout,
};
use anyhow::anyhow;
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
pub struct LinearConstraints<FieldElement> {
    /// Terms contributing to the left hand sides of linear constraints.
    lhs_terms: Vec<LinearConstraintLhsTerm<FieldElement>>,

    /// Vector of right hand sides of linear constraints.
    rhs: Vec<FieldElement>,
}

impl<FE: ProofFieldElement> LinearConstraints<FE> {
    /// Construct constraints from the provided proof of execution for the circuit and public
    /// inputs.
    ///
    /// Corresponds to `constraints_circuit` in [1]. That definition takes arguments `sym_pad` and
    /// `sym_private_inputs`, but since the whole point is that we don't know what those values are,
    /// it doesn't make sense to represent them as arguments.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
    pub fn from_proof(
        circuit: &Circuit<FE>,
        public_inputs: &[FE],
        transcript: &mut Transcript,
        proof: &SumcheckProof<FE>,
    ) -> Result<Self, anyhow::Error> {
        if public_inputs.len() != circuit.num_public_inputs() {
            return Err(anyhow!("wrong number of inputs"));
        }

        let mut constraints = Self {
            lhs_terms: Vec::with_capacity(
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
            rhs: Vec::with_capacity(1 + circuit.num_layers()),
        };

        let witness_layout = WitnessLayout::from_circuit(circuit);

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
            let mut quad = circuit.combined_quad(layer_index, beta)?;

            // Bind the combined quad to G.
            quad.bindv_gate(&bindings[0], &bindings[1], alpha);

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
                for hand in [Hand::Left, Hand::Right] {
                    let polynomial = polynomial_pair[hand as usize];
                    transcript.write_polynomial(&polynomial)?;

                    let challenge = transcript.generate_challenge(1)?;
                    new_bindings[hand as usize][round] = challenge[0];

                    let (p0_witness, p2_witness) = witness_layout.polynomial_witness_indices(
                        layer_index,
                        round,
                        hand as usize,
                    );

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

                    quad.bind_hand(hand, challenge[0]);
                }
            }

            // Specification interpretation verification: over the course of the loop above, we bind
            // bound_quad to single field elements enough times that it should be reduced to a
            // single non-zero element.
            assert_eq!(quad.contents().len(), 1);
            assert_eq!(quad.contents()[0].gate_index, 0);
            assert_eq!(quad.contents()[0].left_wire_index, 0);
            assert_eq!(quad.contents()[0].right_wire_index, 0);
            let bound_element = quad.contents()[0].coefficient;

            let (vl_witness, vr_witness, vl_vr_witness) =
                witness_layout.wire_witness_indices(layer_index);

            // Output the three remaining terms of the linear constraint for this layer.
            // - (Q * layer_proof.vr) * sym_layer_pad.vl
            layer_claim += Term::new(vl_witness) * -bound_element * proof_layer.vr;
            // - (Q * layer_proof.vl) * sym_layer_pad.vr
            layer_claim += Term::new(vr_witness) * -bound_element * proof_layer.vl;
            // - Q * sym_layer_pad.vl_vr
            layer_claim += Term::new(vl_vr_witness) * -bound_element;

            // Output the LHS terms of the layer linear constraint
            constraints.lhs_terms.extend(layer_claim.lhs_terms());

            // Output linear constraint RHS Q * layer_proof.vl * layer_proof.vr - known
            constraints
                .rhs
                .push(bound_element * proof_layer.vl * proof_layer.vr - layer_claim.known());

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
        let eq2 = bindeq(&bindings[0], &bindings[1], gamma);
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

        constraints.lhs_terms.extend(final_claim.lhs_terms());
        constraints.rhs.push(rhs);

        Ok(constraints)
    }

    /// The number of linear constraints.
    pub fn len(&self) -> usize {
        self.rhs.len()
    }

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
        fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp128::FieldP128},
        ligero::LigeroCommitment,
        sumcheck::{initialize_transcript, prover::SumcheckProver},
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        transcript::TranscriptMode,
        witness::Witness,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn self_consistent() {
        let (test_vector, circuit) = load_rfc();

        let evaluation: Evaluation<FieldP128> =
            circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let witness = Witness::fill_witness(
            witness_layout.clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            FieldP128::sample,
        );

        let mut proof_transcript =
            Transcript::new(b"test", TranscriptMode::V3Compatibility).unwrap();
        proof_transcript
            .write_byte_array(LigeroCommitment::test_commitment().as_bytes())
            .unwrap();
        initialize_transcript(
            &mut proof_transcript,
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )
        .unwrap();

        // Fork the transcript
        let mut constraint_transcript = proof_transcript.clone();

        let proof = SumcheckProver::new(&circuit)
            .prove(&evaluation, &mut proof_transcript, &witness)
            .unwrap();

        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &proof.proof,
        )
        .unwrap();

        // Transcripts should have received the same sequence of writes.
        assert_eq!(proof_transcript, constraint_transcript);

        // Check that we allocated appropriate size for LHS terms. Ideally we won't reallocate in
        // the constraint generator loop.
        assert_eq!(
            linear_constraints.lhs_terms.len(),
            3 * circuit.num_layers()
                + 2 * (circuit.num_layers() - 1)
                + circuit.logw_sum() * 2 * 2
                + circuit.num_private_inputs()
                + 2
        );

        for lhs_term in &linear_constraints.lhs_terms {
            // All LHS terms should refer to elements of the RHS and witness vectors.
            assert!(lhs_term.constraint_number < linear_constraints.rhs.len());
            assert!(lhs_term.witness_index < witness_layout.length());
            // No LHS element should have a constant factor of 0.
            assert_ne!(lhs_term.constant_factor, FieldP128::ZERO);
        }

        let mut lhs_summed = vec![FieldP128::ZERO; linear_constraints.rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in linear_constraints.lhs_terms
        {
            lhs_summed[constraint_number] += witness.element(witness_index) * constant_factor;
        }

        assert_eq!(lhs_summed, linear_constraints.rhs);

        assert_eq!(linear_constraints.rhs.len(), circuit.num_layers() + 1);

        let quadratic_constraints = quadratic_constraints(&circuit);

        assert_eq!(quadratic_constraints.len(), circuit.num_layers());

        for QuadraticConstraint { x, y, z } in quadratic_constraints {
            assert_eq!(witness.element(x) * witness.element(y), witness.element(z));
        }
    }

    fn constraints<FE: ProofFieldElement>(
        test_vector: CircuitTestVector<FE>,
        circuit: Circuit<FE>,
    ) {
        let test_vector_proof = test_vector.sumcheck_proof(&circuit);

        let evaluation: Evaluation<FE> = circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let witness = Witness::fill_witness(
            witness_layout.clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad(),
        );

        let mut transcript = Transcript::new(b"test", TranscriptMode::V3Compatibility).unwrap();
        transcript
            .write_byte_array(test_vector.ligero_commitment().as_bytes())
            .unwrap();
        initialize_transcript(
            &mut transcript,
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )
        .unwrap();

        let linear_constraints = LinearConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut transcript,
            &test_vector_proof,
        )
        .unwrap();

        for wrong_length in [
            circuit.num_public_inputs() - 1,
            circuit.num_public_inputs() + 1,
        ] {
            assert!(
                LinearConstraints::from_proof(
                    &circuit,
                    evaluation.public_inputs(wrong_length),
                    &mut transcript,
                    &test_vector_proof,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("wrong number of inputs")
            );
        }

        assert_eq!(
            linear_constraints.rhs,
            test_vector.constraints.linear_constraint_rhs()
        );

        let mut lhs_summed = vec![FE::ZERO; linear_constraints.rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in linear_constraints.lhs_terms
        {
            lhs_summed[constraint_number] += witness.element(witness_index) * constant_factor;
        }
        assert_eq!(lhs_summed, test_vector.constraints.linear_constraint_rhs());

        assert_eq!(
            quadratic_constraints(&circuit),
            test_vector.constraints.quadratic
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        constraints::<FieldP128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac() {
        let (test_vector, circuit) = load_mac();
        constraints::<Field2_128>(test_vector, circuit);
    }
}
