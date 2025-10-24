//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use crate::{
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement},
    sumcheck::{
        Proof,
        bind::{ElementwiseSum, SumcheckArray, bindeq},
        witness::WitnessLayout,
    },
    transcript::Transcript,
};
use serde::Deserialize;

/// A term of a  linear constraint consisting of a triple (c, j, k), per [4.4.2][1]. This is one
/// element of the the constraint matrix A for verifying that A * W = b. Several of these terms sum
/// together into one of the elements of `ProofConstraints::linear_constraint_rhs`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
// We don't yet examine these outside of test code, so allow dead code for now.
#[allow(dead_code)]
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

pub struct ProofConstraints<FieldElement> {
    /// Terms contributing to the left hand sides of linear constraints.
    linear_constraint_lhs: Vec<LinearConstraintLhsTerm<FieldElement>>,

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
        ligero_commitment: &[u8],
        proof: &Proof<FE>,
    ) -> Result<Self, anyhow::Error> {
        let mut constraints = Self {
            linear_constraint_lhs: Vec::with_capacity(
                // On each layer, 3 terms for vl, vr, vl * vr
                3 * circuit.num_layers()
                // On each layer past the first, 3 terms for the previous layer's vl, vr
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

            if layer_index > 0 {
                // For layers past the first, claims is computed from the previous layer's vl and
                // vr, so we need linear constraint terms for that symbolic manipulation.
                let (vl_witness, vr_witness, _) =
                    witness_layout.wire_witness_indices(layer_index - 1);
                // claims[0] is previous layer's vl
                constraints
                    .linear_constraint_lhs
                    .push(LinearConstraintLhsTerm {
                        constraint_number: layer_index,
                        witness_index: vl_witness,
                        constant_factor: FE::ONE,
                    });
                // claims[1] is previous layer's vr
                constraints
                    .linear_constraint_lhs
                    .push(LinearConstraintLhsTerm {
                        constraint_number: layer_index,
                        witness_index: vr_witness,
                        constant_factor: alpha,
                    });
            }

            for (round, polynomial_pair) in proof_layer.polynomials.iter().enumerate() {
                for (hand, polynomial) in polynomial_pair.iter().enumerate() {
                    transcript.write_polynomial(polynomial)?;

                    let challenge = transcript.generate_challenge(1)?;
                    new_bindings[hand][round] = challenge[0];

                    let (p0_witness_index, p2_witness_index) =
                        witness_layout.polynomial_witness_indices(layer_index, round, hand);

                    // The proof contains padded polynomial points p0_hat and p2_hat where
                    // p0 = p0_hat - p0_pad and p2 = p2_hat - p2_pad. p1 is interpolated and so its
                    // padded polynomial does not appear in the proof, but we still have constraint
                    // terms for its symbolic manipulation.
                    // Directly manipulate the known portions p0_hat and p2_hat to compute the known
                    // portion of the  next claim, which will eventually contribute to the layer's
                    // linear constraint RHS.
                    claim_known = polynomial.p0
                        * lagrange_basis_polynomial_i(FE::ZERO, challenge[0])
                        + (claim_known - polynomial.p0) // infer P1
                            * lagrange_basis_polynomial_i(FE::ONE, challenge[0])
                        + polynomial.p2
                            * lagrange_basis_polynomial_i(FE::SUMCHECK_P2, challenge[0]);

                    // We multiplied the claim by lag_1(challenge). The claim has a symbolic part
                    // consisting of every symbolic expression yet encountered on this layer. Scale
                    // them all up.
                    // TODO: this isn't quite right but close!
                    for term in &mut constraints.linear_constraint_lhs {
                        if term.constraint_number == layer_index {
                            term.constant_factor *=
                                lagrange_basis_polynomial_i(FE::ONE, challenge[0]);
                        }
                    }

                    // Manipulate the unknown portions p0_pad and p2_pad symbolically, accumulating
                    // linear constraint LHS terms.
                    constraints
                        .linear_constraint_lhs
                        .push(LinearConstraintLhsTerm {
                            constraint_number: layer_index,
                            witness_index: p0_witness_index,
                            constant_factor: lagrange_basis_polynomial_i(FE::ZERO, challenge[0])
                                // Account for subtracting p0 from claim
                                - FE::ONE,
                        });
                    constraints
                        .linear_constraint_lhs
                        .push(LinearConstraintLhsTerm {
                            constraint_number: layer_index,
                            witness_index: p2_witness_index,
                            constant_factor: lagrange_basis_polynomial_i(
                                FE::SUMCHECK_P2,
                                challenge[0],
                            ),
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
                .push(LinearConstraintLhsTerm {
                    constraint_number: layer_index,
                    witness_index: vl_witness,
                    constant_factor: -bound_quad[0][0] * proof_layer.vr,
                });
            // - (Q * layer_proof.vl) * sym_layer_pad.vr
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintLhsTerm {
                    constraint_number: layer_index,
                    witness_index: vr_witness,
                    constant_factor: -bound_quad[0][0] * proof_layer.vl,
                });
            // - Q * sym_layer_pad.vl_vr
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintLhsTerm {
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
        let input_layer_index = circuit.num_layers();

        // One linear constraint LHS term for each private input
        for (private_input_index, private_input_witness) in
            witness_layout.private_input_witness_indices().enumerate()
        {
            constraints
                .linear_constraint_lhs
                .push(LinearConstraintLhsTerm {
                    constraint_number: input_layer_index,
                    witness_index: private_input_witness,
                    constant_factor: eq2[private_input_index + circuit.num_public_inputs()],
                });
        }

        let (vl_witness, vr_witness, _) =
            witness_layout.wire_witness_indices(input_layer_index - 1);

        // Linear constraint LHS term for sym_layer_pad.vl
        constraints
            .linear_constraint_lhs
            .push(LinearConstraintLhsTerm {
                constraint_number: input_layer_index,
                witness_index: vl_witness,
                constant_factor: -FE::ONE,
            });

        // Linear constraint LHS term for sym_layer_pad.vr
        constraints
            .linear_constraint_lhs
            .push(LinearConstraintLhsTerm {
                constraint_number: input_layer_index,
                witness_index: vr_witness,
                constant_factor: -gamma,
            });

        // Linear constraint RHS
        constraints.linear_constraint_rhs.push(
            claims[0] + gamma * claims[1]
                - public_inputs
                    .iter()
                    .zip(eq2.iter())
                    .fold(FE::ZERO, |sum, (eq2_i, public_input_i)| {
                        sum + *eq2_i * public_input_i
                    }),
        );

        Ok(constraints)
    }
}

/// From Section 6.6:
/// LET lag_i(x) =
///                the quadratic polynomial such that
///                       lag_i(P_k) = 1  if i = k
///                                    0  otherwise
///                for 0 <= k < 3
///
/// https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
fn lagrange_basis_polynomial_i<FE: FieldElement>(i: FE, x: FE) -> FE {
    // Our nodes are x_0 = 0, x_1 = 1, and x_2 = SUMCHECK_P2 (aka 2) in the
    // field. Since we only have three nodes, we can work out each Lagrange
    // basis polynomial by hand.
    //
    // To avoid divisions, we multiply the numerator by the multiplicative
    // inverses of the three possible denominators for each field, which have
    // been preconputed.
    //
    // https://en.wikipedia.org/wiki/Lagrange_polynomial#Definition
    let (numerator, denominator_mul_inverse) = if i == FE::ZERO {
        (
            // (x - x_1) * (x - x_2)
            (x - FE::ONE) * (x - FE::SUMCHECK_P2),
            // (x_0 - x_1) * (x_0 - x_2) = (0 - 1) * (0 - 2) = 2
            FE::sumcheck_p2_mul_inv(),
        )
    } else if i == FE::ONE {
        (
            // (x - x_0) * (x - x_2)
            (x - FE::ZERO) * (x - FE::SUMCHECK_P2),
            // (x_1 - x_0) * (x_1 - x_2) = (1 - 0) * (1 - 2) = -1
            FE::negative_one_mul_inv(),
        )
    } else if i == FE::SUMCHECK_P2 {
        (
            // (x - x_0) * (x - x_1)
            (x - FE::ZERO) * (x - FE::ONE),
            // (x_2 - x_0) * (x_2 - x_1) = (2 - 0) * (2 - 1) = 2
            FE::sumcheck_p2_mul_inv(),
        )
    } else {
        panic!("lagrange basis polynomial undefined for {i:?}");
    };

    numerator * denominator_mul_inverse
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{Evaluation, tests::CircuitTestVector},
        fields::{
            FieldElement, field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256,
            fieldp256_2::FieldP256_2, fieldp521::FieldP521,
        },
        sumcheck::Prover,
    };

    fn lagrange_basis_polynomial_test<FE: FieldElement>() {
        // lag_i is 1 at i and 0 at the other nodes
        assert_eq!(lagrange_basis_polynomial_i(FE::ZERO, FE::ZERO), FE::ONE);
        assert_eq!(lagrange_basis_polynomial_i(FE::ZERO, FE::ONE), FE::ZERO);
        assert_eq!(
            lagrange_basis_polynomial_i(FE::ZERO, FE::SUMCHECK_P2),
            FE::ZERO
        );

        assert_eq!(lagrange_basis_polynomial_i(FE::ONE, FE::ZERO), FE::ZERO);
        assert_eq!(lagrange_basis_polynomial_i(FE::ONE, FE::ONE), FE::ONE);
        assert_eq!(
            lagrange_basis_polynomial_i(FE::ONE, FE::SUMCHECK_P2),
            FE::ZERO
        );

        assert_eq!(
            lagrange_basis_polynomial_i(FE::SUMCHECK_P2, FE::ZERO),
            FE::ZERO
        );
        assert_eq!(
            lagrange_basis_polynomial_i(FE::SUMCHECK_P2, FE::ONE),
            FE::ZERO
        );
        assert_eq!(
            lagrange_basis_polynomial_i(FE::SUMCHECK_P2, FE::SUMCHECK_P2),
            FE::ONE
        );
    }

    #[test]
    fn lagrange_basis_polynomial_field_p128() {
        lagrange_basis_polynomial_test::<FieldP128>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_p256() {
        lagrange_basis_polynomial_test::<FieldP256>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_p521() {
        lagrange_basis_polynomial_test::<FieldP521>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_2_128() {
        lagrange_basis_polynomial_test::<Field2_128>();
    }

    #[test]
    fn lagrange_basis_polynomial_field_p256_2() {
        lagrange_basis_polynomial_test::<FieldP256_2>();
    }

    #[test]
    fn self_consistent() {
        let (_, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let witness_layout = WitnessLayout::from_circuit(&circuit);

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit.evaluate(&[45, 5, 6]).unwrap();

        let mut proof_transcript = Transcript::new(b"test").unwrap();

        // Fork the transcript
        let mut constraint_transcript = proof_transcript.clone();

        let proof = Prover::new(&circuit, FieldP128::sample, "test")
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
            // All LHS terms should refer to an element of the RHS vector.
            assert!(lhs_term.constraint_number < constraints.linear_constraint_rhs.len());
            assert!(lhs_term.witness_index < witness_layout.length());
        }

        let mut all_pass = true;

        let mut lhs_summed = vec![FieldP128::ZERO; constraints.linear_constraint_rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in constraints.linear_constraint_lhs
        {
            lhs_summed[constraint_number] += proof.witness[witness_index] * constant_factor;
        }

        if lhs_summed != constraints.linear_constraint_rhs {
            println!(
                "FAIL: computed LHS terms do not sum ({lhs_summed:?}) to computed RHS ({:?})",
                constraints.linear_constraint_rhs
            );

            all_pass = false;
        }

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

        assert!(all_pass);
    }

    #[test]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        let test_vector_constraints = test_vector.constraints.unwrap();
        let test_vector_ligero_commitment =
            hex::decode(&test_vector.ligero_commitment.as_ref().unwrap()).unwrap();

        let witness_layout = WitnessLayout::from_circuit(&circuit);

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit.evaluate(&[45, 5, 6]).unwrap();

        let mut proof_transcript = Transcript::new(b"test").unwrap();

        // Fork the transcript
        let mut constraint_transcript = proof_transcript.clone();

        let proof = Prover::new(
            &circuit,
            // Hold pad to 0 so we can test against the test vector.
            || FieldP128::from_u128(7),
            "test",
        )
        .prove(
            &evaluation,
            &mut proof_transcript,
            Some(&test_vector_ligero_commitment),
        )
        .unwrap();

        // Ensure our witness vector length is consistent with witness layout, and with the
        // witnesses described in test vector constraints.
        assert_eq!(witness_layout.length(), proof.witness.len());

        let constraints = ProofConstraints::from_proof(
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
            &mut constraint_transcript,
            &test_vector_ligero_commitment,
            &proof.proof,
        )
        .unwrap();

        let mut all_pass = true;

        let test_vector_rhs_terms = test_vector_constraints.linear_constraint_rhs();

        if constraints.linear_constraint_rhs != test_vector_rhs_terms {
            println!(
                "FAIL: linear constraint rhs mismatch. ours: len {}\n{:#?}\ntest vector: len {}\n{:#?}",
                constraints.linear_constraint_rhs.len(),
                constraints.linear_constraint_rhs,
                test_vector_rhs_terms.len(),
                test_vector_rhs_terms,
            );

            all_pass = false;
        };

        println!(
            "computed lhs terms: {:#?}",
            constraints.linear_constraint_lhs
        );

        let their_lhs_terms: Vec<FieldP128> = [
            "ce6a2970f3e0c672fd3c0b8b9b09f8f0",
            "c2fbb2860deaaefa8ff005ed8d5c3f2a",
            "2aa80d5247a87620cce58bf45754ec48",
            "a41adc35f244be6d6e1fef2b2047e922",
            "6db0bbbe404221b57421b4b2529e87b2",
            "f21489d23bfaa787ac3be8064d35990a",
            "f8b6fc85adde2504705b9df8c5779a18",
            "18460de7da5182f1c3cfef924117445d",
            "77614599c11a9f2e52d236767d4565c8",
            "3ceb66b1e2bb0b7508bf7ec7c8678875",
            "c6fa1f7bbff963bad3ca9becabd2db34",
            "7f8a91a64877b7d6fb54b25c0a434f84",
            "c0b3db3fca1af0c9c4c6176375c552ba",
            "8a7c3a167be30d0e07bd473b04166771",
            "cc6a1aec59b01884b841dc3bc03a92bc",
            "d0fc6c37e217b18d49b12703785645b5",
            "6fc9119481530f49deacd2eec5e85853",
            "00000000000000000000000000000000",
            "498514d66ccec08dbe00b5b53e5100f6",
            "101847c71fc933884ff54b5c458d8e51",
            "451513baa77764f95361cadf72fed1ab",
            "ff22afaebc3fdd1e4b2d6a4cf869afa1",
            "2a44cd5eea7c2ac5635cf89f45f05228",
            "145aa8d314cf8223a73221b8530aa56b",
            "17b3e75dfbce2a4fc2cc82b2e13e9ad0",
            "b3777738ec80bdf3a115f5299efea140",
            "3ee8da496bbb2a352f0ef35e445b3935",
            "213c91fc428bb4409b3e25af6ea7eab5",
            "8831b3a10452799f52febfa40cc39c78",
            "8b291572389656df6b2ca8abf259991b",
            "b95450ff7b7a656ed51b891f443f6d4f",
            "00000000000000000000000000f0ffff",
            "83c743985e984bc29d94eafab192ec20",
        ]
        .into_iter()
        .map(|hex| FieldP128::try_from(hex::decode(hex).unwrap().as_slice()).unwrap())
        .collect();

        println!("their lhs terms: {:#?}", their_lhs_terms);

        let mut lhs_summed = vec![FieldP128::ZERO; constraints.linear_constraint_rhs.len()];
        for LinearConstraintLhsTerm {
            constraint_number,
            witness_index,
            constant_factor,
        } in constraints.linear_constraint_lhs
        {
            lhs_summed[constraint_number] += proof.witness[witness_index] * constant_factor;
        }
        if lhs_summed != test_vector_constraints.linear_constraint_rhs() {
            println!(
                "FAIL: computed LHS terms do not sum ({lhs_summed:?}) to test vector RHS ({:?})",
                test_vector_constraints.linear_constraint_rhs::<FieldP128>(),
            );

            all_pass = false;
        }

        assert_eq!(
            constraints.quadratic_constraints,
            test_vector_constraints.quadratic
        );

        assert!(all_pass);
    }
}
