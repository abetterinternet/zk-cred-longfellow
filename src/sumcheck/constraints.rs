//! Generation of constraints from a padded sumcheck proof, used by Ligero prover and verifier.
//! As specified in [draft-google-cfrg-libzk-01 section 6.6][1]
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6

use std::ops::{Add, Mul, MulAssign, Sub};

use crate::{
    circuit::{self, Circuit},
    fields::FieldElement,
    sumcheck::{
        bind::{ElementwiseSum, SumcheckArray},
        symbolic::SymbolicExpression,
    },
    transcript::Transcript,
};

use super::Proof;

/*

Linear constraints assert that A * W = b

W is witnesses which we don't have
b is a scalar with a known value
A

we represent this as triples (c, j, k)

c is the index into b
j is the index into W
k is constant factor

but also the vector b!

W[2] + 2W[3] = 3 yields two triples
- (0,2,1) -> 1 * 2nd element of W contributes to 0th elemebt of b
- (0,3,2) -> 2 * 3rd element of W contributes to 0th element of b

given constraint
symbolic
      - (Q * layer_proof.vr) * sym_layer_pad.vl
      - (Q * layer_proof.vl) * sym_layer_pad.vr
      - Q * sym_layer_pad.vl_vr
     =
      Q * layer_proof.vl * layer_proof.vl - known

push rhs into vector b


*/

/// A linear constraint consisting of a triple (c, j, k), per [4.4.2][1]. This is one element of the
/// the constraint matrix for A verifying that A * W = b.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
pub struct LinearConstraint<FieldElement> {
    /// c, the constraint number or row of A.
    constraint_number: usize,
    /// j, the index of the witness.
    witness_index: usize,
    /// The constant factor.
    constant_factor: FieldElement,
    // TODO: more
}

/// A quadratic constraint consisting of a triple (x, y, z), per [4.4.2][1]. For an array of
/// witnesses W, this constrains `W[x] * W[y] = W[z]`.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4.2
pub struct QuadraticConstraint {
    x: usize,
    y: usize,
    z: usize,
}

pub struct ProofConstraints<FieldElement> {
    /// Linear and quadratic constraints for each layer.
    layer_constraints: Vec<(LinearConstraint<FieldElement>, QuadraticConstraint)>,

    /// Linear constraints binding the final claims to G[0], G[1].
    public_inputs_constraint: LinearConstraint<FieldElement>,
}

impl<FE: FieldElement> ProofConstraints<FE> {
    /// Construct constraints from the provided proof of execution for the circuit and public
    /// inputs.
    ///
    /// Corresponds to `constraints_circuit` in [1]. That definition takes arguments `sym_pad` and
    /// `sym_private_inputs`, but we represent those as [`SymbolicExpression`] and do not need to
    /// pre-construct them.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
    pub fn from_proof(
        circuit: &Circuit,
        public_inputs: &[FE],
        transcript: &mut Transcript,
        proof: Proof<FE>,
    ) -> Result<Self, anyhow::Error> {
        transcript.initialize(&circuit, public_inputs)?;

        // Choose the bindings for the output layer.
        // The spec says to generate "circuit.lv" field elements, which I think has to mean the
        // number of bits needed to describe an output wire, because the idea is that binding to
        // challenges of this length will reduce the 3D quad down to 2D.
        let output_wire_bindings = transcript.generate_challenge::<FE>(circuit.logw())?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        transcript.init_fast_forward::<FE>(circuit)?;

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
                vec![FE::ZERO; circuit_layer.logw.into()],
                vec![FE::ZERO; circuit_layer.logw.into()],
            ];

            // Initial symbolic claim
            let mut sym_claim = SymbolicExpression::<2, _>::new(claims[0] + alpha * claims[1]);

            for (round, polynomial_pair) in proof_layer.polynomials.iter().enumerate() {
                for (hand, polynomial) in polynomial_pair.iter().enumerate() {
                    transcript.write_polynomial(&polynomial)?;

                    let challenge = transcript.generate_challenge(1)?;
                    new_bindings[hand][round] = challenge[0];

                    // Lagrange interpolation!
                    let sym_p0 = SymbolicExpression::new(polynomial.p0);
                    let sym_p1 = sym_claim - sym_p0;
                    let sym_p2 = SymbolicExpression::new(polynomial.p2);

                    sym_claim = sym_p0 * lag_i(FE::ZERO, challenge[0])
                        + sym_p1 * lag_i(FE::ONE, challenge[0])
                        + sym_p2 * lag_i(FE::TWO, challenge[0]);

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

            // "output" linear and quad constraints? in what form?

            // Commit to the padded evaluations of l and r. The specification implies they are
            // written as individual field elements, but longfellow-zk writes them as an array.
            transcript.write_field_element_array(&[proof_layer.vl, proof_layer.vr])?;

            // Update claims and bindings for the next layer.
            claims = [proof_layer.vl, proof_layer.vr];
            bindings = new_bindings;
        }

        // Linear constraint for the two final claims
        let gamma = transcript.generate_challenge(1)?;

        // TODO: output linear constraint

        Ok(todo!())
    }
}

/// LET lag_i(x) =
///                the quadratic polynomial such that
///                       lag_i(P_k) = 1  if i = k
///                                    0  otherwise
///                for 0 <= k < 3
///
/// Discussed in Section 6.6 [1].
///
/// # Bugs
///
/// This won't work in fields like GF(2^128) where P2 isn't literally two.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.6
fn lag_i<FE: FieldElement>(i: FE, x: FE) -> FE {
    // only lag_0, _1, _2 are defined
    assert!(i == FE::ZERO || i == FE::ONE || i == FE::TWO);

    if x == i { FE::ONE } else { FE::ZERO }
}
