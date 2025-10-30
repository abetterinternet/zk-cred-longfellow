//! Sumcheck prover.

use crate::{
    circuit::{Circuit, CircuitLayer, Evaluation},
    fields::CodecFieldElement,
    sumcheck::{
        Polynomial,
        bind::{ElementwiseSum, SumcheckArray},
    },
    transcript::Transcript,
    witness::WitnessLayout,
};
use std::{iter::repeat_with, mem::swap};

/// Generate a sumcheck proof of evaluation of a circuit.
#[derive(Clone, Debug)]
pub struct Prover<'a, PadGenerator> {
    circuit: &'a Circuit,
    pad_generator: PadGenerator,
}

/// Sumcheck proof plus some extra data useful for validation.
#[derive(Clone, Debug)]
// We don't yet examine these outside of test code, so allow dead code for now.
#[allow(dead_code)]
pub struct ProverResult<FE> {
    /// The sumcheck proof from which Ligero constraints may be generated.
    pub proof: Proof<FE>,
    /// The witnesses computed while computing the proof. The witness vector is never actually used
    /// by the prover during the protocol. It is recorded only to help validate the correctness of
    /// later steps.
    pub witness: Vec<FE>,
    /// The transcript after all the proof messages have been written to it.
    pub transcript: Transcript,
}

impl<'a, FE: CodecFieldElement, PadGenerator: FnMut() -> FE> Prover<'a, PadGenerator> {
    pub fn new(circuit: &'a Circuit, pad_generator: PadGenerator) -> Self {
        Self {
            circuit,
            pad_generator,
        }
    }

    /// Construct a padded proof of the transcript of the given evaluation of the circuit and return
    /// the prover messages needed for the verifier to reconstruct the transcript.
    pub fn prove(
        &mut self,
        evaluation: &Evaluation<FE>,
        transcript: &mut Transcript,
        ligero_commitment: &[u8],
    ) -> Result<ProverResult<FE>, anyhow::Error> {
        // Specification interpretation verification: all the outputs should be zero
        for output in evaluation.outputs() {
            assert_eq!(output, &FE::ZERO);
        }

        let witness_layout = WitnessLayout::from_circuit(self.circuit);
        let mut witness = Vec::with_capacity(witness_layout.length());

        // Witness vector starts with private inputs
        witness.extend(evaluation.private_inputs(self.circuit.num_public_inputs()));

        transcript.initialize(
            ligero_commitment,
            self.circuit,
            evaluation.public_inputs(self.circuit.num_public_inputs()),
        )?;

        // Choose the bindings for the output layer.
        let output_wire_bindings = transcript.generate_output_wire_bindings(self.circuit)?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        let mut proof = Proof {
            layers: Vec::with_capacity(self.circuit.num_layers()),
        };

        for (layer_index, layer) in self.circuit.layers.iter().enumerate() {
            // Choose alpha and beta for this layer
            let alpha = transcript.generate_challenge(1)?[0];
            let beta = transcript.generate_challenge(1)?[0];

            // The combined quad, aka QZ[g, l, r], a three dimensional array.
            let combined_quad = self.circuit.combined_quad(layer_index, beta)?;

            // Bind the combined quad to G.
            let mut bound_quad = combined_quad
                .bind(&bindings[0])
                .elementwise_sum(&combined_quad.bind(&bindings[1]).scale(alpha));

            // Specification interpretation verification: Because the length of g is the same as the
            // number of bits needed to describe wires on this layer (logw), bound_quad[g, l, r] = 0
            // for any g > 0. Thus bound_quad is effectively two-dimensional.
            for item in bound_quad.iter().skip(1) {
                assert!(item.is_empty());
            }

            // Reduce bound_quad to a Vec<Vec<FE>> so that we can later bind to the correct
            // dimension.
            let mut bound_quad = bound_quad.remove(0);

            // Allocate room for the new bindings this layer will generate
            let mut new_bindings = [vec![FE::ZERO; layer.logw()], vec![FE::ZERO; layer.logw()]];

            // Generate the pad for this layer. The pad has the same structure as the proof since the
            // one has to be subtracted from the other.
            let layer_pad = ProofLayer {
                polynomials: repeat_with(|| {
                    [
                        Polynomial {
                            p0: (self.pad_generator)(),
                            p2: (self.pad_generator)(),
                        },
                        Polynomial {
                            p0: (self.pad_generator)(),
                            p2: (self.pad_generator)(),
                        },
                    ]
                })
                .take(layer.logw())
                .collect(),
                vl: (self.pad_generator)(),
                vr: (self.pad_generator)(),
            };

            // Allocate the proof for this layer. The zero values in the polynomial are not
            // significant. We just need an initial value.
            let mut layer_proof_polynomials = vec![
                [Polynomial {
                    p0: FE::ZERO,
                    p2: FE::ZERO
                }; 2];
                layer.logw()
            ];

            // (VL, VR) = wires
            // The specification says "wires[j]" where 0 <= j < circuit.num_layers. Recall that
            // evaluation.wires includes the circuit output wires at index 0 so we have to go up one
            // to get the input wires for this layer.
            // This makes sense because over the course of the loop that follows, we'll bind each of
            // left_ and right_wires to a challenge layer.logw times, exactly enough to reduce these
            // arrays to a single element, which become the layer claims vl and vr.
            let mut left_wires = evaluation.wires[layer_index + 1].clone();
            let mut right_wires = evaluation.wires[layer_index + 1].clone();

            for (round, (pad_polynomials, proof_polynomials)) in layer_pad
                .polynomials
                .into_iter()
                .zip(&mut layer_proof_polynomials)
                .enumerate()
            {
                for hand in 0..2 {
                    // Implements the polynomial from the specification:
                    // Let p(x) = SUM_{l, r} bind(QUAD, x)[l, r] * bind(VL, x)[l] * VR[r]
                    let evaluate_polynomial = |at: FE| {
                        let bind = &[at];

                        let bound_quad_at = bound_quad.bind(bind);
                        let bound_left_wires = left_wires.bind(bind);

                        // Specification interpretation verification: the back half of
                        // bound_left_wires should be zeroes after binding.
                        for i in left_wires.len().div_ceil(2)..left_wires.len() {
                            assert_eq!(bound_left_wires.element(i), FE::ZERO);
                        }

                        let mut point = FE::ZERO;

                        // SUM_{l, r} is interpreted to mean evaluating the expression at all
                        // possible left and right wire indices.
                        // In sumcheck terms, we're evaluating the function at each of the vertices
                        // of a 2*logw-dimensional unit hypercube, or evaluating the function at all
                        // possible 2*logw length bitstrings, or actually 2*logw - 1 since we can
                        // skip the back half of bound_left_wires, which we know to contain only
                        // zeroes since we bound it.
                        for left_wire_index in 0..left_wires.len().div_ceil(2) {
                            for right_wire_index in 0..right_wires.len() {
                                // bind(QUAD, x)[l, r]
                                let bound_quad_term =
                                    bound_quad_at.element([left_wire_index, right_wire_index]);
                                // bind(VL, x)[l]
                                let left_wire_term = bound_left_wires.element(left_wire_index);
                                // VR[r]
                                let right_wire_term = right_wires.element(right_wire_index);

                                point += bound_quad_term * left_wire_term * right_wire_term;
                            }
                        }
                        point
                    };

                    // Evaluate the polynomial at P0 and P2, subtracting the pad
                    let poly_evaluation = Polynomial {
                        p0: evaluate_polynomial(FE::ZERO) - pad_polynomials[hand].p0,
                        p2: evaluate_polynomial(FE::SUMCHECK_P2) - pad_polynomials[hand].p2,
                    };

                    // Add polynomial pads to the witness.
                    witness.extend([pad_polynomials[hand].p0, pad_polynomials[hand].p2]);

                    // Commit to the padded polynomial.
                    transcript.write_polynomial(&poly_evaluation)?;

                    proof_polynomials[hand] = poly_evaluation;

                    // Generate an element of the binding for the next layer.
                    let challenge = transcript.generate_challenge(1)?;

                    new_bindings[hand][round] = challenge[0];

                    // Bind the current left wires and the quad to the challenge
                    left_wires = left_wires.bind(&challenge);
                    bound_quad = bound_quad.bind(&challenge);

                    swap(&mut left_wires, &mut right_wires);
                    bound_quad = bound_quad.transpose();
                }
            }

            // Specification interpretation verification: over the course of the loop above, we bind
            // bound_quad, left_wires and right_wires to single field elements enough times that all
            // should be reduced to a single non-zero element.
            for (i, row) in bound_quad.iter().enumerate() {
                for (j, element) in row.iter().enumerate() {
                    if i != 0 && j != 0 {
                        assert_eq!(*element, FE::ZERO, "bound quad: {bound_quad:?}");
                    }
                }
            }
            for left_wire in left_wires.iter().skip(1) {
                assert_eq!(left_wire, &FE::ZERO, "left wires: {left_wires:#?}");
            }
            for right_wire in right_wires.iter().skip(1) {
                assert_eq!(right_wire, &FE::ZERO, "right wires: {right_wires:#?}");
            }

            // Add vl, vr and vl * vr pads to the witness
            witness.extend([layer_pad.vl, layer_pad.vr, layer_pad.vl * layer_pad.vr]);

            let layer_proof = ProofLayer {
                polynomials: layer_proof_polynomials,
                vl: left_wires.element(0) - layer_pad.vl,
                vr: right_wires.element(0) - layer_pad.vr,
            };

            // Commit to the padded evaluations of l and r. The specification implies they are
            // written as individual field elements, but longfellow-zk writes them as an array.
            transcript.write_field_element_array(&[layer_proof.vl, layer_proof.vr])?;

            proof.layers.push(layer_proof);

            bindings = new_bindings;
        }

        Ok(ProverResult {
            proof,
            witness,
            transcript: transcript.clone(),
        })
    }
}

/// Proof constructed by sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<FieldElement> {
    pub layers: Vec<ProofLayer<FieldElement>>,
}

impl<FE: CodecFieldElement> Proof<FE> {
    /// Decode a proof from the bytes. This can't be an implementation of [`Codec`][crate::Codec]
    /// because we need the circuit this is a proof of to know how many layers there are.
    pub fn decode(
        circuit: &Circuit,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let mut proof_layers = Vec::with_capacity(circuit.num_layers());

        for circuit_layer in &circuit.layers {
            proof_layers.push(ProofLayer::decode(circuit_layer, bytes)?);
        }

        Ok(Self {
            layers: proof_layers,
        })
    }

    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Encode the layers as a fixed length array. That is, no length prefix.
        for layer in &self.layers {
            layer.encode(bytes)?;
        }

        Ok(())
    }
}

/// Sumcheck proof for a circuit layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofLayer<FieldElement> {
    /// A pair of polynomials (one for each hand) for each bit needed to describe a wire on the
    /// layer. That is, there are logw pairs.
    pub polynomials: Vec<[Polynomial<FieldElement>; 2]>,
    /// vl is (perhaps?) the evaluation of the "unique multi-linear extension" for the array of
    /// wires at this layer, evaluated at a random point l. Referred to as "wc0" elsewhere.
    /// See <https://eprint.iacr.org/2024/2010.pdf> p. 9
    pub vl: FieldElement,
    /// vr is similar to vl but evaluated at random point r. Referred to as "wc1" elsewhere.
    pub vr: FieldElement,
}

/// Proof layer serialization corresponds to PaddedTranscriptLayer in [7.3][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.3
impl<FE: CodecFieldElement> ProofLayer<FE> {
    /// Decode a proof layer from the bytes. We can't implement `Codec` here because we need some
    /// context (the corresponding circuit layer) to determine how many elements the layer should
    /// contain.
    pub fn decode(
        circuit_layer: &CircuitLayer,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        // The specification's "wires" corresponds to our "polynomials".
        // For each bit needed to describe a wire (logw), we have two hands and two polynomial
        // evaluations (at P0 and P2).
        let wires = FE::decode_fixed_array(bytes, circuit_layer.logw() * 4)?;

        // Each 4 field elements in the array makes a pair of Polynomials.
        // It would be good to avoid the copies of field elements here, but none of the methods that
        // would do the trick (Vec::into_chunks or Iterator::array_chunks) are in stable Rust.
        let polynomials = wires
            .as_chunks::<4>()
            .0
            .iter()
            // In longfellow-zk's encoding the array is indexed by hand, then wire/round
            .map(|[p0_0, p0_1, p2_0, p2_1]| {
                [
                    Polynomial {
                        p0: *p0_0,
                        p2: *p2_0,
                    },
                    Polynomial {
                        p0: *p0_1,
                        p2: *p2_1,
                    },
                ]
            })
            .collect();

        // In the specification, this is wc0
        let vl = FE::decode(bytes)?;
        let vr = FE::decode(bytes)?;

        Ok(Self {
            polynomials,
            vl,
            vr,
        })
    }

    /// Encode the proof layer into the provided bytes.
    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Fixed length array, whose length depends on the circuit this is a proof of.
        // In longfellow-zk's encoding the array is indexed by hand, then wire/round
        for [
            Polynomial { p0: p0_0, p2: p2_0 },
            Polynomial { p0: p0_1, p2: p2_1 },
        ] in &self.polynomials
        {
            p0_0.encode(bytes)?;
            p0_1.encode(bytes)?;
            p2_0.encode(bytes)?;
            p2_1.encode(bytes)?;
        }

        self.vl.encode(bytes)?;
        self.vr.encode(bytes)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Size, fields::fieldp128::FieldP128, test_vector::CircuitTestVector};
    use std::io::Cursor;

    #[test]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");

        assert_eq!(circuit.num_copies, Size(1));

        // This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m. For example, C(45, 5, 6) = 0.
        let evaluation: Evaluation<FieldP128> = circuit
            .evaluate(test_vector.valid_inputs.as_deref().unwrap())
            .unwrap();

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
        let mut transcript = Transcript::new(b"test").unwrap();

        let proof = Prover::new(&circuit, || test_vector.pad().unwrap())
            .prove(
                &evaluation,
                &mut transcript,
                test_vector.ligero_commitment().as_deref().unwrap(),
            )
            .unwrap();

        let test_vector_decoded = Proof::decode(
            &circuit,
            &mut Cursor::new(&test_vector.serialized_sumcheck_proof),
        )
        .unwrap();

        assert_eq!(
            proof.proof, test_vector_decoded,
            "ours: {proof:#?}\n\ntheirs: {test_vector_decoded:#?}"
        );

        let mut proof_encoded = Vec::new();
        proof.proof.encode(&mut proof_encoded).unwrap();

        assert_eq!(
            proof_encoded.len(),
            test_vector.serialized_sumcheck_proof.len()
        );
        assert_eq!(proof_encoded, test_vector.serialized_sumcheck_proof);
    }

    #[test]
    fn roundtrip_encoded_proof() {
        let (test_vector, circuit) =
            CircuitTestVector::decode("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");
        let test_vector_decoded = Proof::<FieldP128>::decode(
            &circuit,
            &mut Cursor::new(&test_vector.serialized_sumcheck_proof),
        )
        .unwrap();

        let mut test_vector_again = Vec::new();
        test_vector_decoded.encode(&mut test_vector_again).unwrap();
    }
}
