//! Sumcheck prover.

use crate::{
    ParameterizedCodec,
    circuit::{Circuit, CircuitLayer, Evaluation},
    fields::{CodecFieldElement, ProofFieldElement},
    sumcheck::{
        Polynomial,
        bind::{DenseSumcheckArray, sparse::Hand},
    },
    transcript::Transcript,
    witness::Witness,
};
use anyhow::anyhow;
use std::{borrow::Cow, io::Write};

/// Generate a sumcheck proof of evaluation of a circuit.
#[derive(Clone, Debug)]
pub struct SumcheckProver<'a, FE> {
    circuit: &'a Circuit<FE>,
}

/// Sumcheck proof plus some extra data useful for validation.
#[derive(Clone, Debug)]
pub struct ProverResult<FE> {
    /// The sumcheck proof from which Ligero constraints may be generated.
    pub proof: SumcheckProof<FE>,
    /// The transcript after all the proof messages have been written to it.
    pub transcript: Transcript,
}

impl<'a, FE: ProofFieldElement> SumcheckProver<'a, FE> {
    pub fn new(circuit: &'a Circuit<FE>) -> Self {
        Self { circuit }
    }

    /// Construct a padded proof of the transcript of the given evaluation of the circuit and return
    /// the prover messages needed for the verifier to reconstruct the transcript.
    pub fn prove(
        &self,
        evaluation: &Evaluation<FE>,
        transcript: &mut Transcript,
        witness: &Witness<FE>,
    ) -> Result<ProverResult<FE>, anyhow::Error> {
        // Specification interpretation verification: all the outputs should be zero
        for output in evaluation.outputs() {
            assert_eq!(output, &FE::ZERO);
        }

        if evaluation.inputs().len() != self.circuit.num_inputs() {
            return Err(anyhow!("wrong number of inputs"));
        }

        // Choose the bindings for the output layer.
        let output_wire_bindings = transcript.generate_output_wire_bindings(self.circuit)?;
        let mut bindings = [output_wire_bindings.clone(), output_wire_bindings];

        let mut proof = SumcheckProof {
            layers: Vec::with_capacity(self.circuit.num_layers()),
        };

        for (layer_index, layer) in self.circuit.layers.iter().enumerate() {
            // Choose alpha and beta for this layer
            let alpha = transcript.generate_challenge(1)?[0];
            let beta = transcript.generate_challenge(1)?[0];

            // The combined quad, aka QZ[g, l, r], a three dimensional array.
            let mut quad = self.circuit.combined_quad(layer_index, beta)?;

            // Bind the combined quad to G.
            quad.bindv_gate(&bindings[0], &bindings[1], alpha);

            // Allocate room for the new bindings this layer will generate
            let mut new_bindings = [vec![FE::ZERO; layer.logw()], vec![FE::ZERO; layer.logw()]];

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
            let mut wires = [
                evaluation.wires[layer_index + 1].clone(),
                evaluation.wires[layer_index + 1].clone(),
            ];

            for (round, proof_polynomials) in layer_proof_polynomials.iter_mut().enumerate() {
                for hand in [Hand::Left, Hand::Right] {
                    // Implements the polynomial from the specification:
                    // Let p(x) = SUM_{l, r} bind(QUAD, x)[l, r] * bind(VL, x)[l] * VR[r]
                    let evaluate_polynomial = |at: FE| {
                        // Bind a *copy* of the quad
                        let mut sparse_bound_quad_clone = quad.clone();
                        // Binding to alternating hands is equivalent to transposing the array at
                        // each iteration and binding to the outermost dimension.
                        sparse_bound_quad_clone.bind_hand(hand, at);

                        // SUM_{l, r} is interpreted to mean evaluating the expression at all
                        // possible left and right wire indices.
                        // In sumcheck terms, we're evaluating the function at each of the vertices
                        // of a 2*logw-dimensional unit hypercube, or evaluating the function at all
                        // possible 2*logw length bitstrings.
                        // But since we use a sparse array, we can skip all the bitstrings where the
                        // coefficient is known to be zero.
                        // The specification instructs us to swap the left and right wire arrays at
                        // each iteration and always bind to the left. We instead bind the wire
                        // array corresponding to the current hand.
                        // Use Cow to avoid copying whichever wires array we're not binding.
                        let mut bound_wires = [Cow::from(&wires[0]), Cow::from(&wires[1])];
                        bound_wires[hand as usize].to_mut().bind(at);

                        sparse_bound_quad_clone
                            .contents()
                            .iter()
                            .fold(FE::ZERO, |acc, element| {
                                acc + element.coefficient
                                    * bound_wires[Hand::Left as usize][element.left_wire_index]
                                    * bound_wires[Hand::Right as usize][element.right_wire_index]
                            })
                    };

                    // Evaluate the polynomial at P0 and P2, subtracting the pad
                    let polynomial_pad =
                        witness.polynomial_witnesses(layer_index, round, hand as usize);
                    let poly_evaluation = Polynomial {
                        p0: evaluate_polynomial(FE::ZERO) - polynomial_pad.p0,
                        p2: evaluate_polynomial(FE::SUMCHECK_P2) - polynomial_pad.p2,
                    };

                    // Commit to the padded polynomial.
                    transcript.write_polynomial(&poly_evaluation)?;

                    proof_polynomials[hand as usize] = poly_evaluation;

                    // Generate an element of the binding for the next layer.
                    let challenge = transcript.generate_challenge(1)?;

                    new_bindings[hand as usize][round] = challenge[0];

                    // Bind the current wires and the quad to the challenge
                    wires[hand as usize].bind(challenge[0]);
                    quad.bind_hand(hand, challenge[0]);
                }
            }

            // Specification interpretation verification: over the course of the loop above, we bind
            // bound_quad, left_wires and right_wires to single field elements enough times that all
            // should be reduced to a single non-zero element.
            assert_eq!(quad.contents().len(), 1);
            assert_eq!(quad.contents()[0].gate_index, 0);
            assert_eq!(quad.contents()[0].left_wire_index, 0);
            assert_eq!(quad.contents()[0].right_wire_index, 0);
            for left_wire in wires[Hand::Left as usize].iter().skip(1) {
                assert_eq!(
                    left_wire,
                    &FE::ZERO,
                    "left wires: {:#?}",
                    wires[Hand::Left as usize],
                );
            }
            for right_wire in wires[Hand::Right as usize].iter().skip(1) {
                assert_eq!(
                    right_wire,
                    &FE::ZERO,
                    "right wires: {:#?}",
                    wires[Hand::Right as usize],
                );
            }

            let (vl_pad, vr_pad, _) = witness.wire_witnesses(layer_index);

            let layer_proof = ProofLayer {
                polynomials: layer_proof_polynomials,
                vl: wires[Hand::Left as usize].element(0) - vl_pad,
                vr: wires[Hand::Right as usize].element(0) - vr_pad,
            };

            // Commit to the padded evaluations of l and r. The specification implies they are
            // written as individual field elements, but longfellow-zk writes them as an array.
            transcript.write_field_element_array(&[layer_proof.vl, layer_proof.vr])?;

            proof.layers.push(layer_proof);

            bindings = new_bindings;
        }

        Ok(ProverResult {
            proof,
            transcript: transcript.clone(),
        })
    }

    /// Return the circuit used by the prover.
    pub fn circuit(&self) -> &Circuit<FE> {
        self.circuit
    }
}

/// Proof constructed by sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof<FieldElement> {
    pub layers: Vec<ProofLayer<FieldElement>>,
}

impl<FE: CodecFieldElement> ParameterizedCodec<Circuit<FE>> for SumcheckProof<FE> {
    fn decode_with_param(
        circuit: &Circuit<FE>,
        bytes: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let mut proof_layers = Vec::with_capacity(circuit.num_layers());

        for circuit_layer in &circuit.layers {
            proof_layers.push(ProofLayer::decode_with_param(circuit_layer, bytes)?);
        }

        Ok(Self {
            layers: proof_layers,
        })
    }

    fn encode_with_param<W: Write>(
        &self,
        circuit: &Circuit<FE>,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        // Encode the layers as a fixed length array. That is, no length prefix.
        for (proof_layer, circuit_layer) in self.layers.iter().zip(&circuit.layers) {
            proof_layer.encode_with_param(circuit_layer, bytes)?;
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
impl<FE: CodecFieldElement> ParameterizedCodec<CircuitLayer> for ProofLayer<FE> {
    fn decode_with_param(
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

    fn encode_with_param<W: Write>(
        &self,
        _: &CircuitLayer,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
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
    use crate::{
        fields::{field2_128::Field2_128, fieldp128::FieldP128},
        sumcheck::initialize_transcript,
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        transcript::TranscriptMode,
        witness::WitnessLayout,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    fn prove<FE: ProofFieldElement>(test_vector: CircuitTestVector<FE>, circuit: Circuit<FE>) {
        assert_eq!(circuit.num_copies(), 1);

        let evaluation: Evaluation<FE> = circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad(),
        );

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
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
        let proof = SumcheckProver::new(&circuit)
            .prove(&evaluation, &mut transcript, &witness)
            .unwrap();

        let test_vector_proof = test_vector.sumcheck_proof(&circuit);

        // It's not terribly useful to print 1000s of bytes of proof to stderr so we avoid the usual
        // assert_eq! form.
        assert!(proof.proof == test_vector_proof);

        let proof_encoded = proof.proof.get_encoded_with_param(&circuit).unwrap();

        assert_eq!(
            proof_encoded.len(),
            test_vector.serialized_sumcheck_proof.len()
        );
        assert!(proof_encoded == test_vector.serialized_sumcheck_proof);
    }

    fn prove_input_length_validation<FE: ProofFieldElement>(
        test_vector: CircuitTestVector<FE>,
        circuit: Circuit<FE>,
    ) {
        let mut longer_input = test_vector.valid_inputs().to_vec();
        longer_input.push(FE::ZERO);

        let evaluation: Evaluation<FE> = circuit.evaluate(&longer_input).unwrap();

        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
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
        let error = SumcheckProver::new(&circuit)
            .prove(&evaluation, &mut transcript, &witness)
            .err()
            .unwrap();

        assert!(error.to_string().contains("wrong number of inputs"));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        prove::<FieldP128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b_input_validation() {
        let (test_vector, circuit) = load_rfc();
        prove_input_length_validation::<FieldP128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac() {
        let (test_vector, circuit) = load_mac();
        prove::<Field2_128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac_input_validation() {
        let (test_vector, circuit) = load_mac();
        prove_input_length_validation::<Field2_128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn roundtrip_encoded_proof() {
        let (test_vector, circuit) = load_rfc();
        let test_vector_decoded = SumcheckProof::<FieldP128>::get_decoded_with_param(
            &circuit,
            &test_vector.serialized_sumcheck_proof,
        )
        .unwrap();

        let test_vector_again = test_vector_decoded
            .get_encoded_with_param(&circuit)
            .unwrap();
        assert_eq!(test_vector.serialized_sumcheck_proof, test_vector_again);
    }
}
