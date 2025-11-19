//! Implements the witness vector, referred to as W in the specification.

use crate::{
    circuit::{Circuit, CircuitLayer},
    fields::FieldElement,
    sumcheck::Polynomial,
};
use std::ops::Range;

/// The layout of the witness vector W. This is a 1D vector containing values known to the prover
/// but not the verifier:
///
///   - private inputs to the circuit (count depends on the circuit)
///   - one-time-pad for polynomials at each layer (2 * 2 * logw elements per circuit layer)
///   - one-time-pad for vl, vr and vl * vr for each layer of the circuit (three elements per
///     circuit layer)
///
/// The prover and verifier both manipulate these quantities symbolically, so this structure doesn't
/// actually contain witness values. Rather, it is used to determine where in the witness vector a
/// given value occurs so that the right challenge value can be looked up later.
#[derive(Debug, Clone)]
pub struct WitnessLayout {
    /// The number of private inputs to the circuit.
    num_private_inputs: usize,
    /// The number of polynomial evaluations on each layer.
    logw: Vec<usize>,
}

impl WitnessLayout {
    pub fn from_circuit(circuit: &Circuit) -> Self {
        Self::new(
            circuit.num_private_inputs(),
            circuit.layers.iter().map(CircuitLayer::logw).collect(),
        )
    }

    pub fn new(num_private_inputs: usize, logw: Vec<usize>) -> Self {
        Self {
            num_private_inputs,
            logw,
        }
    }

    /// Indices of the witnesses for private inputs.
    pub fn private_input_witness_indices(&self) -> Range<usize> {
        0..self.num_private_inputs
    }

    /// Indices of the witnesses for `vl`, `vr` and `vl * vr` at the given layer.
    pub fn wire_witness_indices(&self, layer: usize) -> (usize, usize, usize) {
        assert!(layer < self.logw.len());

        let start = self.num_private_inputs // skip past private inputs
            // skip vl, vr, vl*vr for each layer except this one
            + layer * 3
            // skip the polynomials (2 elements, 2 hands) for each layer, including this one
            + 2 * 2 * self.logw.iter().take(layer + 1).sum::<usize>();

        // vl, vr and vl * vr are always adjacent in the witness vector.
        (start, start + 1, start + 2)
    }

    /// Indices of the witnesses for the polynomial at the given layer, round and hand. There is a
    /// witness for each of p0 and p2.
    pub fn polynomial_witness_indices(
        &self,
        layer: usize,
        round: usize,
        hand: usize,
    ) -> (usize, usize) {
        assert!(layer < self.logw.len());
        assert!(round < self.logw[layer]);
        assert!(hand < 2);

        let start = self.num_private_inputs // skip past private inputs
            // skip vl, vr, vl*vr for each layer except this one
            + layer * 3
            // skip the polynomials (2 elements, 2 hands) for each layer except this one
            + 2 * 2 * self.logw.iter().take(layer).sum::<usize>()
            // skip the polynomials for each round except this one
            + 2 * 2 * round
            // skip the polynomials for each hand except this one
            + 2 * hand;

        // p0 and p2 are always adjacent in the witness vector
        (start, start + 1)
    }

    /// Total length of the witness vector.
    pub fn length(&self) -> usize {
        self.num_private_inputs
            // three wire witnesses per layer
            + self.logw.len() * 3
            // four polynomial witnesses per logw
            + 4 * self.logw.iter().sum::<usize>()
    }
}

/// The contents of the witness vector W. This is a 1D vector containing values known to the prover
/// but not the verifier:
///
///   - private inputs to the circuit (count depends on the circuit)
///   - one-time-pad for polynomials at each layer (2 * 2 * logw elements per circuit layer)
///   - one-time-pad for vl, vr and vl * vr for each layer of the circuit (three elements per
///     circuit layer)
pub struct Witness<FieldElement> {
    values: Vec<FieldElement>,
    layout: WitnessLayout,
}

impl<FE: FieldElement> Witness<FE> {
    /// Number of field elements in the witness.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Construct a witness vector for the layout, generating pad values.
    pub fn fill_witness<PadGenerator: FnMut() -> FE>(
        layout: WitnessLayout,
        private_inputs: &[FE],
        mut pad_generator: PadGenerator,
    ) -> Self {
        let mut witnesses = Vec::with_capacity(layout.length());

        // Witness vector starts with private inputs
        witnesses.extend(private_inputs);

        for layer_logw in &layout.logw {
            // Polynomial pads p0, p2 for each round in layer
            for _ in 0..*layer_logw {
                for _ in 0..2 {
                    witnesses.push(pad_generator());
                    witnesses.push(pad_generator());
                }
            }

            // vl, vr, vl*vr pads for each layer
            let vl = pad_generator();
            let vr = pad_generator();
            witnesses.push(vl);
            witnesses.push(vr);
            witnesses.push(vl * vr);
        }

        Self {
            values: witnesses,
            layout,
        }
    }

    /// Witnesses (pad values) for the polynomial at the given layer, round and hand.
    pub fn polynomial_witnesses(&self, layer: usize, round: usize, hand: usize) -> Polynomial<FE> {
        let (p0, p2) = self.layout.polynomial_witness_indices(layer, round, hand);
        Polynomial {
            p0: self.element(p0),
            p2: self.element(p2),
        }
    }

    /// Pads for the wires at the given layer.
    pub fn wire_witnesses(&self, layer: usize) -> (FE, FE, FE) {
        let (vl, vr, vl_vr) = self.layout.wire_witness_indices(layer);

        (self.element(vl), self.element(vr), self.element(vl_vr))
    }

    /// Get an element of the witness.
    pub fn element(&self, index: usize) -> FE {
        self.values[index]
    }

    /// Get an iterator over a range of witnesses, or zeroes if the witness index is undefined.
    pub fn elements(&self, start: usize, count: usize) -> impl Iterator<Item = FE> {
        self.values
            .iter()
            .skip(start)
            .copied()
            .chain(std::iter::repeat(FE::ZERO))
            .take(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fieldp128::FieldP128;
    #[cfg(panic = "unwind")]
    use std::panic::catch_unwind;

    #[test]
    fn witness_layout() {
        // private inputs:    private_input_0 | private_input_1 | private_input_2 |
        // layer 0: logw = 0: vl | vr | vl * vr
        // layer 1: logw = 3: p0_hand0_round0 | p2_hand0_round0 | p0_hand1_round0 | p2_hand1_round0
        //                  | p0_hand0_round1 | p2_hand0_round1 | p0_hand1_round1 | p2_hand1_round1
        //                  | p0_hand0_round2 | p2_hand0_round2 | p0_hand1_round2 | p2_hand1_round2
        //                  | vl | vr | vl * vr
        // layer 2: logw = 2: p0_hand0_round0 | p2_hand0_round0 | p0_hand1_round0 | p2_hand1_round0
        //                  | p0_hand0_round1 | p2_hand0_round1 | p0_hand1_round1 | p2_hand1_round1
        //                  | vl | vr | vl * vr
        let layout = WitnessLayout::new(3, vec![0, 3, 2]);

        let witness = Witness {
            values: (0..layout.length() as u128)
                .map(FieldP128::from_u128)
                .collect(),
            layout: layout.clone(),
        };

        assert_eq!(layout.private_input_witness_indices(), 0..3);

        let wire_ok = |layer, want_vl, want_vr, want_vl_vr| {
            assert_eq!(
                layout.wire_witness_indices(layer),
                (want_vl, want_vr, want_vl_vr)
            );
            assert_eq!(
                witness.wire_witnesses(layer),
                (
                    FieldP128::from_u128(want_vl as u128),
                    FieldP128::from_u128(want_vr as u128),
                    FieldP128::from_u128(want_vl_vr as u128)
                )
            );
        };
        #[cfg_attr(not(panic = "unwind"), allow(unused_variables))]
        let wire_bad = |layer| {
            #[cfg(panic = "unwind")]
            {
                catch_unwind(|| layout.wire_witness_indices(layer)).unwrap_err();
                catch_unwind(|| witness.wire_witnesses(layer)).unwrap_err();
            }
        };
        let poly_ok = |layer, round, hand, want_p0, want_p2| {
            assert_eq!(
                layout.polynomial_witness_indices(layer, round, hand),
                (want_p0, want_p2)
            );
            assert_eq!(
                witness.polynomial_witnesses(layer, round, hand),
                Polynomial {
                    p0: FieldP128::from_u128(want_p0 as u128),
                    p2: FieldP128::from_u128(want_p2 as u128),
                }
            )
        };
        #[cfg_attr(not(panic = "unwind"), allow(unused_variables))]
        let poly_bad = |layer, round, hand| {
            #[cfg(panic = "unwind")]
            {
                catch_unwind(|| layout.polynomial_witness_indices(layer, round, hand)).unwrap_err();
                catch_unwind(|| witness.polynomial_witnesses(layer, round, hand)).unwrap_err();
            }
        };

        // Layer 0. No polynomials on layer 0.
        poly_bad(0, 0, 0);
        wire_ok(0, 3, 4, 5);

        // Layer 1.
        poly_ok(1, 0, 0, 6, 7);
        poly_ok(1, 0, 1, 8, 9);
        poly_ok(1, 1, 0, 10, 11);
        poly_ok(1, 1, 1, 12, 13);
        poly_ok(1, 2, 0, 14, 15);
        poly_ok(1, 2, 1, 16, 17);
        // Round 3 does not exist.
        poly_bad(1, 3, 0);
        // Hand 2 does not exist
        poly_bad(1, 0, 2);
        wire_ok(1, 18, 19, 20);

        // Layer 2.
        poly_ok(2, 0, 0, 21, 22);
        poly_ok(2, 0, 1, 23, 24);
        poly_ok(2, 1, 0, 25, 26);
        poly_ok(2, 1, 1, 27, 28);
        // Round 2 does not exist.
        poly_bad(2, 2, 0);
        wire_ok(2, 29, 30, 31);

        // Layer 3 does not exist.
        poly_bad(3, 0, 0);
        wire_bad(3);

        assert_eq!(layout.length(), 32);
        assert_eq!(layout.length(), witness.values.len());
    }
}
