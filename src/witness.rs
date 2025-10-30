//! Implements the witness vector, referred to as W in the specification.

use crate::circuit::{Circuit, CircuitLayer};
use std::ops::Range;

/// The witness vector W. This is a 1D vector containing values known to the prover but not the
/// verifier:
///
///   - private inputs to the circuit (count depends on the circuit)
///   - one-time-pad for polynomials at each layer (2 * 2 * logw elements per circuit layer)
///   - one-time-pad for vl, vr and vl * vr for each layer of the circuit (three elements per
///     circuit layer)
///
/// The prover and verifier both manipulate these quantities symbolically, so this structure doesn't
/// actually contain witness values. Rather, it is used to determine where in the witness vector a
/// given value occurs so that the right challenge value can be looked up later.
pub(crate) struct WitnessLayout {
    /// The number of private inputs to the circuit.
    num_private_inputs: usize,
    /// The number of polynomial evaluations on each layer.
    logw: Vec<usize>,
}

impl WitnessLayout {
    pub(crate) fn from_circuit(circuit: &Circuit) -> Self {
        Self::new(
            circuit.num_private_inputs(),
            circuit.layers.iter().map(CircuitLayer::logw).collect(),
        )
    }

    pub(crate) fn new(num_private_inputs: usize, logw: Vec<usize>) -> Self {
        Self {
            num_private_inputs,
            logw,
        }
    }

    /// Indices of the witnesses for private inputs.
    pub(crate) fn private_input_witness_indices(&self) -> Range<usize> {
        0..self.num_private_inputs
    }

    /// Indices of the witnesses for `vl`, `vr` and `vl * vr` at the given layer.
    pub(crate) fn wire_witness_indices(&self, layer: usize) -> (usize, usize, usize) {
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
    pub(crate) fn polynomial_witness_indices(
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
    pub(crate) fn length(&self) -> usize {
        self.num_private_inputs
            // three wire witnesses per layer
            + self.logw.len() * 3
            // four polynomial witnesses per logw
            + 4 * self.logw.iter().sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use super::*;

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

        assert_eq!(layout.private_input_witness_indices(), 0..3);

        // Layer 0. No polynomials on layer 0.
        catch_unwind(|| layout.polynomial_witness_indices(0, 0, 0)).unwrap_err();
        assert_eq!(layout.wire_witness_indices(0), (3, 4, 5));

        // Layer 1.
        assert_eq!(layout.polynomial_witness_indices(1, 0, 0), (6, 7));
        assert_eq!(layout.polynomial_witness_indices(1, 0, 1), (8, 9));
        assert_eq!(layout.polynomial_witness_indices(1, 1, 0), (10, 11));
        assert_eq!(layout.polynomial_witness_indices(1, 1, 1), (12, 13));
        assert_eq!(layout.polynomial_witness_indices(1, 2, 0), (14, 15));
        assert_eq!(layout.polynomial_witness_indices(1, 2, 1), (16, 17));
        // Round 3 does not exist.
        catch_unwind(|| layout.polynomial_witness_indices(1, 3, 0)).unwrap_err();
        // Hand 2 does not exist
        catch_unwind(|| layout.polynomial_witness_indices(1, 0, 2)).unwrap_err();
        assert_eq!(layout.wire_witness_indices(1), (18, 19, 20));

        // Layer 2.
        assert_eq!(layout.polynomial_witness_indices(2, 0, 0), (21, 22));
        assert_eq!(layout.polynomial_witness_indices(2, 0, 1), (23, 24));
        assert_eq!(layout.polynomial_witness_indices(2, 1, 0), (25, 26));
        assert_eq!(layout.polynomial_witness_indices(2, 1, 1), (27, 28));
        // Round 2 does not exist.
        catch_unwind(|| layout.polynomial_witness_indices(2, 2, 0)).unwrap_err();
        assert_eq!(layout.wire_witness_indices(2), (29, 30, 31));

        // Layer 3 does not exist.
        catch_unwind(|| layout.polynomial_witness_indices(3, 0, 0)).unwrap_err();
        catch_unwind(|| layout.wire_witness_indices(3)).unwrap_err();

        assert_eq!(layout.length(), 32);
    }
}
