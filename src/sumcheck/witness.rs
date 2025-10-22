//! Implements the witness vector, referred to as W in the specification.

use std::ops::Range;

/// The witness vector W. This is a 1D vector containing values known to the prover but not the
/// verifier:
///
///   - private inputs to the circuit (count depends on the circuit)
///   - polynomials at each layer (2 * logw elements per circuit layer)
///   - vl, vr and vl * vr for each layer of the circuit (three elements per circuit layer)
///
/// The prover and verifier both manipulate these quantities symbolically (see
/// [`sumcheck::symbolic::SymbolicExpression`]), so this structure doesn't actually contain witness
/// values. Rather, it is used to determine where in the witness vector a given value occurs so that
/// the right challenge value can be looked up later.
pub(crate) struct WitnessLayout {
    /// The number of private inputs to the circuit.
    num_private_inputs: usize,
    /// The number of polynomial evaluations on each layer.
    logw: Vec<usize>,
}

impl WitnessLayout {
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
            + layer * 3 // skip vl, vr, vl*vr for each layer except this one
            // skip the polynomials (2 elements) for each layer, including this one
            + 2 * self.logw.iter().take(layer + 1).sum::<usize>();

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
        + layer * 3 // skip vl, vr, vl*vr for each layer except this one
        + 2 * (round - 1) + hand;

        // p0 and p2 are always adjacent in the witness vector
        (start, start + 1)
    }
}
