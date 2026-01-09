//! Implements a sparse array specialized for Sumcheck. The entries of the array are quads,
//! indexed by gate number, left wire index and right wire index, and whose value is a coefficient.
//!
//! # Binding to left and right wires in sparse sumcheck arrays
//!
//! Sumcheck as laid out in [draft-google-cfrg-libzk-01 section 6][1] requires repeatedly binding
//! the sumcheck array, alternating between the left wire and right wire dimensions.
//!
//! Recall the definition of `bind(A, x)` in 6.1:
//!
//! ```no_compile
//! B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
//! ```
//!
//! This means B will be about half the length of A. In a dense array, we can easily determine where
//! `A[2i]` and `A[2i+1]` are (or, if A isn't that long, determine by the sumcheck array convention
//! that they are zero). Thus our approach would be to iterate over `B[i]`, looking forward to
//! `A[2 * i]` and `A[2 * i + 1]` to compute values. This is what we do in
//! [`crate::sumcheck::bind`]. But our array is sparse, so for each i we would have to walk the
//! array forward to find out where 2i or 2i+1 are, if present in the array at all.
//!
//! So instead, we work backward: iterate over the values that do exist in the sparse array,
//! treating them as either the 2i-th or 2i+1-th elements, and then computing their contribution to
//! the i-th element of the bound array. See [`SparseSumcheckArray::bind_hand`].
//!
//! For this to work, we need element `(g, 2i+1, r)`, if it is present in the sparse array, to be
//! immediately after element `(g, 2i, r)` for all `g, r`. Analogously, when binding the `r`
//! dimension, we need `(g, l, 2i)` and `(g, l, 2i+1)` to be adjacent.
//!
//! The other challenge is alternating the dimension we bind over. In the spec's pseudocode, this is
//! achieved by transposing the inner 2D array at the end of every iteration, so that on the next
//! iteration, the outermost dimension will be the one we want to bind on.
//!
//! We can address both these challenges (adjacency and alternation) by judiciously sorting the
//! sparse array.
//!
//! For example, let's suppose we have an array of 9 elements, all nonzero (i.e. the sparse array is
//! also 9 elements):
//!
//! ```no_compile
//! [[a, b, c]
//!  [d, e, f]
//!  [g, h, i]]
//! ```
//!
//! Here all elemetns have gate_index = 0, and in practice this is case when we're binding the
//! quad in the inner sumcheck loop.
//!
//! The most straightforward representation is to sort lexicographically by `(g, l, r)`, in that
//! order:
//!
//! ```no_compile
//! g: 0 l: 00 r: 00 v: a
//! g: 0 l: 00 r: 01 v: b
//! g: 0 l: 00 r: 10 v: c
//! g: 0 l: 01 r: 00 v: d
//! g: 0 l: 01 r: 01 v: e
//! g: 0 l: 01 r: 10 v: f
//! g: 0 l: 10 r: 00 v: g
//! g: 0 l: 10 r: 01 v: h
//! g: 0 l: 10 r: 10 v: i
//! ```
//!
//! We show indices in binary for reasons that will become clear soon.
//!
//! But this is no good: we bind on l first, so we want `[0, 1, 0]` to be immediately after
//! [0, 0, 0]. Here, we have [0, 0, 1] and [0, 0, 2] in between. So we might instead sort by
//! `(g, l, r)`:
//!
//! ```no_compile
//! g: 0 l: 00 r: 00 v: a
//! g: 0 l: 01 r: 00 v: d
//! g: 0 l: 10 r: 00 v: g
//! g: 0 l: 00 r: 01 v: b
//! g: 0 l: 01 r: 01 v: e
//! g: 0 l: 10 r: 01 v: h
//! g: 0 l: 00 r: 10 v: c
//! g: 0 l: 01 r: 10 v: f
//! g: 0 l: 10 r: 10 v: i
//! ```
//!
//! This is better: now we can bind on `l` because `[0, 0, 0]` and `[0, 1, 0]` are adjacent.
//! [0, 2, 0] doesn't come after [0, 1, 0], but that's okay, because it doesn't appear anywhere in
//! the sparse array. After binding to the left wires, the array will look like:
//!
//! ```no_compile
//! g: 0 l: 00 r: 00
//! g: 0 l: 01 r: 00
//! g: 0 l: 00 r: 01
//! g: 0 l: 01 r: 01
//! g: 0 l: 00 r: 10
//! g: 0 l: 01 r: 10
//! ```

//! (We stop including the values `v` because now they start to become complex expressions that
//! distract more than they help.)
//!
//! But now we're stuck, because `[0, 0, 0]` and `[0, 0, 1]` are not adjacent, so we can't bind on
//! `r`. But notice that the bound array is about half the size it was before. Can we sort the
//! initial array such that it's set up for binding on `l`, and then binding knocks out the elements
//! between the adjacent elements in the `r` dimension? Yes, by sorting by the interleaved bits of
//! `r` and `l`, in that order!
//!
//! e.g., `l = 0011` and `r = 1100` becomes `10100101`.
//!
//! Here's the initial array, reordered by the interleaving of `r` and `l`.
//!
//! ```no_compile
//!                               r0 l0 r1 l1
//! g: 0 l: 00 r: 00 interleaved: 0  0  0  0
//! g: 0 l: 01 r: 00 interleaved: 0  0  0  1
//! g: 0 l: 00 r: 01 interleaved: 0  0  1  0
//! g: 0 l: 01 r: 01 interleaved: 0  0  1  1
//! g: 0 l: 10 r: 00 interleaved: 0  1  0  0
//! g: 0 l: 10 r: 01 interleaved: 0  1  1  1
//! g: 0 l: 00 r: 10 interleaved: 1  0  0  0
//! g: 0 l: 01 r: 10 interleaved: 1  0  0  1
//! g: 0 l: 10 r: 10 interleaved: 1  1  0  0
//! ```
//!
//! After binding on `l`, we get:
//!
//! ```no_compile
//!                               r0 l0 r1 l1
//! g: 0 l: 00 r: 00 interleaved: 0  0  0  0
//! g: 0 l: 00 r: 01 interleaved: 0  0  1  0
//! g: 0 l: 01 r: 00 interleaved: 0  0  0  1
//! g: 0 l: 01 r: 01 interleaved: 0  0  1  1
//! g: 0 l: 00 r: 10 interleaved: 1  0  0  0
//! g: 0 l: 01 r: 10 interleaved: 1  0  0  1
//! ```
//!
//! The array is no longer sorted by the interleavings of the current `l`, `r`, but it *does* have
//! the adjacency property we want in `r`! And if we bind on `r`, we restore adjacency on `l`, and
//! can bind to our heart's content.
//!
//! ```no_compile
//! g: 0 l: 00 r: 00
//! g: 0 l: 01 r: 00
//! g: 0 l: 00 r: 01
//! g: 0 l: 01 r: 01
//! ```
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6

use crate::{fields::FieldElement, sumcheck::bind::SumcheckArray};
use std::cmp::Ordering;

/// A sparse 3D array indexed by `g` (gate number), `l` (input left wire index) and `r` (input right
/// wire index) where the value is a coefficient. See [1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.3.2
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparseSumcheckArray<FE> {
    contents: Vec<SparseQuadElement<FE>>,
    /// The hand over which the next binding may occur.
    next_bind: Hand,
}

/// The handedness of an input wire. Also the dimensions over which the inner 2D array is bound.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Hand {
    #[default]
    Left = 0,
    Right,
}

impl Hand {
    /// Return the hand opposite to `self`.
    fn opposite(&self) -> Self {
        match self {
            Hand::Left => Hand::Right,
            Hand::Right => Hand::Left,
        }
    }
}

/// An individual quad in the circuit. Unlike [`crate::circuit::Quad`], which contains an index into
/// a constant table, this contains an actual value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseQuadElement<FE> {
    pub gate_index: usize,
    pub left_wire_index: usize,
    pub right_wire_index: usize,
    pub coefficient: FE,
}

impl<'a, FE: FieldElement> SparseQuadElement<FE> {
    /// A new sparse quad element, assigning the wire indices based on the indicated handedness.
    fn new(
        gate_index: usize,
        hand: Hand,
        hand_wire: usize,
        opposite_hand_wire: usize,
        coefficient: FE,
    ) -> Self {
        assert_ne!(
            coefficient,
            FE::ZERO,
            "sparse array should not contain elements with zero coefficient",
        );
        let (left_wire_index, right_wire_index) = match hand {
            Hand::Left => (hand_wire, opposite_hand_wire),
            Hand::Right => (opposite_hand_wire, hand_wire),
        };
        Self {
            gate_index,
            left_wire_index,
            right_wire_index,
            coefficient,
        }
    }

    /// Returns the wire index on the given hand.
    fn hand_wire(&self, hand: Hand) -> usize {
        match hand {
            Hand::Left => self.left_wire_index,
            Hand::Right => self.right_wire_index,
        }
    }

    /// Returns `Some` if `other` is the next wire in the indicated handedness, but same in the
    /// other dimensions (`g` and the opposite hand).
    ///
    /// e.g. `[0, 1, 0]` is the next `Hand::Left` wire to `[0, 0, 0]`, but not to `[0, 0, 1]`.
    /// `[2, 1, 1]` is the next `Hand::Right` wire to `[2, 1, 0]` but not to `[2, 2, 0]`.
    fn is_next_wire(
        &self,
        hand: Hand,
        other: Option<&'a SparseQuadElement<FE>>,
    ) -> Option<&'a SparseQuadElement<FE>> {
        if let Some(other) = other
            && other.gate_index == self.gate_index
            && other.hand_wire(hand) == self.hand_wire(hand) + 1
            && other.hand_wire(hand.opposite()) == self.hand_wire(hand.opposite())
        {
            Some(other)
        } else {
            None
        }
    }
}

impl<FE: FieldElement> PartialOrd for SparseQuadElement<FE> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<FE: FieldElement> Ord for SparseQuadElement<FE> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort the array using the lexicographic ordering of the gate index and the interleaving of
        // the bits of the right wire and left wire indices (in that order). See the module level
        // comment for discussion.
        //
        // We interleave into a u128 because that's big enough to fit all the bits of two usizes on
        // any platform we're likely to deploy to.
        fn interleave(right: usize, left: usize) -> u128 {
            if usize::BITS > 64 {
                panic!("usize on this platform is too big to interleave into u128")
            }
            let mut interleaved = 0u128;
            for bit in (0..usize::BITS).rev() {
                let mask = 1 << bit;
                interleaved += (right as u128 & mask) << (bit + 1);
                interleaved += (left as u128 & mask) << (bit);
            }

            interleaved
        }
        // Using the `Ord` impl on `[T]` gives us lexicographic ordering over the slice elements.
        [
            self.gate_index as u128,
            interleave(self.right_wire_index, self.left_wire_index),
        ]
        .cmp(&[
            other.gate_index as u128,
            interleave(other.right_wire_index, other.left_wire_index),
        ])
    }
}

impl<FE: FieldElement> From<Vec<SparseQuadElement<FE>>> for SparseSumcheckArray<FE> {
    fn from(mut contents: Vec<SparseQuadElement<FE>>) -> Self {
        contents.sort();
        Self {
            contents,
            next_bind: Hand::Left,
        }
    }
}

impl<FE: FieldElement> From<Vec<Vec<Vec<FE>>>> for SparseSumcheckArray<FE> {
    fn from(value: Vec<Vec<Vec<FE>>>) -> Self {
        // Assumes that the value is a non-sparse array of coefficients indexed by g, l, r
        let mut contents = Vec::default();
        for (gate_index, lefts) in value.iter().enumerate() {
            for (left_wire_index, rights) in lefts.iter().enumerate() {
                for (right_wire_index, coefficient) in rights
                    .iter()
                    .enumerate()
                    // omit zero coefficients from sparse array
                    .filter(|(_, e)| **e != FE::ZERO)
                {
                    contents.push(SparseQuadElement {
                        gate_index,
                        left_wire_index,
                        right_wire_index,
                        coefficient: *coefficient,
                    });
                }
            }
        }

        Self::from(contents)
    }
}

impl<FE: FieldElement> From<Vec<Vec<FE>>> for SparseSumcheckArray<FE> {
    fn from(value: Vec<Vec<FE>>) -> Self {
        // Make a 2D array into 3D by setting gate_index = 0 for all values
        Self::from(vec![value])
    }
}

impl<FE: FieldElement> PartialEq<Vec<Vec<FE>>> for SparseSumcheckArray<FE> {
    /// Assumes that `dense` is the dense representation of a sumcheck array that has been bound
    /// to two dimensions.
    fn eq(&self, dense: &Vec<Vec<FE>>) -> bool {
        let mut dense_nonzero_count = 0;
        for x in dense {
            for y in x {
                if *y != FE::ZERO {
                    dense_nonzero_count += 1;
                }
            }
        }
        if self.contents.len() != dense_nonzero_count {
            return false;
        }

        for element in &self.contents {
            if element.gate_index != 0 {
                // Comparing a 3D sparse array to a 2D dense array only works if all gate_index = 0
                return false;
            }
            if dense[element.left_wire_index][element.right_wire_index] != element.coefficient {
                return false;
            }
        }

        true
    }
}

impl<FE: FieldElement> SparseSumcheckArray<FE> {
    /// Bind this array to `binding` in the dimension indicated by `hand`, in-place. That is, if
    /// `hand == Hand::Left`, bind `self[g, 2i, r]` and `self[g, 2i+1, r]` into `self[g, i, r]` for
    /// all g, r. If `hand == Hand::Right`, bind `self[g, l, 2i]` and`self[g, l, 2i+i]` into
    /// `self[g, l, i]`.
    ///
    /// This can only be used once the `gate_index` dimension has been bound down to a single
    /// element. That is, `gate_index == 0` for all elements in the array.
    pub fn bind_hand(&mut self, hand: Hand, binding: FE) {
        // Binding is stateful: based on the currently layout of the contents, we can only bind over
        // either l or r. Make sure the caller is on the correct hand.
        assert_eq!(
            self.next_bind, hand,
            "array cannot currently be bound to {hand:?}",
        );
        self.next_bind = self.next_bind.opposite();

        // Walk the elements of the array and work out what bound elements they contribute to. See
        // the module level comment for discussion of this strategy.
        //
        // We bind in place. If we are visiting element 2i or 2i+1 of the array in the dimension
        // indicated by hand, then we've already visited anything that might contribute to elements
        // j < i of the bound array and thus it's safe to overwrite anything between j and 2i.
        let mut write = 0;
        let mut read = 0;
        while read < self.contents.len() {
            let curr = self.contents[read];
            let next = self.contents.get(read + 1);
            assert_eq!(
                curr.gate_index, 0,
                "sparse array should have been bound down to 2D before binding a hand",
            );

            // If element 2i+1 is in the array, it will be immediately after element 2i. See the
            // module level doccomment for an explanation of how we sort the sparse array to impose
            // this invariant.
            let (coeff_2i, coeff_2i_plus_1) = if let Some(next) = curr.is_next_wire(hand, next)
                && curr.hand_wire(hand).is_multiple_of(2)
            {
                // curr and next are 2i and 2i+1, respectively
                assert_eq!(
                    next.gate_index, 0,
                    "sparse array should have been bound down to 2D before binding a hand",
                );
                read += 2;
                (curr.coefficient, next.coefficient)
            } else {
                read += 1;
                if curr.hand_wire(hand).is_multiple_of(2) {
                    // curr is 2i, sparse array does not contain 2i+1
                    (curr.coefficient, FE::ZERO)
                } else {
                    // curr is 2i+1, sparse array does not contain 2i
                    (FE::ZERO, curr.coefficient)
                }
            };

            // Don't bother writing elements with zero coefficient
            let coefficient = (FE::ONE - binding) * coeff_2i + binding * coeff_2i_plus_1;
            if coefficient != FE::ZERO {
                self.contents[write] = SparseQuadElement::new(
                    0,
                    hand,
                    // 2i-th or 2i+1-th element contributes to the i-th bound element
                    curr.hand_wire(hand) >> 1,
                    curr.hand_wire(hand.opposite()),
                    coefficient,
                );
                write += 1;
            }
        }

        // Truncate the sparse array, which effectively zeroes out all elements of the original
        // array we didn't overwrite.
        self.contents.truncate(write);
    }

    /// Compare the sparse array to a dense array, accounting for whether the dense array has been
    /// transposed
    pub fn compare_bound_array(&self, hand: Hand, dense: &Vec<Vec<FE>>) {
        if hand == Hand::Right {
            assert_eq!(*self, dense.transpose());
        } else {
            assert_eq!(self, dense);
        }
    }
}
