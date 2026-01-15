//! Extension trait implementing sumcheck arrays and the `bind` functions from [1] on top of
//! `Vec<FieldElement>`.
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1

use crate::fields::FieldElement;

pub mod sparse;
#[cfg(test)]
pub mod test_vector;

/// An dense array of field elements conforming to the sumcheck array convention of [6.1][1]:
///
/// > The sumcheck array `A[i]` is implicitly assumed to be defined for all nonnegative integers i,
/// > padding with zeroes as necessary.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1
pub trait DenseSumcheckArray<FieldElement>: Sized {
    /// Retrieve the element at the index, or zero if no element is defined for the index.
    fn element(&self, index: usize) -> FieldElement;

    /// Bind a array of field elements to a single field element, in-place.
    ///
    /// This corresponds to `bind()` from [6.1][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1
    fn bind(&mut self, binding: FieldElement);
}

impl<FE: FieldElement> DenseSumcheckArray<FE> for Vec<FE> {
    fn element(&self, index: usize) -> FE {
        *self.get(index).unwrap_or(&FE::ZERO)
    }

    fn bind(&mut self, binding: FE) {
        assert!(
            self.len() > 1,
            "binding over a vector that's already reduced to a single element"
        );

        // B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
        // The back half of B[i] will always be zero so we can skip computing those elements
        let new_len = self.len().div_ceil(2);
        for index in 0..new_len {
            self[index] = (FE::ONE - binding) * self.element(2 * index)
                + binding * self.element(2 * index + 1);
        }

        self.truncate(new_len);
    }
}

/// Compute `bindv(EQ, bindings_0) + scale * bindv(EQ, bindings_1)` using `bindv(EQ_{n}, X) =
/// bindeq(l, X)` of [6.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.2
pub fn bindeq<FE: FieldElement>(bindings_0: &[FE], bindings_1: &[FE], scale: FE) -> Vec<FE> {
    let mut bindeq_0 = bindeq_inner(bindings_0);
    for (bindeq_0, bindeq_1) in bindeq_0.iter_mut().zip(bindeq_inner(bindings_1).iter()) {
        *bindeq_0 += scale * bindeq_1;
    }
    bindeq_0
}

/// Naive implementation of bindeq() from 6.2 ([1]). This binds `input` of length `l` to the
/// implicit `EQ_2^l` array.
///
/// # Bugs
///
/// We should rework this to avoid recursion ([2]).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.2
/// [2]: https://github.com/abetterinternet/zk-cred-longfellow/issues/41
fn bindeq_inner<FE: FieldElement>(input: &[FE]) -> Vec<FE> {
    let output_len = 1 << input.len();
    let mut bound = vec![FE::ZERO; output_len];

    if input.is_empty() {
        bound[0] = FE::ONE;
    } else {
        let a = bindeq_inner(&input[1..]);
        // usize::div rounds towards zero
        for index in 0..output_len / 2 {
            bound[2 * index] = (FE::ONE - input[0]) * a[index];
            bound[2 * index + 1] = input[0] * a[index];
        }
    }

    bound
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        field_element_tests,
        fields::{CodecFieldElement, FieldElement},
        sumcheck::bind::{
            DenseSumcheckArray, bindeq_inner,
            sparse::{Hand, SparseSumcheckArray},
            test_vector::{
                BindTestVector, Dense1DArrayBindTestCase, load_dense_1d_array_bind_2_128,
                load_dense_1d_array_bind_p128, load_dense_1d_array_bind_p256,
            },
        },
    };
    use std::iter::Iterator;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn dense_1d_array_bind_test_vector<FE: CodecFieldElement>(
        test_vector: BindTestVector<Dense1DArrayBindTestCase<FE>>,
    ) {
        for mut test_case in test_vector.test_cases {
            test_case.input.bind(test_case.binding);
            assert_eq!(
                test_case.input, test_case.output,
                "test case {} failed",
                test_case.description
            );
        }
    }

    #[test]
    fn dense_1d_array_bind_test_vector_p128() {
        dense_1d_array_bind_test_vector(load_dense_1d_array_bind_p128())
    }

    #[test]
    fn dense_1d_array_bind_test_vector_p256() {
        dense_1d_array_bind_test_vector(load_dense_1d_array_bind_p256())
    }

    #[test]
    fn dense_1d_array_bind_test_vector_2_128() {
        dense_1d_array_bind_test_vector(load_dense_1d_array_bind_2_128())
    }

    fn bindeq_equivalence<FE: FieldElement>() {
        // 6.2: bindv(EQ_{n}, X) = bindeq(l, X) for n = 2^l
        fn construct_eq<FE: FieldElement>(n: usize) -> Vec<Vec<FE>> {
            let mut eq_n = vec![vec![FE::ZERO; n]; n];

            for (i, row) in eq_n.iter_mut().enumerate() {
                for (j, element) in row.iter_mut().enumerate() {
                    *element = if i == j { FE::ONE } else { FE::ZERO };
                }
            }

            eq_n
        }

        for (binding, eq_n) in [
            (vec![FE::ONE], construct_eq(2)),
            (vec![FE::from_u128(217)], construct_eq(2)),
            (
                vec![FE::from_u128(217), FE::from_u128(11111)],
                construct_eq(4),
            ),
        ] {
            let mut sparse = <SparseSumcheckArray<FE> as From<Vec<Vec<FE>>>>::from(eq_n);
            for binding_element in &binding {
                sparse.bind_hand(Hand::Left, *binding_element);
            }
            for element in sparse.contents() {
                assert_eq!(element.gate_index, 0);
                assert_eq!(element.left_wire_index, 0);
            }

            for (index, element) in bindeq_inner(&binding).iter().enumerate() {
                let mut saw_element = false;
                for sparse_element in sparse.contents() {
                    if sparse_element.right_wire_index == index {
                        assert_eq!(sparse_element.coefficient, *element);
                        saw_element = true;
                    }
                }
                if *element == FE::ZERO {
                    assert!(!saw_element)
                } else {
                    assert!(saw_element);
                }
            }
        }
    }

    field_element_tests!(bindeq_equivalence);
}
