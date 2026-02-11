//! Test vectors for various bind implementations.
use crate::{
    field_element_tests,
    fields::{
        ProofFieldElement, field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256,
    },
    sumcheck::bind::{
        DenseSumcheckArray,
        sparse::{Hand, SparseSumcheckArray},
    },
};
use rand::{Rng, SeedableRng, TryRngCore, random};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use wasm_bindgen_test::wasm_bindgen_test;

/// Includes test vector files at compile time, and passes them to the relevant `decode()` method.
#[macro_export]
macro_rules! decode_bind_test_vector {
    ($test_vector_type:ident, $test_vector_name:expr $(,)?) => {
        $test_vector_type::decode(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-vectors/bind/",
            $test_vector_name,
            ".json"
        )))
    };
}

/// Test vector exercising sumcheck array binding.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BindTestVector<TestCase> {
    pub seed: u64,
    pub test_cases: Vec<TestCase>,
}

impl<'de, TestCase: Deserialize<'de>> BindTestVector<TestCase> {
    fn decode(json: &'de [u8]) -> Self {
        serde_json::from_slice(json).unwrap()
    }
}

/// Individual test case.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Dense1DArrayBindTestCase<FieldElement> {
    pub description: String,
    pub input: Vec<FieldElement>,
    pub binding: FieldElement,
    pub output: Vec<FieldElement>,
}

pub(crate) fn load_dense_1d_array_bind_p128() -> BindTestVector<Dense1DArrayBindTestCase<FieldP128>>
{
    decode_bind_test_vector!(BindTestVector, "dense_1d_array_bind_FieldP128")
}

pub(crate) fn load_dense_1d_array_bind_p256() -> BindTestVector<Dense1DArrayBindTestCase<FieldP256>>
{
    decode_bind_test_vector!(BindTestVector, "dense_1d_array_bind_FieldP256")
}

pub(crate) fn load_dense_1d_array_bind_2_128()
-> BindTestVector<Dense1DArrayBindTestCase<Field2_128>> {
    decode_bind_test_vector!(BindTestVector, "dense_1d_array_bind_Field2_128")
}

/// Test vector exercising binding a two dimensional sparse array of field elements to a series of
/// single field elements, alternating between binding the left wire and right wire dimensions.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Sparse2DArrayBindHandTestCase<FieldElement> {
    pub description: String,
    /// The input as a sparse 2D array. The gate index is assumed to be zero.
    pub input: SparseSumcheckArray<FieldElement>,
    pub bindings: Vec<FieldElement>,
    /// The bound array at each step. The outermost dimension is the same length as `bindings`.
    pub outputs: Vec<SparseSumcheckArray<FieldElement>>,
}

pub(crate) fn load_sparse_2d_array_bind_hand_p128()
-> BindTestVector<Sparse2DArrayBindHandTestCase<FieldP128>> {
    decode_bind_test_vector!(BindTestVector, "sparse_2d_array_bind_FieldP128")
}

pub(crate) fn load_sparse_2d_array_bind_hand_p256()
-> BindTestVector<Sparse2DArrayBindHandTestCase<FieldP256>> {
    decode_bind_test_vector!(BindTestVector, "sparse_2d_array_bind_FieldP256")
}

pub(crate) fn load_sparse_2d_array_bind_hand_2_128()
-> BindTestVector<Sparse2DArrayBindHandTestCase<Field2_128>> {
    decode_bind_test_vector!(BindTestVector, "sparse_2d_array_bind_Field2_128")
}

/// Test vector exercising binding a three dimensional sparse array of field elements to two vectors
/// of field elements along the gate dimension. This simulates computing the bound quad for each
/// sumcheck layer.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Sparse3DArrayBindGateTestCase<FieldElement> {
    pub description: String,
    pub input: SparseSumcheckArray<FieldElement>,
    pub bindings_0: Vec<FieldElement>,
    pub bindings_1: Vec<FieldElement>,
    pub alpha: FieldElement,
    pub output: SparseSumcheckArray<FieldElement>,
}

pub(crate) fn load_sparse_3d_array_bind_gate_p128()
-> BindTestVector<Sparse3DArrayBindGateTestCase<FieldP128>> {
    decode_bind_test_vector!(BindTestVector, "sparse_3d_array_bind_FieldP128")
}

pub(crate) fn load_sparse_3d_array_bind_gate_p256()
-> BindTestVector<Sparse3DArrayBindGateTestCase<FieldP256>> {
    decode_bind_test_vector!(BindTestVector, "sparse_3d_array_bind_FieldP256")
}

pub(crate) fn load_sparse_3d_array_bind_gate_2_128()
-> BindTestVector<Sparse3DArrayBindGateTestCase<Field2_128>> {
    decode_bind_test_vector!(BindTestVector, "sparse_3d_array_bind_Field2_128")
}

/// Portably deterministic RNG that generates field elements with some percentage of values being
/// zero.
struct TestVectorRng {
    rng: ChaCha20Rng,
}

impl TestVectorRng {
    fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    fn sample<FE: ProofFieldElement>(&mut self, sparseness: f64) -> FE {
        if self.rng.random_bool(sparseness) {
            return FE::ZERO;
        }
        FE::sample_from_source(|num_bytes| {
            let mut bytes = vec![0; num_bytes];
            self.rng.try_fill_bytes(&mut bytes).unwrap();

            bytes
        })
    }

    fn sample_n<FE: ProofFieldElement>(&mut self, n: usize, sparseness: f64) -> Vec<FE> {
        std::iter::repeat_with(|| self.sample(sparseness))
            .take(n)
            .collect()
    }
}

fn write_test_vector<TestCase: Serialize, FieldElement>(
    test_vector: BindTestVector<TestCase>,
    filename_prefix: &'static str,
) {
    if Ok("1") == std::env::var("ZK_CRED_LONGFELLOW_WRITE_TEST_VECTOR_FILES").as_deref() {
        let test_vector_path = format!(
            "{}/test-vectors/bind/{}_{}.json",
            env!("CARGO_MANIFEST_DIR"),
            filename_prefix,
            std::any::type_name::<FieldElement>()
                .rsplit("::")
                .next()
                .unwrap()
        );
        println!("writing test vector to {test_vector_path}");
        serde_json::to_writer_pretty(&mut File::create(test_vector_path).unwrap(), &test_vector)
            .unwrap();
    } else {
        println!("{}", serde_json::to_string_pretty(&test_vector).unwrap());
    }
}

fn generate_1d_dense_array_bind_test_vector_with_seed<FE: ProofFieldElement>(
    seed: u64,
) -> BindTestVector<Dense1DArrayBindTestCase<FE>> {
    let mut rng = TestVectorRng::new(seed);

    let mut test_cases = Vec::new();
    for (input_len, description) in [
        (10, "length even, not power of 2"),
        (11, "length odd"),
        (16, "length power of 2"),
    ] {
        let mut output = rng.sample_n(input_len, 0.0);
        let input = output.clone();
        let binding: FE = rng.sample(0.0);
        output.bind(super::Binding::Other(binding));
        test_cases.push(Dense1DArrayBindTestCase {
            description: description.to_string(),
            input,
            binding,
            output,
        });
    }

    BindTestVector { seed, test_cases }
}

fn generate_1d_dense_array_bind_test_vector<FE: ProofFieldElement>() {
    let seed = random();
    println!("seed: {seed}");
    write_test_vector::<_, FE>(
        generate_1d_dense_array_bind_test_vector_with_seed::<FE>(seed),
        "dense_1d_array_bind",
    );
}

field_element_tests!(generate_1d_dense_array_bind_test_vector);

fn check_1d_dense_array_bind_test_vector_consistency<FE: ProofFieldElement>(
    checked_in_vector: BindTestVector<Dense1DArrayBindTestCase<FE>>,
) {
    let generated_vector =
        generate_1d_dense_array_bind_test_vector_with_seed(checked_in_vector.seed);

    assert_eq!(checked_in_vector, generated_vector);
}

#[wasm_bindgen_test(unsupported = test)]
fn check_1d_dense_array_bind_test_vector_consistency_p128() {
    check_1d_dense_array_bind_test_vector_consistency(load_dense_1d_array_bind_p128());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_1d_dense_array_bind_test_vector_consistency_p256() {
    check_1d_dense_array_bind_test_vector_consistency(load_dense_1d_array_bind_p256());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_1d_dense_array_bind_test_vector_consistency_2_128() {
    check_1d_dense_array_bind_test_vector_consistency(load_dense_1d_array_bind_2_128());
}

fn generate_2d_sparse_array_bind_test_vector_with_seed<FE: ProofFieldElement>(
    seed: u64,
) -> BindTestVector<Sparse2DArrayBindHandTestCase<FE>> {
    let mut rng = TestVectorRng::new(seed);

    let mut test_cases = Vec::new();

    for (input_len, description) in [
        (128, "length power of 2"),
        (135, "odd length"),
        (132, "length even, not power of 2"),
    ] {
        let mut sparse = loop {
            let dense = std::iter::repeat_with(|| rng.sample_n::<FE>(input_len, 0.9999))
                .take(input_len)
                .collect::<Vec<_>>();

            let sparse = SparseSumcheckArray::from(dense.clone());
            // keep trying until we get a non-empty array
            if sparse.contents().is_empty() {
                continue;
            }
            break sparse;
        };
        let input = sparse.clone();

        // Reduce the array down to a single element. We need ceil(log_2(dimension_len)) iterations
        // for each dimension.
        let mut bindings = Vec::new();
        let mut outputs = Vec::new();
        for iteration in 0..(input_len.next_power_of_two().ilog2() * 2) {
            let binding: FE = rng.sample(0.0);
            bindings.push(binding);

            let hand = if iteration.is_multiple_of(2) {
                Hand::Left
            } else {
                Hand::Right
            };

            sparse.bind_hand(hand, binding);
            outputs.push(sparse.clone());
        }

        // verify that we reduced all the way down to a single element as expected
        assert_eq!(sparse.contents().len(), 1, "{description}");

        test_cases.push(Sparse2DArrayBindHandTestCase {
            description: description.to_string(),
            input,
            bindings,
            outputs,
        });
    }

    BindTestVector { seed, test_cases }
}

fn generate_2d_sparse_array_bind_test_vector<FE: ProofFieldElement>() {
    let seed = random();
    println!("seed: {seed}");
    write_test_vector::<_, FE>(
        generate_2d_sparse_array_bind_test_vector_with_seed::<FE>(seed),
        "sparse_2d_array_bind",
    );
}

field_element_tests!(generate_2d_sparse_array_bind_test_vector);

fn check_2d_sparse_array_bind_test_vector_consistency<FE: ProofFieldElement>(
    checked_in_vector: BindTestVector<Sparse2DArrayBindHandTestCase<FE>>,
) {
    let generated_vector =
        generate_2d_sparse_array_bind_test_vector_with_seed(checked_in_vector.seed);

    assert_eq!(checked_in_vector, generated_vector);
}

#[wasm_bindgen_test(unsupported = test)]
fn check_2d_sparse_array_bind_test_vector_consistency_p128() {
    check_2d_sparse_array_bind_test_vector_consistency(load_sparse_2d_array_bind_hand_p128());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_2d_sparse_array_bind_test_vector_consistency_p256() {
    check_2d_sparse_array_bind_test_vector_consistency(load_sparse_2d_array_bind_hand_p256());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_2d_sparse_array_bind_test_vector_consistency_2_128() {
    check_2d_sparse_array_bind_test_vector_consistency(load_sparse_2d_array_bind_hand_2_128());
}

fn generate_3d_sparse_array_bind_test_vector_with_seed<FE: ProofFieldElement>(
    seed: u64,
) -> BindTestVector<Sparse3DArrayBindGateTestCase<FE>> {
    let mut rng = TestVectorRng::new(seed);

    let mut test_cases = Vec::new();

    for (input_len, description) in [
        (32, "length power of 2"),
        (63, "odd length"),
        (34, "length even, not power of 2"),
    ] {
        let mut sparse = loop {
            let dense: Vec<Vec<Vec<_>>> = std::iter::repeat_with(|| {
                std::iter::repeat_with(|| rng.sample_n::<FE>(input_len, 0.9999))
                    .take(input_len)
                    .collect()
            })
            .take(input_len)
            .collect();

            let sparse = SparseSumcheckArray::from(dense);
            if sparse.contents().is_empty() {
                println!("rejected empty");
                // Keep trying until we get a non-empty array.
                continue;
            }

            break sparse;
        };
        let input = sparse.clone();

        let binding_len = input_len.next_power_of_two().ilog2() as usize;
        let bindings_0 = rng.sample_n(binding_len, 0.0);
        let bindings_1 = rng.sample_n(binding_len, 0.0);
        let alpha = rng.sample(0.0);

        sparse.bindv_gate(&bindings_0, &bindings_1, alpha);

        for element in sparse.contents() {
            assert_eq!(element.gate_index, 0);
        }

        test_cases.push(Sparse3DArrayBindGateTestCase {
            description: description.to_string(),
            input,
            bindings_0,
            bindings_1,
            alpha,
            output: sparse,
        });
    }

    BindTestVector { seed, test_cases }
}

fn generate_3d_sparse_array_bind_gate_vector<FE: ProofFieldElement>() {
    let seed = random();
    println!("seed: {seed}");
    write_test_vector::<_, FE>(
        generate_3d_sparse_array_bind_test_vector_with_seed::<FE>(seed),
        "sparse_3d_array_bind",
    );
}

field_element_tests!(generate_3d_sparse_array_bind_gate_vector);

fn check_3d_sparse_array_bind_test_vector_consistency<FE: ProofFieldElement>(
    checked_in_vector: BindTestVector<Sparse3DArrayBindGateTestCase<FE>>,
) {
    let generated_vector =
        generate_3d_sparse_array_bind_test_vector_with_seed(checked_in_vector.seed);

    assert_eq!(checked_in_vector, generated_vector);
}

#[wasm_bindgen_test(unsupported = test)]
fn check_3d_sparse_array_bind_test_vector_consistency_p128() {
    check_3d_sparse_array_bind_test_vector_consistency(load_sparse_3d_array_bind_gate_p128());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_3d_sparse_array_bind_test_vector_consistency_p256() {
    check_3d_sparse_array_bind_test_vector_consistency(load_sparse_3d_array_bind_gate_p256());
}

#[wasm_bindgen_test(unsupported = test)]
fn check_3d_sparse_array_bind_test_vector_consistency_2_128() {
    check_3d_sparse_array_bind_test_vector_consistency(load_sparse_3d_array_bind_gate_2_128());
}
