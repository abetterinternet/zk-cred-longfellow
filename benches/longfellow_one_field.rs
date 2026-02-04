use criterion::{Criterion, criterion_group};
use std::{hint::black_box, io::Cursor};
use zk_cred_longfellow::{
    Codec,
    circuit::Circuit,
    fields::{FieldElement, field2_128::Field2_128, fieldp128::FieldP128},
    ligero::LigeroParameters,
    zk_one_circuit::{prover::Prover, verifier::Verifier},
};

fn rfc_1(c: &mut Criterion) {
    let compressed = include_bytes!(
        "../test-vectors/one-circuit/longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b.circuit.zst"
    );
    let bytes = zstd::decode_all(compressed.as_slice()).unwrap();
    let circuit = Circuit::decode(&mut Cursor::new(&bytes)).unwrap();
    let ligero_parameters = LigeroParameters {
        nreq: 6,
        witnesses_per_row: 15,
        quadratic_constraints_per_row: 2,
        block_size: 21,
        num_columns: 128,
    };

    let session_id = b"test";
    let inputs = &[FieldP128::from(45), FieldP128::from(5), FieldP128::from(6)];

    let prover = Prover::new(&circuit, ligero_parameters);

    let mut g = c.benchmark_group("rfc_1");

    g.sample_size(50);
    g.bench_function("prove", |b| {
        b.iter(|| {
            prover
                .prove(black_box(session_id), black_box(inputs))
                .unwrap();
        });
    });

    let proof = prover.prove(session_id, inputs).unwrap();
    let public_inputs = &inputs[..1];

    let verifier = Verifier::new(&circuit, ligero_parameters);

    g.sample_size(50);
    g.bench_function("verify", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(public_inputs), black_box(&proof))
                .unwrap();
        });
    });

    g.finish();
}

fn mac(c: &mut Criterion) {
    let compressed = include_bytes!(
        "../test-vectors/one-circuit/longfellow-mac-circuit-66aeaf09a9cc98e36873e868307ac07279d5f7e0-1.circuit.zst"
    );
    let bytes = zstd::decode_all(compressed.as_slice()).unwrap();
    let circuit = Circuit::decode(&mut Cursor::new(&bytes)).unwrap();
    let ligero_parameters = LigeroParameters {
        nreq: 128,
        witnesses_per_row: 213,
        quadratic_constraints_per_row: 213,
        block_size: 341,
        num_columns: 2048,
    };

    let session_id = b"test";
    let num_inputs = circuit.num_public_inputs() + circuit.num_private_inputs();
    let inputs = vec![Field2_128::ZERO; num_inputs - 1];
    // The inputs are the implicit one, the message, the MACs, the verifier key share, and the proof
    // key shares. The `Circuit::evaluate()` method will prepend the implicit one. We can set all of
    // the other inputs to zero for benchmark purposes, since the MAC will verify successfully.

    let prover = Prover::new(&circuit, ligero_parameters);

    let mut g = c.benchmark_group("mac");

    g.bench_function("prove", |b| {
        b.iter(|| {
            prover
                .prove(black_box(session_id), black_box(inputs.as_slice()))
                .unwrap();
        });
    });

    let proof = prover.prove(session_id, inputs.as_slice()).unwrap();
    let public_inputs = &inputs[..circuit.num_public_inputs() - 1];

    let verifier = Verifier::new(&circuit, ligero_parameters);

    g.bench_function("verify", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(public_inputs), black_box(&proof))
                .unwrap();
        });
    });

    g.finish();
}

criterion_group!(benches, rfc_1, mac);

fn main() {
    let git_version = git_version::git_version!(fallback = "unknown");
    println!("Git revision: {git_version}");
    println!();

    benches();
    Criterion::default().configure_from_args().final_summary();
}
