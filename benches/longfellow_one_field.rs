use criterion::{Criterion, criterion_group, criterion_main};
use std::{fs, hint::black_box, io::Cursor};
use zk_cred_longfellow::{
    Codec,
    circuit::Circuit,
    fields::fieldp128::FieldP128,
    ligero::LigeroParameters,
    zk_one_circuit::{prover::Prover, verifier::Verifier},
};

fn load_circuit(name: &str) -> Circuit {
    let compressed = fs::read(format!("test-vectors/one-circuit/{name}.circuit.zst")).unwrap();
    let bytes = zstd::decode_all(compressed.as_slice()).unwrap();
    Circuit::decode(&mut Cursor::new(&bytes)).unwrap()
}

fn rfc_1(c: &mut Criterion) {
    let circuit = load_circuit("longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b");
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
                .unwrap()
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
                .unwrap()
        })
    });

    g.finish();
}

criterion_group!(benches, rfc_1);
criterion_main!(benches);
