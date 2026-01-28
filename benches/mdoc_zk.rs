use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::Value;
use std::{
    fs::{self, File},
    hint::black_box,
    time::Duration,
};
use zk_cred_longfellow::mdoc_zk::{
    CircuitVersion,
    prover::MdocZkProver,
    verifier::{Attribute, MdocZkVerifier},
};

fn load_circuit_file() -> Vec<u8> {
    let compressed = fs::read(
        "test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
    )
    .unwrap();
    zstd::decode_all(compressed.as_slice()).unwrap()
}

fn load_inputs() -> (Vec<u8>, Vec<u8>, String) {
    let value = serde_json::from_reader::<_, Value>(
        File::open("test-vectors/mdoc_zk/witness_test_vector.json").unwrap(),
    )
    .unwrap();
    let object = value.as_object().unwrap();
    let mdoc = object["mdoc"].as_str().unwrap();
    let mdoc = hex::decode(mdoc).unwrap();
    let transcript = object["transcript"].as_str().unwrap();
    let transcript = hex::decode(transcript).unwrap();
    let now = object["now"].as_str().unwrap().to_owned();
    (mdoc, transcript, now)
}

fn prove(c: &mut Criterion) {
    c.bench_function("prove", |b| {
        let circuit = load_circuit_file();
        let prover = MdocZkProver::new(&circuit, CircuitVersion::V6, 1).unwrap();
        let (device_response, session_transcript, time) = load_inputs();
        b.iter(|| {
            prover
                .prove(
                    black_box(&device_response),
                    "org.iso.18013.5.1",
                    &["issue_date"],
                    black_box(&session_transcript),
                    &time,
                )
                .unwrap();
        });
    });
}

fn verify(c: &mut Criterion) {
    c.bench_function("verify", |b| {
        let circuit = load_circuit_file();
        let verifier = MdocZkVerifier::new(&circuit, CircuitVersion::V6, 1).unwrap();
        let (_, session_transcript, time) = load_inputs();
        let proof = fs::read("test-vectors/mdoc_zk/proof.bin").unwrap();
        b.iter(|| {
            verifier
                .verify(
                    ISSUER_PUBLIC_KEY,
                    &[Attribute {
                        identifier: "issue_date".to_owned(),
                        value_cbor: b"\xd9\x03\xec\x6a2024-03-15".to_vec(),
                    }],
                    "org.iso.18013.5.1.mDL",
                    b"\xA0",
                    black_box(&session_transcript),
                    &time,
                    black_box(&proof),
                )
                .unwrap();
        });
    });
}

/// Issuer public key for the witness test vector and proof test vector, in SEC 1 form.
const ISSUER_PUBLIC_KEY: &[u8] =
    b"\x04\xDC\x1C\x1F\x55\xCF\xF4\xCD\x5C\x76\xCF\x41\x69\x27\x8F\x72\x17\x66\x7F\
    \x86\xEE\x81\xD8\x66\x9B\x63\xF2\xE1\x9B\xC1\x2A\x0C\x9F\x12\x35\x5D\xD0\x38\x5F\
    \xED\x3B\xC3\x3B\xED\xC9\x78\x1B\x9A\xAD\x47\xB3\x3E\x4C\x24\x70\x4B\x8D\x14\x28\
    \x8B\x1B\x3C\xB4\x5C\x28";

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(180));
    targets = prove, verify
}
criterion_main!(benches);
