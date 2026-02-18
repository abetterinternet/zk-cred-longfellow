#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zk_cred_longfellow::{
    ParameterizedCodec,
    mdoc_zk::{CircuitVersion, MdocZkProof, verifier::MdocZkVerifier},
};

static VERIFIER: OnceLock<MdocZkVerifier> = OnceLock::new();

fuzz_target!(
    init: {
        VERIFIER
            .set(initialize_verifier())
            .map_err(|_| ())
            .expect("already initialized");
    },
    |data: &[u8]| fuzz(data)
);

fn fuzz(data: &[u8]) {
    let verifier = VERIFIER.get().unwrap();
    let _ = MdocZkProof::get_decoded_with_param(&verifier.proof_context(), data);
}

fn initialize_verifier() -> MdocZkVerifier {
    let compressed = include_bytes!(
        "../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
    );
    let decompressed = zstd::decode_all(compressed.as_slice()).unwrap();
    MdocZkVerifier::new(&decompressed, CircuitVersion::V6, 1).unwrap()
}
