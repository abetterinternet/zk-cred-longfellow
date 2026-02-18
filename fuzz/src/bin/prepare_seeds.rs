use std::{fs, path::Path};

fn main() {
    let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Use a valid proof as a seed for the proof decoding fuzzer.
    fs::create_dir_all(base_dir.join("corpus/mdoc_zk_proof")).unwrap();
    fs::copy(
        base_dir.join("../test-vectors/mdoc_zk/proof.bin"),
        base_dir.join("corpus/mdoc_zk_proof/seed_proof"),
    )
    .unwrap();

    // Decompress circuit files used for test vectors, and use them as seeds for the circuit decoding fuzzer.
    fs::create_dir_all(base_dir.join("corpus/circuit")).unwrap();
    let rfc_compressed = fs::read(base_dir.join("../test-vectors/one-circuit/longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b.circuit.zst")).unwrap();
    let rfc_decompressed = zstd::decode_all(rfc_compressed.as_slice()).unwrap();
    fs::write(base_dir.join("corpus/circuit/seed_rfc"), &rfc_decompressed).unwrap();
    let mac_compressed = fs::read(base_dir.join("../test-vectors/one-circuit/longfellow-mac-circuit-66aeaf09a9cc98e36873e868307ac07279d5f7e0-1.circuit.zst")).unwrap();
    let mac_decompressed = zstd::decode_all(mac_compressed.as_slice()).unwrap();
    fs::write(base_dir.join("corpus/circuit/seed_mac"), &mac_decompressed).unwrap();
}
