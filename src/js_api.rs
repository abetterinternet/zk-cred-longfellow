use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use wasm_bindgen::prelude::wasm_bindgen;

/// Initialize the prover by loading a compressed circuit file.
#[wasm_bindgen]
pub fn initialize(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: usize,
) -> Result<MdocZkProver, String> {
    MdocZkProver::new(circuit, circuit_version, num_attributes).map_err(|e| format!("{e:#}"))
}

/// Create a proof for a credential presentation.
///
/// # Arguments
///
/// * `prover`: The prover returned from `initialize()`.
/// * `device_response`: The mdoc's DeviceResponse, as CBOR data.
/// * `namespace`:  The namespace of the claims.
/// * `requested_claims`: The identifiers of the claims to be disclosed.
/// * `session_transcript`: The `SessionTranscript`, as CBOR data.
/// * `time`: The current time. This must be in RFC 3339 format, in UTC, with no time zone offset.
#[wasm_bindgen]
// We have to use `Box<[String]>` because wasm-bindgen does not support `&[String]` arguments.
#[allow(clippy::boxed_local)]
pub fn prove(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: Box<[String]>,
    session_transcript: &[u8],
    time: &str,
) -> Result<Vec<u8>, String> {
    let requested_claims = requested_claims
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prover
        .prove(
            device_response,
            namespace,
            &requested_claims,
            session_transcript,
            time,
        )
        .map_err(|e| format!("{e:#}"))
}
