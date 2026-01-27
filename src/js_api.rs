use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

/// Initialize the prover by loading a decompressed circuit file.
///
/// @param {Uint8Array} circuit - The decompressed circuit file.
/// @param {CircuitVersion} circuit_version - The version of the mdoc_zk circuit interface.
/// @param {number} num_attributes - The number of attributes to be disclosed in the presentation.
/// @returns {MdocZkProver}
#[wasm_bindgen(skip_jsdoc)]
pub fn initialize(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: usize,
) -> Result<MdocZkProver, JsError> {
    MdocZkProver::new(circuit, circuit_version, num_attributes).map_err(convert_error)
}

/// Create a proof for a credential presentation.
///
/// @param {MdocZkProver} prover - The prover returned from `initialize()`.
/// @param {Uint8Array} device_response - The mdoc's DeviceResponse, as CBOR data.
/// @param {string} namespace -  The namespace of the claims.
/// @param {string[]} requested_claims - The identifiers of the claims to be disclosed.
/// @param {Uint8Array} session_transcript - The `SessionTranscript`, as CBOR data.
/// @param {string} time - The current time. This must be in RFC 3339 format, in UTC, with no time zone offset.
/// @returns {Uint8Array} The serialized proof.
#[wasm_bindgen(skip_jsdoc)]
// We have to use `Box<[String]>` because wasm-bindgen does not support `&[String]` arguments.
#[allow(clippy::boxed_local)]
pub fn prove(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: Box<[String]>,
    session_transcript: &[u8],
    time: &str,
) -> Result<Vec<u8>, JsError> {
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
        .map_err(convert_error)
}

fn convert_error(error: anyhow::Error) -> JsError {
    let message = format!("{error:#}");
    JsError::new(&message)
}
