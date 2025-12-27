#![allow(unused)]

use crate::{
    ligero::LigeroParameters,
    mdoc_zk::{self, CircuitVersion, EcdsaP256Signature, MdocZkProver},
};
use chrono::DateTime;
use wasm_bindgen::prelude::wasm_bindgen;

/// Creates a proof of possession of a credential and a device binding signature.
///
/// # Arguments
///
/// * `circuit_version`: The version of the mdoc_zk circuit interface to use.
/// * `circuit`: The compressed circuit file. This must match the circuit version and number of
///   disclosed claims.
/// * `device_response`: The mDoc's DeviceResponse, as CBOR data.
/// * `namespace`: The namespace of the claims.
/// * `requested_claims`: The names of the claims to be disclosed.
/// * `session_transcript`: The `SessionTranscript`, as CBOR data.
/// * `device_authentication_signature_r`: The first component of the device bound key's signature
///   of the `DeviceAuthenticationData`.
/// * `device_authentication_signature_s`: The second component of the device bound key's signature
///   of the `DeviceAuthenticationData`.
/// * `time`: The current time, agreed upon by the prover and verifier.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments, clippy::boxed_local)]
pub fn prove(
    circuit_version: CircuitVersion,
    circuit: &[u8],
    device_response: &[u8],
    namespace: &str,
    requested_claims: Box<[String]>,
    session_transcript: &[u8],
    device_authentication_signature_r: &[u8],
    device_authentication_signature_s: &[u8],
    time: &str,
) -> Result<Box<[u8]>, String> {
    let r = device_authentication_signature_r
        .try_into()
        .map_err(|_| "r must be 32 bytes long".to_owned())?;
    let s = device_authentication_signature_s
        .try_into()
        .map_err(|_| "s must be 32 bytes long".to_owned())?;
    let device_authentication_signature =
        EcdsaP256Signature::new(r, s).map_err(|e| e.to_string())?;

    let requested_claims = requested_claims
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let time = DateTime::parse_from_rfc3339(time)
        .map_err(|e| format!("invalid RFC 3339 time: {e}"))?
        .to_utc();

    let prover = MdocZkProver::new(
        circuit,
        circuit_version,
        requested_claims.len(),
        LigeroParameters {
            nreq: todo!(),
            witnesses_per_row: todo!(),
            quadratic_constraints_per_row: todo!(),
            block_size: todo!(),
            num_columns: todo!(),
        },
        LigeroParameters {
            nreq: todo!(),
            witnesses_per_row: todo!(),
            quadratic_constraints_per_row: todo!(),
            block_size: todo!(),
            num_columns: todo!(),
        },
    )
    .map_err(|e| e.to_string())?;

    prover
        .prove(
            device_response,
            namespace,
            &requested_claims,
            session_transcript,
            device_authentication_signature,
            time,
        )
        .map(|proof| proof.into())
        .map_err(|e| e.to_string())
}
