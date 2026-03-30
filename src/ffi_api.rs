//! Uniffi-friendly prover API.
//!
//! These functions wrap the Rust API, replacing `usize` arguments and wrapping error types.

use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use std::fmt::{self, Debug, Display};

/// Initialize the prover by loading a decompressed circuit file.
#[uniffi::export]
pub fn initialize_prover(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: u8,
) -> Result<MdocZkProver, MdocZkError> {
    MdocZkProver::new(circuit, circuit_version, usize::from(num_attributes)).map_err(MdocZkError)
}

/// Create a proof for a credential presentation.
#[uniffi::export]
pub fn prove(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: &[String],
    session_transcript: &[u8],
    time: &str,
) -> Result<Vec<u8>, MdocZkError> {
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
        .map_err(MdocZkError)
}

#[derive(uniffi::Object)]
pub struct MdocZkError(anyhow::Error);

impl std::error::Error for MdocZkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        self.0.description()
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.0.cause()
    }
}

impl Display for MdocZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <anyhow::Error as Display>::fmt(&self.0, f)
    }
}

impl Debug for MdocZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <anyhow::Error as Debug>::fmt(&self.0, f)
    }
}
