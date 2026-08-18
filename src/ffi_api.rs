//! Uniffi-friendly prover API.
//!
//! These functions wrap the Rust API, replacing `usize` arguments and wrapping error types.

use crate::mdoc_zk::{
    CircuitVersion,
    prover::MdocZkProver,
    verifier::{Attribute, MdocZkVerifier},
};
use std::fmt::{self, Debug, Display};

/// UniFFI doesn't support fixed-size array types across the FFI boundary
/// (`[u8; 32]` isn't `LiftRef`-able), so PPID's `verifier_context` crosses
/// as a slice and gets validated/converted here.
fn verifier_context_from_slice(verifier_context: &[u8]) -> Result<[u8; 32], MdocZkError> {
    verifier_context
        .try_into()
        .map_err(|_| MdocZkError(anyhow::anyhow!("verifier_context must be exactly 32 bytes")))
}

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
    let requested_claims: Vec<_> = requested_claims.iter().map(String::as_str).collect();
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

/// Initialize the verifier by loading a decompressed circuit file.
#[uniffi::export]
pub fn initialize_verifier(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: u8,
) -> Result<MdocZkVerifier, MdocZkError> {
    MdocZkVerifier::new(circuit, circuit_version, usize::from(num_attributes)).map_err(MdocZkError)
}

/// Verify a proof of a credential presentation.
#[uniffi::export]
pub fn verify(
    verifier: &MdocZkVerifier,
    issuer_public_key_sec_1: &[u8],
    attributes: &[Attribute],
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
    session_transcript: &[u8],
    time: &str,
    proof: &[u8],
) -> Result<(), MdocZkError> {
    verifier
        .verify(
            issuer_public_key_sec_1,
            attributes,
            doc_type,
            device_name_spaces_bytes,
            session_transcript,
            time,
            proof,
        )
        .map_err(MdocZkError)
}

/// Create a proof for a credential presentation with pairwise-pseudonym
/// (PPID) support - V8 circuits only. `verifier_context` binds the derived
/// pseudonym to a specific verifier, so the same credential holder presents
/// a different pseudonym to each distinct verifier.
#[uniffi::export]
pub fn prove_with_ppid(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: &[String],
    session_transcript: &[u8],
    time: &str,
    verifier_context: &[u8],
) -> Result<Vec<u8>, MdocZkError> {
    let verifier_context = verifier_context_from_slice(verifier_context)?;
    let requested_claims: Vec<_> = requested_claims.iter().map(String::as_str).collect();
    prover
        .prove_with_ppid(
            device_response,
            namespace,
            &requested_claims,
            session_transcript,
            time,
            &verifier_context,
        )
        .map_err(MdocZkError)
}

/// Verify a proof with pairwise-pseudonym (PPID) support - V8 circuits only.
/// `verifier_context` must match the value the prover used to derive the
/// pseudonym.
#[uniffi::export]
pub fn verify_with_ppid(
    verifier: &MdocZkVerifier,
    issuer_public_key_sec_1: &[u8],
    attributes: &[Attribute],
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
    session_transcript: &[u8],
    time: &str,
    verifier_context: &[u8],
    proof: &[u8],
) -> Result<(), MdocZkError> {
    let verifier_context = verifier_context_from_slice(verifier_context)?;
    verifier
        .verify_with_ppid(
            issuer_public_key_sec_1,
            attributes,
            doc_type,
            device_name_spaces_bytes,
            session_transcript,
            time,
            &verifier_context,
            proof,
        )
        .map_err(MdocZkError)
}

#[derive(uniffi::Object)]
#[uniffi::export(Debug, Display)]
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
        write!(f, "{:#}", &self.0)
    }
}

impl Debug for MdocZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <anyhow::Error as Debug>::fmt(&self.0, f)
    }
}
