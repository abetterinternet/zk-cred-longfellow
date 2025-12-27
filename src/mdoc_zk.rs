#![allow(unused)]

use crate::{
    circuit::Circuit, fields::fieldp256_scalar::FieldP256Scalar, ligero::LigeroParameters,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use wasm_bindgen::prelude::wasm_bindgen;

/// An ECDSA signature, using the P-256 curve.
pub struct EcdsaP256Signature {
    r: FieldP256Scalar,
    s: FieldP256Scalar,
}

impl EcdsaP256Signature {
    /// Constructs a signature from two encoded scalars, r and s.
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Result<Self, anyhow::Error> {
        let r = FieldP256Scalar::try_from(&r).context("invalid scalar r")?;
        let s = FieldP256Scalar::try_from(&s).context("invalid scalar s")?;
        Ok(Self { r, s })
    }
}

/// Versions of the mdoc_zk circuit interface.
#[wasm_bindgen]
#[repr(usize)]
pub enum CircuitVersion {
    V6 = 6,
}

/// Zero-knowledge prover for mdoc credential presentations.
pub struct MdocZkProver {
    circuit_version: CircuitVersion,
    num_attributes: usize,
    signature_circuit: Circuit,
    hash_circuit: Circuit,
    signature_ligero_parameters: LigeroParameters,
    hash_ligero_parameters: LigeroParameters,
}

impl MdocZkProver {
    /// Construct a prover using the given circuit file and metadata.
    pub fn new(
        circuit: &[u8],
        circuit_version: CircuitVersion,
        num_attributes: usize,
        signature_ligero_parameters: LigeroParameters,
        hash_ligero_parameters: LigeroParameters,
    ) -> Result<Self, anyhow::Error> {
        todo!()
    }

    /// Create a proof of possession of a credential and a device binding signature.
    pub fn prove(
        &self,
        device_response: &[u8],
        namespace: &str,
        requested_claims: &[&str],
        session_transcript: &[u8],
        device_authentication_signature: EcdsaP256Signature,
        time: DateTime<Utc>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // * Parse attested claims, MSO, issuer public key, and issuer signature from DeviceResponse.
        // * Construct witness variables from namespace, requested claims, rounds of claim hashes, MSO,
        //   rounds of hash for issuer signature, issuer signature, SessionTranscript, rounds of hash
        //   for device key signature, device key signature, and the time in RFC 3339 format.
        // * Run two-circuit prover on witness and return proof.
        todo!()
    }
}
