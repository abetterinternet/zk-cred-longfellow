//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

use crate::{
    Codec, Sha256Digest, fields::CodecFieldElement, ligero::tableau::TableauLayout,
    transcript::Transcript,
};
use anyhow::{Context, anyhow};
use merkle::Node;
use serde::Deserialize;
use std::io;

pub mod merkle;
pub mod prover;
pub mod tableau;
pub mod verifier;

/// Common parameters for the Ligero proof system. Described in [Section 4.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.2
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct LigeroParameters {
    /// The number of columns of the tableau that the Verifier requests to be revealed by the
    /// Prover. Also `NREQ`.
    pub nreq: usize,
    /// The number of witness values included in each row. Also `WR`.
    pub witnesses_per_row: usize,
    /// The number of quadratic constraints written in each row. Also `QR`.
    pub quadratic_constraints_per_row: usize,
    /// The size of a block, in terms of number of field elements. Also `BLOCK`. The specification
    /// describes this quantity as the "size of each row", but that would be `NCOL` or
    /// `num_columns`.
    pub block_size: usize,
    /// The total size of a tableau row. Also `NCOL`.
    pub num_columns: usize,
}

/// A commitment to a witness vector, as specified in [1]. Concretely, this is the root of a Merkle
/// tree of SHA-256 hashes.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LigeroCommitment(Sha256Digest);

impl TryFrom<&[u8]> for LigeroCommitment {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let commitment: [u8; 32] = value
            .try_into()
            .context("byte slice wrong size for commitment")?;
        Ok(LigeroCommitment(Sha256Digest(commitment)))
    }
}

impl From<Node> for LigeroCommitment {
    fn from(value: Node) -> Self {
        Self(Sha256Digest::from(value))
    }
}

impl LigeroCommitment {
    /// The commitment as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.0
    }

    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.0
    }

    /// A fake but well-formed commitment for tests.
    #[cfg(test)]
    pub fn test_commitment() -> Self {
        Self::try_from([1u8; 32].as_slice()).unwrap()
    }
}

impl Codec for LigeroCommitment {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(Sha256Digest::decode(bytes)?))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        self.0.encode(bytes)
    }
}

/// A 32-byte nonce used in hash commitments.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 32]);

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Codec for Nonce {
    fn decode(bytes: &mut io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let bytes: [u8; 32] = u8::decode_fixed_array(bytes, 32)?
            .try_into()
            .map_err(|_| anyhow!("failed to convert byte vec to array"))?;

        Ok(Self(bytes))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        u8::encode_fixed_array(self.0.as_slice(), bytes)
    }
}

/// Write hash of A to the transcript.
fn write_hash_of_a(transcript: &mut Transcript) -> Result<(), anyhow::Error> {
    // Write 0xdeadbeef, padded to 32 bytes, to the transcript to match what longfellow-zk does.
    // zk_prover.h claims that "[f]or FS soundness, it is ok for hash_of_A to be any string".
    transcript.write_byte_array(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])
}

/// Write a Ligero proof to the transcript.
pub fn write_proof<FE: CodecFieldElement>(
    transcript: &mut Transcript,
    low_degree_test_proof: &[FE],
    dot_proof: &[FE],
    quadratic_proof_low: &[FE],
    quadratic_proof_high: &[FE],
) -> Result<(), anyhow::Error> {
    for proof in [
        low_degree_test_proof,
        dot_proof,
        quadratic_proof_low,
        quadratic_proof_high,
    ] {
        transcript.write_field_element_array(proof)?;
    }
    Ok(())
}

/// Challenges used to produce or verify a Ligero proof.
struct LigeroChallenges<FE> {
    pub low_degree_test_blind: Vec<FE>,
    pub linear_constraint_alphas: Vec<FE>,
    pub quadratic_constraint_alphas: Vec<FE>,
    pub quadratic_proof_blind: Vec<FE>,
}

impl<FE: CodecFieldElement> LigeroChallenges<FE> {
    /// Generate the challenges for the simulated prover-verifier interaction.
    fn generate(
        transcript: &mut Transcript,
        tableau_layout: &TableauLayout,
        linear_constraints_len: usize,
        quadratic_constraints_len: usize,
    ) -> Result<Self, anyhow::Error> {
        // This is "u" in the specification. Generate one element for each witness and quadratic witness
        // row in the tableau.
        let low_degree_test_blind =
            transcript.generate_challenge(tableau_layout.num_constraint_rows())?;

        let linear_constraint_alphas = transcript.generate_challenge(linear_constraints_len)?;
        let quadratic_constraint_alphas =
            transcript.generate_challenge(3 * quadratic_constraints_len)?;

        // Also uquad, u_quad in the specification.
        let quadratic_proof_blind =
            transcript.generate_challenge(tableau_layout.num_quadratic_triples())?;

        Ok(Self {
            low_degree_test_blind,
            linear_constraint_alphas,
            quadratic_constraint_alphas,
            quadratic_proof_blind,
        })
    }
}
