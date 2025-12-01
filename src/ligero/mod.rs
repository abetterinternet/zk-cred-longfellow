//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

use crate::{fields::CodecFieldElement, ligero::tableau::TableauLayout, transcript::Transcript};
use anyhow::Context;
use merkle::Node;
use serde::Deserialize;

pub mod merkle;
pub mod prover;
pub mod tableau;
pub mod verifier;

/// Common parameters for the Ligero proof system. Described in [Section 4.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.2
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
pub struct LigeroCommitment([u8; 32]);

impl TryFrom<&[u8]> for LigeroCommitment {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let commitment: [u8; 32] = value
            .try_into()
            .context("byte slice wrong size for commitment")?;
        Ok(LigeroCommitment(commitment))
    }
}

impl From<Node> for LigeroCommitment {
    fn from(value: Node) -> Self {
        Self(<[u8; 32]>::from(value))
    }
}

impl LigeroCommitment {
    /// The commitment as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// A fake but well-formed commitment for tests.
    #[cfg(test)]
    pub fn test_commitment() -> Self {
        Self::try_from([1u8; 32].as_slice()).unwrap()
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
