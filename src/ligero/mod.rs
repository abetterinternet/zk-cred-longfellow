//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

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
