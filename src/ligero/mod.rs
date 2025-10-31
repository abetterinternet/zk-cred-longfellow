//! Ligero proof system, per [Section 4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4

use serde::Deserialize;

pub mod committer;
pub mod merkle;
pub mod prover;
pub mod verifier;

/// Common parameters for the Ligero proof system. Described in [Section 4.2][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.2
#[derive(Debug, Clone, Deserialize)]
pub struct LigeroParameters {
    /// The number of columns of the commitment matrix that the Verifier requests to be revealed by the Prover.
    pub nreq: usize,
    /// The number of witness values included in each row. Also "WR".
    pub witnesses_per_row: usize,
    /// The number of quadratic constraints written in each row. Also "QR".
    pub quadratic_constraints_per_row: usize,
    /// The size of each row, in terms of number of field elements. Also "BLOCK".
    pub row_size: usize,
}
