//! Padded sumcheck proof of circuit evaluation, per Section 6 ([1]).
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6

pub mod bind;
pub mod prover;

/// A polynomial of degree 2, represented by its evaluations at points `p0` (the field's additive
/// identity, aka 0) and `p2` (the field's multiplicative identity added to itself, aka 1 + 1) (see
/// [6.4][1]. The  evaluation at `p1` (the multiplicative identity aka 1) is "implied and not
/// needed" ([6.5][2]).
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.4
/// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.5
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polynomial<FE> {
    pub p0: FE,
    pub p2: FE,
}
