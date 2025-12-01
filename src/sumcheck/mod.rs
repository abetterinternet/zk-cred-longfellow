//! Padded sumcheck proof of circuit evaluation, per Section 6 ([1]).
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6

use crate::{circuit::Circuit, fields::CodecFieldElement, transcript::Transcript};

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

/// Initialize the transcript per ["special rules for the first message"][1], with adjustments to
/// match longfellow-zk.
///
/// This function should be called after writing the first message (the Ligero commitment). It
/// writes the hash of the circuit, the public inputs, and a representative of the circuit output
/// in order to properly bind the computation to the proof. It writes a zero byte per each quad term
/// in the circuit in order to make it infeasible for the circuit to predict challenges by
/// computing hash function outputs.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-3.1.3
pub(crate) fn initialize_transcript<FE>(
    transcript: &mut Transcript,
    circuit: &Circuit,
    public_inputs: &[FE],
) -> Result<(), anyhow::Error>
where
    FE: CodecFieldElement,
{
    // 3.1.3 item 2: write circuit ID
    transcript.write_byte_array(&circuit.id)?;
    // 3.1.3 item 2: write inputs. Per the specification, this should be an array of field
    // elements, but longfellow-zk writes each input as an individual field element. Also,
    // longfellow-zk only appends the *public* inputs, but the specification isn't clear about
    // that.
    for input in public_inputs {
        transcript.write_field_element(input)?;
    }

    // 3.1.3 item 2: write outputs. We should look at the output layer of `evaluation` here and
    // write an array of field elements. But longfellow-zk writes a single zero, regardless of
    // how many outputs the actual circuit has.
    transcript.write_field_element(&FE::ZERO)?;

    // 3.1.3 item 3: write an array of zero bytes. The spec implies that its length should be
    // the number of arithmetic gates in the circuit, but longfellow-zk uses the number of quads
    // aka the number of terms.
    transcript.write_byte_array(vec![0u8; circuit.num_quads()].as_slice())?;

    Ok(())
}
