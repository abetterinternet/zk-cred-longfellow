#![allow(unused)]

use crate::mdoc_zk::CircuitVersion;
use anyhow::anyhow;

/// Determines the layout of the signature circuit and hash circuit inputs for the mdoc_zk
/// system.
pub(super) struct InputLayout {
    version: CircuitVersion,
    attributes: u8,
}

impl InputLayout {
    pub(super) fn new(version: CircuitVersion, attributes: u8) -> Result<Self, anyhow::Error> {
        if attributes == 0 || attributes > 4 {
            return Err(anyhow!("unsupported number of attributes: {attributes}"));
        }
        Ok(Self {
            version,
            attributes,
        })
    }

    pub(super) fn signature_input_length(&self) -> usize {
        match self.version {
            CircuitVersion::V6 => {}
        }
        1 // implicit 1
            + 2 // issuer public key
            + 1 // hash of session transcript
            + 3 * 2 * 128 // MAC tags
            + 128 // MAC verifier key share
            + 1 // hash of credential
            + 2 // device public key
            + ECDSA_WITNESS_LENGTH // signature verification witness, credential
            + ECDSA_WITNESS_LENGTH // signature verification witness, device binding
            + 3 * (256 * 2 / 2) // MAC prover key shares and messages
    }

    pub(super) fn hash_input_length(&self) -> usize {
        match self.version {
            CircuitVersion::V6 => {}
        }
        1 // implicit 1
            + usize::from(self.attributes) * (
                96 * 8 // attribute identifier and value CBOR data
                    + 8 // length of CBOR data
            )
            + 20 * 8 // time in RFC 3339 format
            + 3 * 2 // MAC tags
            + 1 // MAC verifier key share
            + 256 // hash of credential
            + 2 * 256 // device public key
            + 8 // number of SHA-256 blocks
            + (35 * 64 - 18) * 8 // padded SHA-256 input for credential
            + 35 * SHA_256_BLOCK_WITNESS_LENGTH // SHA-256 witness for credential
            + 12 // validFrom CBOR offset
            + 12 // validUntil CBOR offset
            + 12 // deviceKeyInfo CBOR offset
            + 12 // valueDigests CBOR offset
            + usize::from(self.attributes) * (
                2 * 64 * 8 // padded SHA-256 input for attribute
                    + 2 * SHA_256_BLOCK_WITNESS_LENGTH // SHA-256 witness for attribute
                    + 12 // digest CBOR offset
                    + 12 + 12 // offset and length in SHA-256 preimage
                    + 12 + 12 // unused offset and length
            )
            + 3 * 2 // MAC prover key shares
    }
}

/// Number of signature circuit input wires needed for ECDSA signature verification witnesses.
const ECDSA_WITNESS_LENGTH: usize = {
    5 // r_x, r_y, r_x inverse, s inverse, Q_x inverse
        + 8 // precomputed curve point sums for MSM lookup table
        + 256 + 255 * 3 // MSM intermediate values
};

/// Number of hash circuit input wires needed for SHA-256 verification witnesses per block.
const SHA_256_BLOCK_WITNESS_LENGTH: usize = {
    48 * 32 / 4 // remainder of message schedule
        + 64 * 2 * 32 / 4 // state values e and a
        + 8 * 32 / 4 // intermediate hash value
};

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{CircuitVersion, layout::InputLayout, tests::load_circuits};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn correct_lengths() {
        for attributes in 1..=4 {
            let (sig_circuit, hash_circuit) = load_circuits(attributes);
            let layout = InputLayout::new(CircuitVersion::V6, attributes).unwrap();
            assert_eq!(
                layout.signature_input_length(),
                usize::try_from(sig_circuit.num_inputs.0).unwrap()
            );
            assert_eq!(
                layout.hash_input_length(),
                usize::try_from(hash_circuit.num_inputs.0).unwrap(),
            );
        }
    }
}
