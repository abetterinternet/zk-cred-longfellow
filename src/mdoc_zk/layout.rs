#![allow(unused)]

use crate::{
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    mdoc_zk::CircuitVersion,
};
use anyhow::anyhow;

/// Determines the layout of the signature circuit and hash circuit inputs for the mdoc_zk
/// system.
pub(super) struct InputLayout {
    version: CircuitVersion,
    attributes: u8,
}

impl InputLayout {
    /// Constructs a layout object for the given circuit interface version and number of
    /// attributes to present.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of attributes is not between one and four.
    pub(super) fn new(version: CircuitVersion, attributes: u8) -> Result<Self, anyhow::Error> {
        if attributes == 0 || attributes > 4 {
            return Err(anyhow!("unsupported number of attributes: {attributes}"));
        }
        Ok(Self {
            version,
            attributes,
        })
    }

    /// Returns the length of the input for the signature circuit, in P-256 field elements.
    ///
    /// This includes all public and private inputs, including the implicit 1.
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
            + EcdsaWitness::LENGTH // signature verification witness, credential
            + EcdsaWitness::LENGTH // signature verification witness, device binding
            + 3 * (256 * 2 / 2) // MAC prover key shares and messages
    }

    /// Segments the signature circuit's inputs by purpose.
    ///
    /// # Panics
    ///
    /// Panics if the input slice is not of the length given by [`Self::signature_input_length()`].
    pub(super) fn split_signature_input<'a>(
        &self,
        input: &'a mut [FieldP256],
    ) -> SplitSignatureInput<'a> {
        assert_eq!(input.len(), self.signature_input_length());
        // After this assertion, all subsequent `unwrap()` and `split_at_mut()` calls should not panic.

        let (implicit_one, input) = input.split_first_mut().unwrap();
        let (issuer_public_key_x, input) = input.split_first_mut().unwrap();
        let (issuer_public_key_y, input) = input.split_first_mut().unwrap();
        let (e_session_transcript, input) = input.split_first_mut().unwrap();
        let (mac_tags, input) = input.split_at_mut(3 * 2 * 128);
        let (mac_verifier_key_share, input) = input.split_at_mut(128);
        let (e_credential, input) = input.split_first_mut().unwrap();
        let (device_public_key_x, input) = input.split_first_mut().unwrap();
        let (device_public_key_y, input) = input.split_first_mut().unwrap();
        let (credential_ecdsa_witness, input) = input.split_at_mut(EcdsaWitness::LENGTH);
        let (device_ecdsa_witness, input) = input.split_at_mut(EcdsaWitness::LENGTH);
        let (mac_witnesses, input) = input.split_at_mut(3 * 256 * 2 / 2);
        assert!(input.is_empty());

        SplitSignatureInput {
            implicit_one,
            issuer_public_key_x,
            issuer_public_key_y,
            e_session_transcript,
            mac_tags: mac_tags.try_into().unwrap(),
            mac_verifier_key_share: mac_verifier_key_share.try_into().unwrap(),
            e_credential,
            device_public_key_x,
            device_public_key_y,
            credential_ecdsa_witness: EcdsaWitness::new(
                credential_ecdsa_witness.try_into().unwrap(),
            ),
            device_ecdsa_witness: EcdsaWitness::new(device_ecdsa_witness.try_into().unwrap()),
            mac_witnesses: mac_witnesses.try_into().unwrap(),
        }
    }

    /// Returns the length of the input for the hash circuit, in GF(2^128) field elements.
    ///
    /// This includes all public and private inputs, including the implicit 1.
    pub(super) fn hash_input_length(&self) -> usize {
        match self.version {
            CircuitVersion::V6 => {}
        }
        1 // implicit 1
            + usize::from(self.attributes) * AttributeInput::LENGTH // attribute CBOR data
            + 20 * 8 // time in RFC 3339 format
            + 3 * 2 // MAC tags
            + 1 // MAC verifier key share
            + 256 // hash of credential
            + 2 * 256 // device public key
            + 8 // number of SHA-256 blocks
            + SHA_256_INPUT_WIRES // padded SHA-256 input for credential
            + SHA_256_CREDENTIAL_WITNESS_WIRES // SHA-256 witness for credential
            + 12 // validFrom CBOR offset
            + 12 // validUntil CBOR offset
            + 12 // deviceKeyInfo CBOR offset
            + 12 // valueDigests CBOR offset
            + usize::from(self.attributes) * AttributeWitness::LENGTH
            + 3 * 2 // MAC prover key shares
    }

    /// Segments the hash circuit's inputs by purpose.
    ///
    /// # Panics
    ///
    /// Panics if the input slice is not of the length given by [`Self::hash_input_length()`].
    pub(super) fn split_hash_input<'a>(&self, input: &'a mut [Field2_128]) -> SplitHashInput<'a> {
        assert_eq!(input.len(), self.hash_input_length());
        // After this assertion, all subsequent `unwrap()` and `split_at_mut()` calls should not panic.

        // Re-assert the bounds on `attributes` that were previously checked in the constructor.
        assert!(self.attributes >= 1);
        assert!(self.attributes <= 4);

        let (implicit_one, mut input) = input.split_first_mut().unwrap();

        let mut attribute_inputs = AttributeInputs::default();
        for out in attribute_inputs.inputs[0..self.attributes.into()].iter_mut() {
            let (chunk, rest) = input.split_at_mut(AttributeInput::LENGTH);
            input = rest;

            let (cbor_data, cbor_length) = chunk.split_at_mut(96 * 8);

            *out = Some(AttributeInput {
                cbor_data: cbor_data.try_into().unwrap(),
                cbor_length: cbor_length.try_into().unwrap(),
            });
        }

        let (time, input) = input.split_at_mut(20 * 8);
        let (mac_tags, input) = input.split_at_mut(3 * 2);
        let (mac_verifier_key_share, input) = input.split_first_mut().unwrap();
        let (e_credential, input) = input.split_at_mut(256);
        let (device_public_key_x, input) = input.split_at_mut(256);
        let (device_public_key_y, input) = input.split_at_mut(256);
        let (sha_256_block_count, input) = input.split_at_mut(8);
        let (sha_256_input, input) = input.split_at_mut(SHA_256_INPUT_WIRES);
        let (sha_256_witness_credential, input) =
            input.split_at_mut(SHA_256_CREDENTIAL_WITNESS_WIRES);
        let (valid_from_offset, input) = input.split_at_mut(CBOR_OFFSET_BITS);
        let (valid_until_offset, input) = input.split_at_mut(CBOR_OFFSET_BITS);
        let (device_key_info_offset, input) = input.split_at_mut(CBOR_OFFSET_BITS);
        let (value_digests_offset, mut input) = input.split_at_mut(CBOR_OFFSET_BITS);

        let mut attribute_witnesses = AttributeWitnesses::default();
        for out in attribute_witnesses.inputs[0..self.attributes.into()].iter_mut() {
            let (chunk, rest) = input.split_at_mut(AttributeWitness::LENGTH);
            input = rest;

            let (sha_256_input, chunk) = chunk.split_at_mut(2 * 64 * 8);
            let (sha_256_witness, chunk) = chunk.split_at_mut(2 * Sha256BlockWitness::LENGTH);
            let (digest_offset, chunk) = chunk.split_at_mut(CBOR_OFFSET_BITS);
            let (cbor_data_offset, chunk) = chunk.split_at_mut(CBOR_OFFSET_BITS);
            let (cbor_data_length, chunk) = chunk.split_at_mut(CBOR_OFFSET_BITS);
            let (unused_offset, chunk) = chunk.split_at_mut(CBOR_OFFSET_BITS);
            let (unused_length, chunk) = chunk.split_at_mut(CBOR_OFFSET_BITS);
            assert!(chunk.is_empty());

            *out = Some(AttributeWitness {
                sha_256_input: sha_256_input.try_into().unwrap(),
                sha_256_witness: Sha256Witness {
                    input: sha_256_witness.try_into().unwrap(),
                },
                digest_offset: digest_offset.try_into().unwrap(),
                cbor_data_offset: cbor_data_offset.try_into().unwrap(),
                cbor_data_length: cbor_data_length.try_into().unwrap(),
                unused_offset: unused_offset.try_into().unwrap(),
                unused_length: unused_length.try_into().unwrap(),
            });
        }

        let (mac_prover_key_shares, input) = input.split_at_mut(3 * 2);
        assert!(input.is_empty());

        SplitHashInput {
            implicit_one,
            attribute_inputs,
            time: time.try_into().unwrap(),
            mac_tags: mac_tags.try_into().unwrap(),
            mac_verifier_key_share,
            e_credential: e_credential.try_into().unwrap(),
            device_public_key_x: device_public_key_x.try_into().unwrap(),
            device_public_key_y: device_public_key_y.try_into().unwrap(),
            sha_256_block_count: sha_256_block_count.try_into().unwrap(),
            sha_256_input: sha_256_input.try_into().unwrap(),
            sha_256_witness_credential: Sha256Witness {
                input: sha_256_witness_credential.try_into().unwrap(),
            },
            valid_from_offset: valid_from_offset.try_into().unwrap(),
            valid_until_offset: valid_until_offset.try_into().unwrap(),
            device_key_info_offset: device_key_info_offset.try_into().unwrap(),
            value_digests_offset: value_digests_offset.try_into().unwrap(),
            attribute_witnesses,
            mac_prover_key_shares: mac_prover_key_shares.try_into().unwrap(),
        }
    }
}

/// Pointers to different parts of the signature circuit's inputs.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct SplitSignatureInput<'a> {
    pub(super) implicit_one: &'a mut FieldP256,
    pub(super) issuer_public_key_x: &'a mut FieldP256,
    pub(super) issuer_public_key_y: &'a mut FieldP256,
    pub(super) e_session_transcript: &'a mut FieldP256,
    pub(super) mac_tags: &'a mut [FieldP256; 3 * 2 * 128],
    pub(super) mac_verifier_key_share: &'a mut [FieldP256; 128],
    pub(super) e_credential: &'a mut FieldP256,
    pub(super) device_public_key_x: &'a mut FieldP256,
    pub(super) device_public_key_y: &'a mut FieldP256,
    pub(super) credential_ecdsa_witness: EcdsaWitness<'a>,
    pub(super) device_ecdsa_witness: EcdsaWitness<'a>,
    pub(super) mac_witnesses: &'a mut [FieldP256; 3 * 256 * 2 / 2],
}

/// Witnesses for ECDSA verification.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct EcdsaWitness<'a> {
    pub(super) r_x: &'a mut FieldP256,
    pub(super) r_y: &'a mut FieldP256,
    pub(super) r_x_inverse: &'a mut FieldP256,
    pub(super) neg_s_inverse: &'a mut FieldP256,
    pub(super) q_x_inverse: &'a mut FieldP256,
    pub(super) sum_g_q: &'a mut [FieldP256; 2],
    pub(super) sum_g_r: &'a mut [FieldP256; 2],
    pub(super) sum_q_r: &'a mut [FieldP256; 2],
    pub(super) sum_g_q_r: &'a mut [FieldP256; 2],
    msm_witnesses: &'a mut [FieldP256; 256 + 255 * 3],
}

impl<'a> EcdsaWitness<'a> {
    /// Number of signature circuit input wires needed for ECDSA signature verification witnesses.
    const LENGTH: usize = {
        5 // r_x, r_y, r_x inverse, s inverse, Q_x inverse
            + 8 // precomputed curve point sums for MSM lookup table
            + 256 + 255 * 3 // MSM intermediate values
    };

    fn new(witnesses: &'a mut [FieldP256; EcdsaWitness::LENGTH]) -> Self {
        // Unwrap safety: these calls will not panic because the input array length is statically
        // known, and we don't index past the end of it.

        let (r_x, witnesses) = witnesses.split_first_mut().unwrap();
        let (r_y, witnesses) = witnesses.split_first_mut().unwrap();
        let (r_x_inverse, witnesses) = witnesses.split_first_mut().unwrap();
        let (neg_s_inverse, witnesses) = witnesses.split_first_mut().unwrap();
        let (q_x_inverse, witnesses) = witnesses.split_first_mut().unwrap();

        let (sum_g_q, witnesses) = witnesses.split_at_mut(2);
        let (sum_g_r, witnesses) = witnesses.split_at_mut(2);
        let (sum_q_r, witnesses) = witnesses.split_at_mut(2);
        let (sum_g_q_r, witnesses) = witnesses.split_at_mut(2);

        Self {
            r_x,
            r_y,
            r_x_inverse,
            neg_s_inverse,
            q_x_inverse,
            sum_g_q: sum_g_q.try_into().unwrap(),
            sum_g_r: sum_g_r.try_into().unwrap(),
            sum_q_r: sum_q_r.try_into().unwrap(),
            sum_g_q_r: sum_g_q_r.try_into().unwrap(),
            msm_witnesses: witnesses.try_into().unwrap(),
        }
    }

    /// Returns an iterator over witness values for each step of the multiscalar multiplication.
    ///
    /// Yields a tuple of the table index, and optionally the three projective coordinates of the
    /// accumulator point. The latter is not present on the last iteration.
    pub(super) fn iter_msm(
        &'a mut self,
    ) -> impl Iterator<Item = (&'a mut FieldP256, Option<&'a mut [FieldP256; 3]>)> {
        self.msm_witnesses.chunks_mut(4).map(|chunk| {
            // Unwrap safety: chunks yielded by `chunks_mut()` are always nonempty.
            let (table_index, coordinates) = chunk.split_first_mut().unwrap();
            if coordinates.is_empty() {
                (table_index, None)
            } else {
                // Unwrap safety: the array length has remainder 1 mod 4, so this branch is only
                // taken when `chunk` has length 4, and `coordinates` has length 3.
                (
                    table_index,
                    Some(<&'a mut [FieldP256; 3]>::try_from(coordinates).unwrap()),
                )
            }
        })
    }
}

/// Pointers to different parts of the hash circuit's inputs.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct SplitHashInput<'a> {
    pub(super) implicit_one: &'a mut Field2_128,
    pub(super) attribute_inputs: AttributeInputs<'a>,
    pub(super) time: &'a mut [Field2_128; 20 * 8],
    pub(super) mac_tags: &'a mut [Field2_128; 6],
    pub(super) mac_verifier_key_share: &'a mut Field2_128,
    pub(super) e_credential: &'a mut [Field2_128; 256],
    pub(super) device_public_key_x: &'a mut [Field2_128; 256],
    pub(super) device_public_key_y: &'a mut [Field2_128; 256],
    pub(super) sha_256_block_count: &'a mut [Field2_128; 8],
    pub(super) sha_256_input: &'a mut [Field2_128; SHA_256_INPUT_WIRES],
    pub(super) sha_256_witness_credential: Sha256Witness<'a, SHA_256_CREDENTIAL_WITNESS_WIRES>,
    pub(super) valid_from_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) valid_until_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) device_key_info_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) value_digests_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) attribute_witnesses: AttributeWitnesses<'a>,
    pub(super) mac_prover_key_shares: &'a mut [Field2_128; 3 * 2],
}

#[derive(Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct AttributeInputs<'a> {
    pub(super) inputs: [Option<AttributeInput<'a>>; 4],
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct AttributeInput<'a> {
    pub(super) cbor_data: &'a mut [Field2_128; 96 * 8],
    pub(super) cbor_length: &'a mut [Field2_128; 8],
}

impl<'a> AttributeInput<'a> {
    const LENGTH: usize = {
        96 * 8 // attribute identifier and value CBOR data
            + 8 // length of CBOR data
    };
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct Sha256Witness<'a, const WIRES: usize> {
    input: &'a mut [Field2_128; WIRES],
}

impl<'a, const WIRES: usize> Sha256Witness<'a, WIRES> {
    pub(super) fn iter_blocks(&'a mut self) -> impl Iterator<Item = Sha256BlockWitness<'a>> {
        self.input
            .chunks_exact_mut(Sha256BlockWitness::LENGTH)
            .map(|input| {
                let (message_schedule, input) = input.split_at_mut(48 * 32 / 4);
                let (state_e_a, input) = input.split_at_mut(64 * 2 * 32 / 4);
                let (intermediate_hash_value, input) = input.split_at_mut(8 * 32 / 4);
                assert!(input.is_empty());

                Sha256BlockWitness {
                    message_schedule: message_schedule.try_into().unwrap(),
                    state_e_a: state_e_a.try_into().unwrap(),
                    intermediate_hash_value: intermediate_hash_value.try_into().unwrap(),
                }
            })
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct Sha256BlockWitness<'a> {
    pub(super) message_schedule: &'a mut [Field2_128; 48 * 32 / 4],
    pub(super) state_e_a: &'a mut [Field2_128; 64 * 2 * 32 / 4],
    pub(super) intermediate_hash_value: &'a mut [Field2_128; 8 * 32 / 4],
}

impl<'a> Sha256BlockWitness<'a> {
    /// Number of hash circuit input wires needed for SHA-256 verification witnesses per block.
    pub(super) const LENGTH: usize = {
        48 * 32 / 4 // remainder of message schedule
        + 64 * 2 * 32 / 4 // state values e and a
        + 8 * 32 / 4 // intermediate hash value
    };
}

#[derive(Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct AttributeWitnesses<'a> {
    pub(super) inputs: [Option<AttributeWitness<'a>>; 4],
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) struct AttributeWitness<'a> {
    pub(super) sha_256_input: &'a mut [Field2_128; 2 * 64 * 8],
    pub(super) sha_256_witness: Sha256Witness<'a, { 2 * Sha256BlockWitness::LENGTH }>,
    pub(super) digest_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) cbor_data_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) cbor_data_length: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) unused_offset: &'a mut [Field2_128; CBOR_OFFSET_BITS],
    pub(super) unused_length: &'a mut [Field2_128; CBOR_OFFSET_BITS],
}

impl<'a> AttributeWitness<'a> {
    const LENGTH: usize = {
        2 * 64 * 8 // padded SHA-256 input for attribute
            + 2 * Sha256BlockWitness::LENGTH // SHA-256 witness for attribute
            + 12 // digest CBOR offset
            + 12 + 12 // offset and length in SHA-256 preimage
            + 12 + 12 // unused offset and length
    };
}

/// Maximum allowed number of SHA-256 blocks during verification of the issuer's signature over the
/// credential.
pub(super) const SHA_256_CREDENTIAL_MAX_BLOCKS: usize = 35;
/// Number of wires for all block witnesses related to the credential SHA-256 calculation.
pub(super) const SHA_256_CREDENTIAL_WITNESS_WIRES: usize =
    SHA_256_CREDENTIAL_MAX_BLOCKS * Sha256BlockWitness::LENGTH;
/// Length of the constant prefix excluded from the SHA-256 padded input witness.
///
/// This includes the first few fields of the encoded `Sig_structure` CBOR structure.
pub(super) const SHA_256_CREDENTIAL_KNOWN_PREFIX_BYTES: usize = 18;
/// Number of wires needed for the credential SHA-256 input.
///
/// Note that 18 bytes are subtracted from the actual length of the padded SHA-256 input, because
/// they are a constant prefix, and do not need to be provided.
const SHA_256_INPUT_WIRES: usize =
    (SHA_256_CREDENTIAL_MAX_BLOCKS * 64 - SHA_256_CREDENTIAL_KNOWN_PREFIX_BYTES) * 8;
/// Number of bits and wires for each CBOR offset.
const CBOR_OFFSET_BITS: usize = 12;

#[cfg(test)]
mod tests {
    use crate::mdoc_zk::{CircuitVersion, layout::InputLayout, tests::load_circuits};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn correct_lengths() {
        for attributes in 1..=4 {
            let (sig_circuit, hash_circuit) = load_circuits(attributes);
            let layout = InputLayout::new(CircuitVersion::V6, attributes).unwrap();
            assert_eq!(layout.signature_input_length(), sig_circuit.num_inputs());
            assert_eq!(layout.hash_input_length(), hash_circuit.num_inputs());
        }
    }
}
