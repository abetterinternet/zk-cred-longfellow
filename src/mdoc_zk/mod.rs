use crate::{
    Codec,
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    mdoc_zk::{
        bit_plucker::BitPlucker,
        ec::{AffinePoint, fill_ecdsa_witness},
        layout::{
            AttributeInput, EcdsaWitness, InputLayout, SHA_256_CREDENTIAL_KNOWN_PREFIX_BYTES,
        },
        mdoc::{
            ParsedAttribute, compute_credential_hash, compute_session_transcript_hash,
            find_attributes, hash_to_field_element, parse_device_response,
        },
    },
};
use anyhow::{Context, anyhow};

mod bit_plucker;
mod ec;
mod layout;
mod mdoc;
mod sha256;

/// Versions of the mdoc_zk circuit interface.
pub enum CircuitVersion {
    V6 = 6,
}

/// Inputs for the mdoc_zk circuits.
pub struct CircuitInputs {
    layout: InputLayout,
    signature_input: Vec<FieldP256>,
    hash_input: Vec<Field2_128>,
    #[allow(unused)]
    mac_messages: [Field2_128; 6],
}

impl CircuitInputs {
    /// Construct inputs for the signature and hash circuits.
    pub fn new(
        version: CircuitVersion,
        mdoc_device_response: &[u8],
        transcript: &[u8],
        attribute_ids: &[String],
        time: &str,
        mac_prover_key_shares: &[Field2_128; 6],
    ) -> Result<Self, anyhow::Error> {
        let layout = InputLayout::new(
            version,
            attribute_ids
                .len()
                .try_into()
                .map_err(|_| anyhow!("unsupported number of attributes"))?,
        )?;

        let mdoc = parse_device_response(mdoc_device_response)?;
        let attributes = find_attributes(&mdoc.attribute_preimages, attribute_ids)?;

        let mut signature_input = vec![FieldP256::ZERO; layout.signature_input_length()];
        let mut split_signature_input = layout.split_signature_input(&mut signature_input);

        let mut hash_input = vec![Field2_128::ZERO; layout.hash_input_length()];
        let mut split_hash_input = layout.split_hash_input(&mut hash_input);

        // Set the first wire in both inputs to one.
        *split_signature_input.implicit_one = FieldP256::ONE;
        *split_hash_input.implicit_one = Field2_128::ONE;

        // Set the issuer public key.
        *split_signature_input.issuer_public_key_x = mdoc.issuer_public_key_x;
        *split_signature_input.issuer_public_key_y = mdoc.issuer_public_key_y;

        // Set the session transcript hash.
        let session_transcript_hash = compute_session_transcript_hash(&mdoc, transcript)?;
        *split_signature_input.e_session_transcript =
            hash_to_field_element(session_transcript_hash).context(
                "could not convert session transcript hash to a field element \
                (see https://github.com/google/longfellow-zk/issues/120)",
            )?;

        // Set the hash of the credential.
        let hash_bit_plucker = BitPlucker::<4, Field2_128>::new();
        let credential_hash_result = compute_credential_hash(
            &mdoc,
            &mut split_hash_input.sha_256_witness_credential,
            &hash_bit_plucker,
        )?;
        let credential_hash = credential_hash_result.digest;
        *split_signature_input.e_credential = hash_to_field_element(credential_hash).context(
            "could not convert credential hash to a field element \
            (see https://github.com/google/longfellow-zk/issues/120)",
        )?;

        // Set the device public key.
        let device_public_key_coordinates = mdoc
            .device_public_key
            .coordinates()
            .ok_or_else(|| anyhow!("device public key is the point at infinity"))?;
        *split_signature_input.device_public_key_x = device_public_key_coordinates[0];
        *split_signature_input.device_public_key_y = device_public_key_coordinates[1];

        // Re-encode MAC messages as pairs of GF(2^128) elements.
        let mut mac_messages_buffer = Vec::with_capacity(6 * Field2_128::num_bytes());
        split_signature_input
            .e_credential
            .encode(&mut mac_messages_buffer)?;
        FieldP256::encode_fixed_array(&device_public_key_coordinates, &mut mac_messages_buffer)?;
        let mut mac_messages = [Field2_128::ZERO; 6];
        for (mac_message, chunk) in mac_messages
            .iter_mut()
            .zip(mac_messages_buffer.chunks_exact(Field2_128::num_bytes()))
        {
            // Unwrap safety: This conversion is infallible, since the chunk is of the correct
            // length, and all 128-bit strings represent a valid GF(2^128) element.
            *mac_message = Field2_128::try_from(chunk).unwrap();
        }

        // Set ECDSA witnesses.
        fill_ecdsa_witness(
            &mut split_signature_input.credential_ecdsa_witness,
            AffinePoint::new(mdoc.issuer_public_key_x, mdoc.issuer_public_key_y),
            mdoc.issuer_signature,
            credential_hash,
        )?;
        fill_ecdsa_witness(
            &mut split_signature_input.device_ecdsa_witness,
            mdoc.device_public_key,
            mdoc.device_signature,
            session_transcript_hash,
        )?;

        // Serialize MAC prover key shares to bytes.
        let mut mac_prover_key_shares_buffer =
            Vec::with_capacity(mac_prover_key_shares.len() * Field2_128::num_bytes());
        Field2_128::encode_fixed_array(
            mac_prover_key_shares.as_slice(),
            &mut mac_prover_key_shares_buffer,
        )?;

        // Set signature circuit MAC witnesses, interleaving key shares and messages.
        let sig_mac_bit_plucker = BitPlucker::<2, FieldP256>::new();
        for ((key_shares_chunk, message), out) in mac_prover_key_shares_buffer
            .chunks_exact(32)
            .zip(mac_messages_buffer.chunks_exact(32))
            .zip(split_signature_input.mac_witnesses.chunks_exact_mut(256))
        {
            sig_mac_bit_plucker.encode_byte_array(key_shares_chunk, &mut out[..128]);
            sig_mac_bit_plucker.encode_byte_array(message, &mut out[128..]);
        }

        // Set public contents of attributes.
        for (out_slice, attribute) in split_hash_input
            .attribute_inputs
            .inputs
            .iter_mut()
            .zip(attributes.iter())
        {
            // Unwrap safety: when splitting the circuit inputs, we ensure there are as many `Some`
            // values as there are requested attributes.
            let out_slice = out_slice.as_mut().unwrap();
            fill_attribute_statment(out_slice, attribute)?;
        }

        // Set current time.
        if time.len() != 20 {
            return Err(anyhow!(
                "current time is not correctly formatted, must be 20 bytes long"
            ));
        }
        if time < &mdoc.valid_from {
            return Err(anyhow!("credential is not yet valid"));
        }
        if time > &mdoc.valid_until {
            return Err(anyhow!("credential is expired"));
        }
        byte_array_as_bits(time.as_bytes(), split_hash_input.time);

        // Encode MAC messages. Note that this encodes the credential hash field element in
        // little-endian order, which effectively byte-reverses the hash digest.
        byte_array_as_bits(&mac_messages_buffer[..32], split_hash_input.e_credential);
        byte_array_as_bits(
            &mac_messages_buffer[32..64],
            split_hash_input.device_public_key_x,
        );
        byte_array_as_bits(
            &mac_messages_buffer[64..],
            split_hash_input.device_public_key_y,
        );

        // Set the number of SHA-256 blocks for the credential.
        byte_array_as_bits(
            &[credential_hash_result
                .num_blocks
                .try_into()
                .map_err(|_| anyhow!("credential is too long"))?],
            split_hash_input.sha_256_block_count,
        );

        // Set the padded SHA-256 input for the credential, skipping the known prefix.
        byte_array_as_bits(
            &credential_hash_result.padded_input[SHA_256_CREDENTIAL_KNOWN_PREFIX_BYTES..],
            split_hash_input.sha_256_input,
        );

        // Set the CBOR offsets into the MSO.
        mdoc.mso_offsets
            .valid_from
            .try_into()
            .map_err(anyhow::Error::from)
            .and_then(|valid_from| u12_as_bits(valid_from, split_hash_input.valid_from_offset))
            .context("offset to validFrom is too large")?;
        mdoc.mso_offsets
            .valid_until
            .try_into()
            .map_err(anyhow::Error::from)
            .and_then(|valid_until| u12_as_bits(valid_until, split_hash_input.valid_until_offset))
            .context("offset to validUntil is too large")?;
        mdoc.mso_offsets
            .device_key_info
            .try_into()
            .map_err(anyhow::Error::from)
            .and_then(|device_key_info| {
                u12_as_bits(device_key_info, split_hash_input.device_key_info_offset)
            })
            .context("offset to deviceKeyInfo is too large")?;
        mdoc.mso_offsets
            .value_digests
            .try_into()
            .map_err(anyhow::Error::from)
            .and_then(|value_digests| {
                u12_as_bits(value_digests, split_hash_input.value_digests_offset)
            })
            .context("offset to valueDigests is too large")?;

        // Smoke test: iterate through SHA-256 block witnesses.
        for _ in split_hash_input.attribute_witnesses.inputs[0]
            .as_mut()
            .unwrap()
            .sha_256_witness
            .iter_blocks()
        {}

        Ok(Self {
            layout,
            signature_input,
            hash_input,
            mac_messages,
        })
    }

    /// Updates the MAC verifier key share and MAC key tags in public circuit inputs.
    ///
    /// This should be done after committing to the witnesses, including the cross-circuit shared
    /// witnesses (MAC messages) and MAC prover key shares.
    pub fn update_macs(&mut self, verifier_key_share: Field2_128, tags: [Field2_128; 6]) {
        let sig = self.layout.split_signature_input(&mut self.signature_input);
        for (tag, wires) in tags.iter().zip(sig.mac_tags.chunks_exact_mut(128)) {
            for (bit, wire) in tag.iter_bits().zip(wires.iter_mut()) {
                *wire = FieldP256::from_u128(bit as u128);
            }
        }
        for (bit, wire) in verifier_key_share
            .iter_bits()
            .zip(sig.mac_verifier_key_share.iter_mut())
        {
            *wire = FieldP256::from_u128(bit as u128);
        }

        let hash = self.layout.split_hash_input(&mut self.hash_input);
        hash.mac_tags.copy_from_slice(&tags);
        *hash.mac_verifier_key_share = verifier_key_share;
    }

    /// Returns the input for the signature circuit.
    pub fn signature_input(&self) -> &[FieldP256] {
        &self.signature_input
    }

    /// Returns the input for the hash circuit.
    pub fn hash_input(&self) -> &[Field2_128] {
        &self.hash_input
    }
}

/// Set public inputs related to one attribute.
fn fill_attribute_statment(
    attribute_input: &mut AttributeInput<'_>,
    attribute_data: &ParsedAttribute,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0u8; 96];
    let len = attribute_data.public_cbor_data.len();
    if len > 96 {
        return Err(anyhow!("public attribute data is too long: {len} > 96"));
    }
    buffer[..len].copy_from_slice(&attribute_data.public_cbor_data);
    byte_array_as_bits(&buffer, attribute_input.cbor_data);
    byte_array_as_bits(&[len as u8], attribute_input.cbor_length);
    Ok(())
}

/// Encode an array of bytes as field elements, with one field element representing each bit.
fn byte_array_as_bits(bytes: &[u8], out: &mut [Field2_128]) {
    for (byte, out_chunk) in bytes.iter().zip(out.chunks_exact_mut(8)) {
        let mut bits = *byte;
        for out_elem in out_chunk.iter_mut() {
            *out_elem = Field2_128::inject_bits::<1>((bits & 1) as u16);
            bits >>= 1;
        }
    }
}

/// Encode a 12-bit integer as field elements, with one field element representing each bit.
///
/// This is used for offsets into the CBOR byte string encoding the `MobileSecurityObject` or an
/// `IssuerSignedItem`.
///
/// # Errors
///
/// Returns an error if the input is larger than 4095.
fn u12_as_bits(mut u12: u16, out: &mut [Field2_128; 12]) -> Result<(), anyhow::Error> {
    for out_elem in out.iter_mut() {
        *out_elem = Field2_128::inject_bits::<1>(u12 & 1);
        u12 >>= 1;
    }

    if u12 > 0 {
        Err(anyhow!("CBOR offset is over 4095"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use crate::{
        Codec,
        circuit::Circuit,
        fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
        mdoc_zk::{CircuitInputs, CircuitVersion, byte_array_as_bits},
    };
    use serde::Deserialize;
    use std::io::Cursor;
    use wasm_bindgen_test::wasm_bindgen_test;

    pub(super) fn load_circuits(attributes: u8) -> (Circuit<FieldP256>, Circuit<Field2_128>) {
        let data = match attributes {
            1 => include_bytes!("../../test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6").as_slice(),
            2 => include_bytes!("../../test-vectors/mdoc_zk/6_2_b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e").as_slice(),
            3 => include_bytes!("../../test-vectors/mdoc_zk/6_3_b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010").as_slice(),
            4 => include_bytes!("../../test-vectors/mdoc_zk/6_4_c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6").as_slice(),
            _ => panic!("unsupported number of attributes"),
        };
        let decompressed = zstd::decode_all(data).unwrap();
        let mut cursor = Cursor::new(decompressed.as_slice());
        let first_circuit = Circuit::decode(&mut cursor).unwrap();
        let second_circuit = Circuit::decode(&mut cursor).unwrap();
        assert_eq!(
            cursor.position(),
            u64::try_from(decompressed.len()).unwrap(),
            "extra data"
        );
        (first_circuit, second_circuit)
    }

    /// Test vector for the witness preparation process.
    #[derive(Deserialize)]
    pub(super) struct WitnessTestVector {
        /// The mdoc DeviceResponse, containing the credential, device signature, opened attributes,
        /// etc.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) mdoc: Vec<u8>,
        /// Handoff session binding data.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) transcript: Vec<u8>,
        /// Attributes to be presented.
        pub(super) attributes: Vec<TestVectorAttribute>,
        /// Current time, in RFC 3339 format.
        pub(super) now: String,
        /// Inputs to the signature circuit.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) signature_input: Vec<u8>,
        /// Inputs to the hash circuit.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) hash_input: Vec<u8>,
        /// Verifier's share of MAC key.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) mac_verifier_key_share: Vec<u8>,
        /// Prover's shares of MAC keys.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        pub(super) mac_prover_key_shares: Vec<u8>,
    }

    /// Presented attribute, as represented in a test vector.
    #[derive(Deserialize)]
    pub(super) struct TestVectorAttribute {
        pub(super) id: String,
    }

    pub(super) fn load_witness_test_vector() -> WitnessTestVector {
        serde_json::from_slice(include_bytes!(
            "../../test-vectors/mdoc_zk/witness_test_vector.json"
        ))
        .unwrap()
    }

    #[ignore = "failing, witness preparation is incomplete"]
    #[wasm_bindgen_test(unsupported = test)]
    fn witness_preparation() {
        let test_vector = load_witness_test_vector();

        let attributes = test_vector
            .attributes
            .iter()
            .map(|attr| attr.id.clone())
            .collect::<Vec<_>>();

        let mac_verifier_key_share =
            Field2_128::try_from(test_vector.mac_verifier_key_share.as_slice()).unwrap();
        let mac_prover_key_shares = test_vector
            .mac_prover_key_shares
            .chunks_exact(Field2_128::num_bytes())
            .map(|bytes| Field2_128::try_from(bytes).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut inputs = CircuitInputs::new(
            CircuitVersion::V6,
            &test_vector.mdoc,
            &test_vector.transcript,
            &attributes,
            &test_vector.now,
            &mac_prover_key_shares,
        )
        .unwrap();

        let mut mac_tags = [Field2_128::ZERO; 6];
        for ((mac_message, mac_prover_key_share), mac_tag) in inputs
            .mac_messages
            .iter()
            .zip(&mac_prover_key_shares)
            .zip(mac_tags.iter_mut())
        {
            let mac_key = mac_verifier_key_share + mac_prover_key_share;
            *mac_tag = mac_key * mac_message;
        }
        inputs.update_macs(mac_verifier_key_share, mac_tags);

        let expected_signature_input = test_vector
            .signature_input
            .chunks_exact(FieldP256::num_bytes())
            .map(|bytes| FieldP256::try_from(bytes).unwrap())
            .collect::<Vec<_>>();
        let expected_hash_input = test_vector
            .hash_input
            .chunks_exact(Field2_128::num_bytes())
            .map(|bytes| Field2_128::try_from(bytes).unwrap())
            .collect::<Vec<_>>();

        let layout = &inputs.layout;
        pretty_assertions::assert_eq!(
            layout.split_signature_input(&mut inputs.signature_input().to_vec()),
            layout.split_signature_input(&mut expected_signature_input.clone())
        );

        // We need to split comparison of the hash inputs up by top-level field, otherwise it will
        // hit an allocation error when trying to write the diff.
        let mut hash_actual = inputs.hash_input().to_vec();
        let mut hash_actual_split = layout.split_hash_input(&mut hash_actual);
        let mut hash_expected = expected_hash_input.clone();
        let mut hash_expected_split = layout.split_hash_input(&mut hash_expected);
        pretty_assertions::assert_eq!(
            hash_actual_split.implicit_one,
            hash_expected_split.implicit_one,
            "implicit one"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.attribute_inputs,
            hash_expected_split.attribute_inputs,
            "attribute inputs"
        );
        pretty_assertions::assert_eq!(hash_actual_split.time, hash_expected_split.time, "time");
        pretty_assertions::assert_eq!(
            hash_actual_split.mac_tags,
            hash_expected_split.mac_tags,
            "mac tags"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.mac_verifier_key_share,
            hash_expected_split.mac_verifier_key_share,
            "mac verifier key share"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.e_credential,
            hash_expected_split.e_credential,
            "e, credential"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.device_public_key_x,
            hash_expected_split.device_public_key_x,
            "device public key x"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.device_public_key_y,
            hash_expected_split.device_public_key_y,
            "device public key y"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.sha_256_block_count,
            hash_expected_split.sha_256_block_count,
            "sha-256 block count"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.sha_256_input,
            hash_expected_split.sha_256_input,
            "sha-256 input"
        );
        for (i, (actual_block_witness, expected_block_witness)) in hash_actual_split
            .sha_256_witness_credential
            .iter_blocks()
            .zip(hash_expected_split.sha_256_witness_credential.iter_blocks())
            .enumerate()
        {
            pretty_assertions::assert_eq!(
                actual_block_witness,
                expected_block_witness,
                "sha-256 witness, credential, block {i}"
            );
        }
        pretty_assertions::assert_eq!(
            hash_actual_split.valid_from_offset,
            hash_expected_split.valid_from_offset,
            "validFrom offset"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.valid_until_offset,
            hash_expected_split.valid_until_offset,
            "validUntil offset"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.device_key_info_offset,
            hash_expected_split.device_key_info_offset,
            "deviceKeyInfo offset"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.value_digests_offset,
            hash_expected_split.value_digests_offset,
            "valueDigests offset"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.attribute_witnesses,
            hash_expected_split.attribute_witnesses,
            "attribute witnesses"
        );
        pretty_assertions::assert_eq!(
            hash_actual_split.mac_prover_key_shares,
            hash_expected_split.mac_prover_key_shares,
            "mac prover key shares"
        );

        assert_eq!(inputs.signature_input(), expected_signature_input);
        assert_eq!(inputs.hash_input(), expected_hash_input);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_byte_array() {
        let bytes = b"A\n";
        let mut field_elements = [-Field2_128::ONE; 16];
        byte_array_as_bits(bytes, &mut field_elements);
        assert_eq!(
            field_elements,
            [
                // 0x41
                Field2_128::ONE,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ONE,
                Field2_128::ZERO,
                // 0x0a
                Field2_128::ZERO,
                Field2_128::ONE,
                Field2_128::ZERO,
                Field2_128::ONE,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ZERO,
                Field2_128::ZERO,
            ]
        );
    }
}
