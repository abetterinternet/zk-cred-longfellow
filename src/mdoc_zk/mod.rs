use crate::{
    Codec,
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    mdoc_zk::{
        layout::InputLayout,
        mdoc::{compute_credential_hash, compute_session_transcript_hash, parse_device_response},
    },
};
use anyhow::anyhow;

mod ec;
mod layout;
mod mdoc;
mod sha256;

/// Versions of the mdoc_zk circuit interface.
pub enum CircuitVersion {
    V6 = 6,
}

/// Identifier and value of a presented attribute.
pub struct Attribute {
    /// The attribute's identifier.
    pub id: String,
    /// The attribute's value, as CBOR-encoded data.
    pub cbor_value: Vec<u8>,
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
        _issuer_public_key: [FieldP256; 2],
        transcript: &[u8],
        attributes: &[Attribute],
        _time: &str,
        _mac_prover_key_shares: &[Field2_128; 6],
    ) -> Result<Self, anyhow::Error> {
        let layout = InputLayout::new(
            version,
            attributes
                .len()
                .try_into()
                .map_err(|_| anyhow!("unsupported number of attributes"))?,
        )?;

        let mdoc = parse_device_response(mdoc_device_response)?;

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
        *split_signature_input.e_session_transcript =
            compute_session_transcript_hash(&mdoc, transcript)?;

        // Set the hash of the credential.
        let credential_hash = compute_credential_hash(&mdoc)?;
        *split_signature_input.e_credential = credential_hash;

        // Set the device public key.
        *split_signature_input.device_public_key_x = mdoc.device_public_key_x;
        *split_signature_input.device_public_key_y = mdoc.device_public_key_y;

        // Re-encode MAC messages as pairs of GF(2^128) elements.
        let mut mac_messages_buffer = Vec::with_capacity(6 * Field2_128::num_bytes());
        credential_hash.encode(&mut mac_messages_buffer)?;
        mdoc.device_public_key_x.encode(&mut mac_messages_buffer)?;
        mdoc.device_public_key_y.encode(&mut mac_messages_buffer)?;
        let mut mac_messages = [Field2_128::ZERO; 6];
        for (mac_message, chunk) in mac_messages
            .iter_mut()
            .zip(mac_messages_buffer.chunks_exact(Field2_128::num_bytes()))
        {
            // Unwrap safety: This conversion is infallible, since the chunk is of the correct
            // length, and all 128-bit strings represent a valid GF(2^128) element.
            *mac_message = Field2_128::try_from(chunk).unwrap();
        }

        // Smoke test: iterate through multiscalar multiplication witnesses.
        for _ in split_signature_input.credential_ecdsa_witness.iter_msm() {}
        for _ in split_signature_input.device_ecdsa_witness.iter_msm() {}

        // Smoke test: iterate through SHA-256 block witnesses.
        for _ in split_hash_input.sha_256_witness_credential.iter_blocks() {}
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

#[cfg(test)]
pub(super) mod tests {
    use crate::{
        Codec,
        circuit::Circuit,
        fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
        mdoc_zk::{Attribute, CircuitInputs, CircuitVersion},
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
    struct WitnessTestVector {
        /// The mdoc DeviceResponse, containing the credential, device signature, opened attributes,
        /// etc.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        mdoc: Vec<u8>,
        /// Issuer public key x-coordinate, as a hex literal.
        pkx: String,
        /// Issuer public key y-coordinate, as a hex literal.
        pky: String,
        /// Handoff session binding data.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        transcript: Vec<u8>,
        /// Attributes to be presented.
        attributes: Vec<TestVectorAttribute>,
        /// Current time, in RFC 3339 format.
        now: String,
        /// Inputs to the signature circuit.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        signature_input: Vec<u8>,
        /// Inputs to the hash circuit.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        hash_input: Vec<u8>,
        /// Verifier's share of MAC key.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        mac_verifier_key_share: Vec<u8>,
        /// Prover's shares of MAC keys.
        #[serde(deserialize_with = "hex::serde::deserialize")]
        mac_prover_key_shares: Vec<u8>,
    }

    /// Presented attribute, as represented in a test vector.
    #[derive(Deserialize)]
    struct TestVectorAttribute {
        id: String,
        #[serde(deserialize_with = "hex::serde::deserialize")]
        cbor_value: Vec<u8>,
    }

    fn load_witness_test_vector() -> WitnessTestVector {
        serde_json::from_slice(include_bytes!(
            "../../test-vectors/mdoc_zk/witness_test_vector.json"
        ))
        .unwrap()
    }

    #[ignore = "failing, witness preparation is incomplete"]
    #[wasm_bindgen_test(unsupported = test)]
    fn witness_preparation() {
        let test_vector = load_witness_test_vector();

        let mut issuer_pkx = hex::decode(&test_vector.pkx[2..]).unwrap();
        let mut issuer_pky = hex::decode(&test_vector.pky[2..]).unwrap();
        // Switch from big endian to little endian before decoding field elements.
        issuer_pkx.reverse();
        issuer_pky.reverse();
        let issuer_pkx = FieldP256::try_from(issuer_pkx.as_slice()).unwrap();
        let issuer_pky = FieldP256::try_from(issuer_pky.as_slice()).unwrap();

        let attributes = test_vector
            .attributes
            .iter()
            .map(|attr| Attribute {
                id: attr.id.clone(),
                cbor_value: attr.cbor_value.clone(),
            })
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
            [issuer_pkx, issuer_pky],
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
        pretty_assertions::assert_eq!(
            layout.split_hash_input(&mut inputs.hash_input().to_vec()),
            layout.split_hash_input(&mut expected_hash_input.clone())
        );

        assert_eq!(inputs.signature_input(), expected_signature_input);
        assert_eq!(inputs.hash_input(), expected_hash_input);
    }
}
