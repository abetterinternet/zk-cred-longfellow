#[cfg(test)]
use crate::mdoc_zk::layout::Sha256BlockWitness;
use std::iter;

const INITIAL_HASH_VALUE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pads the input to SHA-256 in-place.
fn pad_input(input: &mut Vec<u8>) {
    let length_bytes = input.len();
    let length_bits = u64::try_from(length_bytes).unwrap() * 8;
    input.push(0x80);
    let zero_bytes = 63 - (length_bytes + 8) % 64;
    input.extend(iter::repeat_n(0, zero_bytes));
    input.extend_from_slice(&length_bits.to_be_bytes());
}

/// Compute the SHA-256 hash of an input.
pub(super) fn run_sha256(input: &[u8]) -> [u8; 32] {
    let mut padded_input = input.to_vec();
    pad_input(&mut padded_input);
    let mut hash_value = INITIAL_HASH_VALUE;
    for chunk in padded_input.chunks_exact(64) {
        process_block(chunk.try_into().unwrap(), &mut hash_value);
    }
    serialize_hash_value(&hash_value)
}

/// Process a block of input.
fn process_block(message_block: &[u8; 64], hash_value: &mut [u32; 8]) {
    let message_schedule = message_schedule(message_block);
    let mut state = *hash_value;
    for (k_t, w_t) in K.iter().zip(&message_schedule) {
        round(&mut state, *k_t, *w_t);
    }
    let [a, b, c, d, e, f, g, h] = state;
    hash_value[0] = hash_value[0].wrapping_add(a);
    hash_value[1] = hash_value[1].wrapping_add(b);
    hash_value[2] = hash_value[2].wrapping_add(c);
    hash_value[3] = hash_value[3].wrapping_add(d);
    hash_value[4] = hash_value[4].wrapping_add(e);
    hash_value[5] = hash_value[5].wrapping_add(f);
    hash_value[6] = hash_value[6].wrapping_add(g);
    hash_value[7] = hash_value[7].wrapping_add(h);
}

#[cfg(test)]
/// Compute one block of SHA-256 and record witness values.
pub(super) fn witness_block(
    message_block: &[u8; 64],
    hash_value: &mut [u32; 8],
    _witness: &mut Sha256BlockWitness<'_>,
    _bit_plucker: &(),
) {
    let message_schedule = message_schedule(message_block);
    // TODO: record computed message schedule values in witness.
    let mut state = *hash_value;
    for (k_t, w_t) in K.iter().zip(&message_schedule) {
        round(&mut state, *k_t, *w_t);
        // TODO: record a and e in witness.
    }
    let [a, b, c, d, e, f, g, h] = state;
    hash_value[0] = hash_value[0].wrapping_add(a);
    hash_value[1] = hash_value[1].wrapping_add(b);
    hash_value[2] = hash_value[2].wrapping_add(c);
    hash_value[3] = hash_value[3].wrapping_add(d);
    hash_value[4] = hash_value[4].wrapping_add(e);
    hash_value[5] = hash_value[5].wrapping_add(f);
    hash_value[6] = hash_value[6].wrapping_add(g);
    hash_value[7] = hash_value[7].wrapping_add(h);
}

/// Expand a block of the message into the message schedule.
fn message_schedule(message: &[u8; 64]) -> [u32; 64] {
    let mut schedule = [0u32; 64];

    // Parse the message.
    for (mi, chunk) in schedule[..16].iter_mut().zip(message.chunks_exact(4)) {
        *mi = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // Compute the rest of the message schedule from its recurrence relation.
    for t in 16..64 {
        schedule[t] = lower_sigma_1(schedule[t - 2])
            .wrapping_add(schedule[t - 7])
            .wrapping_add(lower_sigma_0(schedule[t - 15]))
            .wrapping_add(schedule[t - 16]);
    }

    schedule
}

/// Execute the round function once.
fn round(state: &mut [u32; 8], k_t: u32, w_t: u32) {
    let [a, b, c, d, e, f, g, h] = state;
    let t1 = h
        .wrapping_add(upper_sigma_1(*e))
        .wrapping_add(choice(*e, *f, *g))
        .wrapping_add(k_t)
        .wrapping_add(w_t);
    let t2 = upper_sigma_0(*a).wrapping_add(majority(*a, *b, *c));
    *h = *g;
    *g = *f;
    *f = *e;
    *e = d.wrapping_add(t1);
    *d = *c;
    *c = *b;
    *b = *a;
    *a = t1.wrapping_add(t2);
}

fn serialize_hash_value(hash_value: &[u32; 8]) -> [u8; 32] {
    let mut output = [0; 32];
    for (h, chunk) in hash_value.iter().zip(output.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&h.to_be_bytes());
    }
    output
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn upper_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn upper_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn lower_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn lower_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[cfg(test)]
mod tests {
    use crate::{
        fields::{FieldElement, field2_128::Field2_128},
        mdoc_zk::{
            layout::Sha256BlockWitness,
            sha256::{process_block, run_sha256, witness_block},
        },
    };
    use sha2::{Digest, Sha256};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_digest() {
        let input = b"One two three four five six seven eight nine ten eleven twelve thirteen";
        let hash = run_sha256(input);
        let expected_hash = Sha256::digest(input);
        assert_eq!(hash.as_slice(), expected_hash.as_slice());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_padding_exhaustive() {
        let input = [0xff; 65];
        for i in 0..=input.len() {
            let input = &input[0..i];
            let hash = run_sha256(input);
            let expected_hash = Sha256::digest(input);
            assert_eq!(hash.as_slice(), expected_hash.as_slice(), "length {i}");
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_witness_block_equivalent() {
        let message_block = b"1234567890-=qwertyuiopasdfghjkl;zxcvbnm,,,./QWERTYUIOPASDFGHJKL:";
        let hash_value = [
            0x9187a6ef, 0xe4ab8e3c, 0x14ab981e, 0x3847c87a, 0x981f8431, 0x47361cd4, 0x167eaf13,
            0x97eabfc8,
        ];
        let mut hash_value_1 = hash_value;
        process_block(message_block, &mut hash_value_1);

        let mut message_schedule = [Field2_128::ZERO; 384];
        let mut state_e_a = [Field2_128::ZERO; 1024];
        let mut intermediate_hash_value = [Field2_128::ZERO; 64];
        let mut witness = Sha256BlockWitness {
            message_schedule: &mut message_schedule,
            state_e_a: &mut state_e_a,
            intermediate_hash_value: &mut intermediate_hash_value,
        };
        let mut hash_value_2 = hash_value;
        witness_block(message_block, &mut hash_value_2, &mut witness, &());

        assert_eq!(hash_value_1, hash_value_2);
    }
}
