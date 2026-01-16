use crate::fields::{FieldElement, field2_128::Field2_128, fieldp256::FieldP256};

/// Encoder for the "bit plucker" circuit optimization.
///
/// This allows multiple bits to be packed into one witness input, and then unpacked inside the
/// circuit through interpolation.
pub(super) struct BitPlucker<const BITS: u8, FE: FieldElement> {
    offset: FE,
}

impl BitPlucker<4, Field2_128> {
    /// Construct a bit plucker for a given number of bits.
    pub(super) fn new() -> Self {
        let offset = Field2_128::inject((1u16 << 4) - 1);
        Self { offset }
    }

    /// Encode multiple bits into one field element.
    pub(super) fn encode(&self, value: u16) -> Field2_128 {
        // Note that we need to inject using BITS + 1 bits here. We can't use a generic parameter to
        // compute `BITS + 1` in a const context, so we only instantiate this implementation for the
        // one concrete parameter choice we need.
        Field2_128::inject_bits::<{ 4 + 1 }>(2 * value) - self.offset
    }

    /// Encode multiple words into multiple field elements.
    pub(super) fn encode_u32_array(&self, words: &[u32], out: &mut [Field2_128]) {
        {
            let mask = u16::MAX >> (u16::BITS - 4);
            for (word, out_chunk) in words.iter().zip(out.chunks_exact_mut(32 / 4)) {
                let mut bits = *word;
                for out_elem in out_chunk.iter_mut() {
                    *out_elem = self.encode(bits as u16 & mask);
                    bits >>= 4;
                }
            }
        };
    }
}

impl<const BITS: u8> BitPlucker<BITS, FieldP256> {
    /// Construct a bit plucker for a given number of bits.
    pub(super) fn new() -> Self {
        let offset = FieldP256::from_u128((1u128 << BITS) - 1);
        Self { offset }
    }

    /// Encode multiple bits into one field element.
    pub(super) fn encode(&self, value: u16) -> FieldP256 {
        FieldP256::from_u128(2 * u128::from(value)) - self.offset
    }

    /// Encode multiple bytes into multiple field elements.
    ///
    /// # Panics
    ///
    /// Panics if BITS is not 1, 2, 4, or 8.
    pub(super) fn encode_byte_array(&self, bytes: &[u8], out: &mut [FieldP256]) {
        assert!(BITS <= 8);
        assert_eq!(8 % BITS, 0);
        let mask = u8::MAX >> (u8::BITS - BITS as u32);
        for (byte, out_chunk) in bytes
            .iter()
            .zip(out.chunks_exact_mut(usize::from(8 / BITS)))
        {
            let mut bits = *byte;
            for out_elem in out_chunk.iter_mut() {
                *out_elem = self.encode((bits & mask).into());
                bits >>= BITS;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        fields::{FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
        mdoc_zk::BitPlucker,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_plucker_p256() {
        let bp = BitPlucker::<2, FieldP256>::new();
        let mut out = vec![FieldP256::ZERO; 12];
        // Encode three bytes, or 24 bits, into twelve field elements.
        bp.encode_byte_array(&[0x01, 0x80, 0xff], &mut out);

        // Since this is operating on a large-characteristic field, encoding two bits operates as
        // follows:
        //
        // 00 => -3
        // 01 => -1
        // 10 => 1
        // 11 => 3

        let neg_3 = -FieldP256::from_u128(3);
        let neg_1 = -FieldP256::ONE;
        let one = FieldP256::ONE;
        let three = FieldP256::from_u128(3);

        assert_eq!(
            out,
            [
                neg_1, neg_3, neg_3, neg_3, neg_3, neg_3, neg_3, one, three, three, three, three
            ]
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_plucker_2_128() {
        let bp = BitPlucker::<4, Field2_128>::new();
        let mut out = vec![Field2_128::ZERO; 24];
        bp.encode_u32_array(&[0x00000001, 0x80000000, 0xffffffff], &mut out);

        let offset = Field2_128::inject(15);
        assert_eq!(
            out,
            [
                Field2_128::inject(2) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(0) - offset,
                Field2_128::inject(16) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
                Field2_128::inject(30) - offset,
            ]
        );
    }
}
