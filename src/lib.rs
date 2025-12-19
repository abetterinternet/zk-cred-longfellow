use anyhow::{Context, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{fmt::Display, io::Cursor};

pub mod circuit;
pub mod constraints;
pub mod fields;
pub mod ligero;
pub mod sumcheck;
#[cfg(test)]
pub mod test_vector;
pub mod transcript;
mod witness;
pub mod zk_one_circuit;

/// A serialized size, which is in the range [1, 2^24 -1] per [draft-google-cfrg-libzk-00 section
/// 7][1]. Serialized in little endian order, occupying 3 bytes.
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Default, Hash)]
pub struct Size(u32);

impl From<u32> for Size {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Size> for usize {
    fn from(value: Size) -> Self {
        // XXX shouldn't assume that usize is big enough for u32
        value.0 as Self
    }
}

impl Codec for Size {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        Ok(Self(
            bytes
                .read_u24::<LittleEndian>()
                .context("failed to read u24")?,
        ))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        if self.0 >= (1 << 24) {
            return Err(anyhow!(
                "size {} too big to be serialized in 3 bytes",
                self.0
            ));
        }
        bytes
            .write_u24::<LittleEndian>(self.0)
            .context("failed to write u24")
    }
}

impl PartialEq<usize> for Size {
    fn eq(&self, other: &usize) -> bool {
        usize::from(*self) == *other
    }
}

impl PartialOrd<usize> for Size {
    fn partial_cmp(&self, other: &usize) -> Option<std::cmp::Ordering> {
        usize::from(*self).partial_cmp(other)
    }
}

impl Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Size {
    /// Encode this value as a delta from the previous value in some sequence. The least significant
    /// bit is used as the sign bit, with the actual value shifted up by one position ([1]).
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7.6-5
    pub fn encode_delta(&self, previous: Size, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        let delta = if self.0 >= previous.0 {
            // Delta is positive: shift the delta up by one, leaving sign bit clear
            (self.0 - previous.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
        } else {
            // Delta is negative: shift the delta up by one and set the sign bit
            (previous.0 - self.0)
                .checked_mul(2)
                .ok_or_else(|| anyhow!("shift would overflow"))?
                | 1
        };

        Size::from(delta).encode(bytes)
    }

    /// Decode this value as a delta from the previous value in some sequence.
    pub fn decode_delta(previous: Size, bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let encoded_delta = Size::decode(bytes)?.0;
        let sign = encoded_delta & 1;
        let delta = encoded_delta >> 1;

        let decoded = if sign == 1 {
            // Delta is negative
            previous.0 - delta
        } else {
            // Delta is positive
            previous.0 + delta
        };

        Ok(Self(decoded))
    }
}

/// Describes how to encode and decode an object from a byte sequence, per the rules in
/// [draft-google-cfrg-libzk-00 section 7][1].
///
/// Adapted from [prio::codec](https://docs.rs/prio/0.17.0/prio/codec/index.html).
///
/// [1]: https://www.ietf.org/archive/id/draft-google-cfrg-libzk-00.html#section-7
pub trait Codec: Sized + PartialEq + Eq + std::fmt::Debug {
    /// Decode an opaque byte buffer into an instance of this type.
    ///
    /// XXX: we could take something more sophisticated than a byte slice here, like a Cursor, or a
    /// Read impl, or an Iterator<Item = u8>.
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error>;

    /// Decode a variable length array of items.
    fn decode_array(bytes: &mut Cursor<&[u8]>) -> Result<Vec<Self>, anyhow::Error> {
        // Variable length array encoding: length as a Size, then the elements one after the other.
        // Empirically, based on the test vector, it's length in *elements*, not bytes.
        let elements = Size::decode(bytes)?;
        Self::decode_fixed_array(bytes, elements.into())
    }

    /// Decode a fixed length array of items.
    fn decode_fixed_array(
        bytes: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let item = Self::decode(bytes)?;
            items.push(item);
        }

        Ok(items)
    }

    /// Get the encoded form of this object, allocating a vector to hold it.
    fn get_encoded(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut encoded = Vec::new();
        self.encode(&mut encoded)?;
        Ok(encoded)
    }

    /// Append the encoded form of this object to the end of `bytes`, growing the vector as needed.
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error>;

    /// Encode a variable length array of items.
    fn encode_array(items: &[Self], bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // Variable length array encoding: length in elements as a Size, then the elements one after
        // the other.
        Size(
            items
                .len()
                .try_into()
                .context("vector length too big for u32")?,
        )
        .encode(bytes)?;
        Self::encode_fixed_array(items, bytes)
    }

    /// Encode a fixed length array of items.
    fn encode_fixed_array(items: &[Self], bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        for item in items {
            item.encode(bytes)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn roundtrip(&self) {
        let encoded = self.get_encoded().unwrap();
        println!("encoded: {encoded:0x?}");

        let decoded = Self::decode(&mut Cursor::new(&encoded)).unwrap();

        assert_eq!(*self, decoded)
    }
}

impl Codec for u8 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        bytes.read_u8().context("failed to read u8")
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes.push(*self);

        Ok(())
    }
}

impl Codec for u32 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        bytes
            .read_u32::<LittleEndian>()
            .context("failed to read u32")
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes
            .write_u32::<LittleEndian>(*self)
            .context("failed to write u32")
    }
}

impl Codec for [u8; 32] {
    fn decode(bytes: &mut std::io::Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let bytes: [u8; 32] = u8::decode_fixed_array(bytes, 32)?
            .try_into()
            .map_err(|_| anyhow!("failed to convert byte vec to array"))?;

        Ok(bytes)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        u8::encode_fixed_array(self.as_slice(), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Given a test function that is generic over [`FieldElement`], this macro stamps out a module
    /// containing test cases for multiple specific implementations.
    ///
    /// To ignore specific test instantiations, use the following syntax:
    ///
    /// ```text
    /// field_element_tests!(function, ignore(Field2_128));
    ///
    /// field_element_tests!(function, ignore(Field2_128 = "reason"));
    /// ```
    #[macro_export]
    macro_rules! field_element_tests {
        ($function:ident $($rest:tt)*) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 {}
                @fieldp128_msg {}
                @fieldp256 {}
                @fieldp256_msg {}
                @field2_128 {}
                @field2_128_msg {}
                $($rest)*
            );
        };

        // TT muncher pattern: collect DSL arguments, transform them, and regroup them by field.
        (
            @internal
            $function:ident
            @fieldp128 {}
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP128)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { ignore }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg {}
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP128 = $message_p128:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { ignore = $message_p128 }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 {}
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP256)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { ignore }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg {}
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(FieldP256 = $message_p256:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { ignore = $message_p256 }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 {}
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            , ignore(Field2_128)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { ignore }
                @field2_128_msg { $(ignore = $message_2_128)? }
                $($rest)*
            );
        };

        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg {}
            , ignore(Field2_128 = $message_2_128:tt)
            $($rest:tt)*
        ) => {
            field_element_tests!(
                @internal
                $function
                @fieldp128 { $($ignore_p128)? }
                @fieldp128_msg { $(ignore = $message_p128)? }
                @fieldp256 { $($ignore_p256)? }
                @fieldp256_msg { $(ignore = $message_p256)? }
                @field2_128 { $($ignore_2_128)? }
                @field2_128_msg { ignore = $message_2_128 }
                $($rest)*
            );
        };

        // Base case: no DSL arguments left.
        (
            @internal
            $function:ident
            @fieldp128 { $($ignore_p128:ident)? }
            @fieldp128_msg { $(ignore = $message_p128:tt)? }
            @fieldp256 { $($ignore_p256:ident)? }
            @fieldp256_msg { $(ignore = $message_p256:tt)? }
            @field2_128 { $($ignore_2_128:ident)? }
            @field2_128_msg { $(ignore = $message_2_128:tt)? }
            $(,)?
        ) => {
            mod $function {
                use super::*;

                $(#[$ignore_p128])?
                $(#[ignore = $message_p128])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field_p128() {
                    $function::<$crate::fields::fieldp128::FieldP128>();
                }

                $(#[$ignore_p256])?
                $(#[ignore = $message_p256])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field_p256() {
                    $function::<$crate::fields::fieldp256::FieldP256>();
                }

                $(#[$ignore_2_128])?
                $(#[ignore = $message_2_128])?
                #[wasm_bindgen_test(unsupported = test)]
                fn field2_128() {
                    $function::<$crate::fields::field2_128::Field2_128>();
                }
            }
        };
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_u8() {
        12u8.roundtrip();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_u32() {
        0xffffab65u32.roundtrip();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn codec_roundtrip_size() {
        Size::from(12345).roundtrip();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_size_too_big() {
        // 1 << 24 is too big to be encoded as a 3 byte size, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 24).encode(&mut bytes).unwrap_err();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_delta_positive_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(1 << 31)
            .encode_delta(Size::from(0), &mut bytes)
            .unwrap_err();
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn encode_delta_negative_overflow() {
        // (1 << 31 - 0) << 1 will overflow u32, so this should fail
        let mut bytes = Vec::new();
        Size::from(0)
            .encode_delta(Size::from(1 << 31), &mut bytes)
            .unwrap_err();
    }
}
