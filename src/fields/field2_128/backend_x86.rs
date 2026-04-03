#[cfg(target_arch = "x86")]
use std::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si32, _mm_set_epi64x, _mm_slli_si128,
    _mm_srli_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_set_epi64x, _mm_slli_si128,
    _mm_srli_si128, _mm_xor_si128,
};

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This is loosely based on the code samples in Intel's white paper "Intel® Carry-Less
/// Multiplication Instruction and its Usage for Computing the GCM Mode", but without the bit
/// reversal required for GCM.
#[target_feature(enable = "sse2")]
#[target_feature(enable = "pclmulqdq")]
pub(super) fn galois_multiply(x: u128, y: u128) -> u128 {
    let x = pack_u128(x);
    let y = pack_u128(y);

    // Perform carryless multiplication using schoolbook multiplication and the PCLMULQDQ
    // instruction.
    let product1 = _mm_clmulepi64_si128::<0x00>(x, y);
    let product2 = _mm_clmulepi64_si128::<0x01>(x, y);
    let product3 = _mm_clmulepi64_si128::<0x10>(x, y);
    let product4 = _mm_clmulepi64_si128::<0x11>(x, y);
    let middle = _mm_xor_si128(product2, product3);

    let intermediate_middle = reduce(middle, product4);
    let reduced = reduce(product1, intermediate_middle);

    unpack_u128(reduced)
}

/// Squares a GF(2^128) element, represented as a `u128`.
#[target_feature(enable = "sse2")]
#[target_feature(enable = "pclmulqdq")]
pub(super) fn galois_square(x: u128) -> u128 {
    let x = pack_u128(x);

    // Perform carryless multiplication using schoolbook multiplication and the PCLMULQDQ
    // instruction.
    //
    // In the terms of the variables used by `galois_multiply()`, we know when squaring that
    // `product2` and `product3` will be equal. Therefore, `middle` will be zero, since the field
    // has characteristic two and `product2` and `product3` cancel out.
    let product1 = _mm_clmulepi64_si128::<0x00>(x, x);
    let product4 = _mm_clmulepi64_si128::<0x11>(x, x);

    let intermediate_middle = reduce(pack_u128(0), product4);
    let reduced = reduce(product1, intermediate_middle);

    unpack_u128(reduced)
}

/// Reduce an intermediate 192-bit result into a 128-bit result, modulo the field's quotient
/// polynomial.
///
/// The input to this function is split across two 128-bit registers, representing overlapping
/// powers of the generator x. The input is interpreted as if it were `result_low ^ (result_middle
/// << 64)`.
#[target_feature(enable = "sse2")]
#[target_feature(enable = "pclmulqdq")]
fn reduce(result_low: __m128i, result_middle: __m128i) -> __m128i {
    // The bits of `result_low` can be directly XOR'd into the reduced result. The bottom half of
    // `result_middle` can be shifted up, and then XOR'd in. The top half of `result_middle` has
    // powers of x greater than or equal to 128, and thus requires additional work. We can cancel
    // out these positions by multiplying the upper half by x^128 + x^7 + x^2 + x + 1 and subtracting
    // (or, equivalently, adding). If we shift the upper half of `result_middle` down and multiply
    // by the above quotient polynomial, then the terms produced by multiplication with x^128 will
    // exactly cancel out that upper half of `result_middle`. All that remains is to multiply the
    // upper half of `result_middle` by x^7 + x^2 + x + 1, (represented as 0x87) and XOR that into
    // the final result. Algebraically:
    //
    //   result_low + result_middle * x^64 = reduced mod Q(x)
    //
    //   result_low + result_middle_low * x^64 + result_middle_high * x^128 = reduced mod Q(x)
    //
    //   result_low + result_middle_low * x^64 + result_middle_high * x^128
    //       - result_middle_high * Q(x) = reduced mod Q(x)
    //
    //   result_low + result_middle_low * x^64 + result_middle_high * x^128
    //       - result_middle_high * (x^128 + x^7 + x^2 + x + 1) = reduced mod Q(x)
    //
    //   result_low + result_middle_low * x^64 - result_middle_high * (x^7 + x^2 + x + 1)
    //       = reduced mod Q(x)
    //
    //   result_low + result_middle_low * x^64 + result_middle_high * (x^7 + x^2 + x + 1)
    //       = reduced mod Q(x)
    let product = _mm_clmulepi64_si128::<0x01>(result_middle, pack_u128(0x87));
    let middle_low_half_shifted = _mm_slli_si128::<8>(result_middle);
    _mm_xor_si128(_mm_xor_si128(result_low, middle_low_half_shifted), product)
}

#[target_feature(enable = "sse2")]
fn pack_u128(value: u128) -> __m128i {
    _mm_set_epi64x((value >> 64) as u64 as i64, value as u64 as i64)
}

#[target_feature(enable = "sse2")]
#[cfg(target_arch = "x86_64")]
fn unpack_u128(value: __m128i) -> u128 {
    let low = _mm_cvtsi128_si64(value) as u64 as u128;
    let shifted = _mm_srli_si128::<8>(value);
    let high = _mm_cvtsi128_si64(shifted) as u64 as u128;
    low | (high << 64)
}

#[target_feature(enable = "sse2")]
#[cfg(target_arch = "x86")]
fn unpack_u128(value: __m128i) -> u128 {
    let lane0 = _mm_cvtsi128_si32(value) as u32 as u128;
    let lane1 = _mm_cvtsi128_si32(_mm_srli_si128::<4>(value)) as u32 as u128;
    let lane2 = _mm_cvtsi128_si32(_mm_srli_si128::<8>(value)) as u32 as u128;
    let lane3 = _mm_cvtsi128_si32(_mm_srli_si128::<12>(value)) as u32 as u128;
    lane0 | (lane1 << 32) | (lane2 << 64) | (lane3 << 96)
}

#[cfg(test)]
mod tests {
    use crate::fields::field2_128::backend_x86::{pack_u128, unpack_u128};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn roundtrip_pack_unpack() {
        for x in [
            0x00000000000000000000000000000001,
            0x00000000000000008000000000000000,
            0x00000000000000010000000000000000,
            0x80000000000000000000000000000000,
        ] {
            assert_eq!(unsafe { unpack_u128(pack_u128(x)) }, x);
        }
    }
}
