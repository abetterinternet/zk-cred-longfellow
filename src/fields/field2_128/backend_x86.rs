#[cfg(target_arch = "x86")]
use std::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si32, _mm_or_si128, _mm_set_epi64x, _mm_slli_epi32,
    _mm_slli_si128, _mm_srli_epi32, _mm_srli_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_or_si128, _mm_set_epi64x, _mm_slli_epi32,
    _mm_slli_si128, _mm_srli_epi32, _mm_srli_si128, _mm_xor_si128,
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
    let middle_high = _mm_srli_si128::<8>(middle);
    let middle_low = _mm_slli_si128::<8>(middle);
    let result_low = _mm_xor_si128(product1, middle_low);
    let result_high = _mm_xor_si128(product4, middle_high);

    // Perform the first step of the reduction by x^128 + x^7 + x^2 + x + 1. The carryless product
    // above is 255 bits wide, and x^7 + x^2 + x + 1 is 8 bits wide. Thus, after one step of
    // reduction, we will have an intermediate result that is 134 bits wide. A second reduction step
    // will bring the result to 128 bits wide.
    //
    // We can perform this reduction by shifting the top part of the product multiple times, and
    // XORing with the bottom part of the product. Note that there is no 128-bit wide shift
    // instruction, in part because that would require a very large barrel shifter. We can emulate
    // such wide shifts for the short, constant shift amounts we need by performing left shifts
    // and right shifts of packed 32-bit integers, as well as left and right shifts across lanes,
    // and ORing the results together.
    //
    // We start with result_high * x^128 + result_low. Subtracting result_high * Q(x), we get
    // result_high * (x^7 + x^2 + x + 1) + result_low.
    let result_high_lane_shifted_left = _mm_slli_si128::<4>(result_high);
    let shifted_1 = _mm_or_si128(
        _mm_slli_epi32::<1>(result_high),
        _mm_srli_epi32::<{ 32 - 1 }>(result_high_lane_shifted_left),
    );
    let shifted_2 = _mm_or_si128(
        _mm_slli_epi32::<2>(result_high),
        _mm_srli_epi32::<{ 32 - 2 }>(result_high_lane_shifted_left),
    );
    let shifted_7 = _mm_or_si128(
        _mm_slli_epi32::<7>(result_high),
        _mm_srli_epi32::<{ 32 - 7 }>(result_high_lane_shifted_left),
    );
    let mut first_reduction = result_low;
    first_reduction = _mm_xor_si128(first_reduction, result_high);
    first_reduction = _mm_xor_si128(first_reduction, shifted_1);
    first_reduction = _mm_xor_si128(first_reduction, shifted_2);
    first_reduction = _mm_xor_si128(first_reduction, shifted_7);
    let result_high_lane_shifted_right = _mm_srli_si128::<12>(result_high);
    let mut extra = _mm_srli_epi32::<{ 32 - 1 }>(result_high_lane_shifted_right);
    extra = _mm_xor_si128(
        extra,
        _mm_srli_epi32::<{ 32 - 2 }>(result_high_lane_shifted_right),
    );
    extra = _mm_xor_si128(
        extra,
        _mm_srli_epi32::<{ 32 - 7 }>(result_high_lane_shifted_right),
    );

    // Perform the second step of the reduction. We again multiply the high integer, `extra`, by
    // (x^7 + x^2 + x + 1), and add it to the low integer. This time, `extra` is only 6 bits wide,
    // and the result will fit within 128 bits. We can also use a single packed 32-bit shift
    // instruction for the three shifts, because we only care about the bits on the low end of the
    // first lane.
    let shifted_1 = _mm_slli_epi32::<1>(extra);
    let shifted_2 = _mm_slli_epi32::<2>(extra);
    let shifted_7 = _mm_slli_epi32::<7>(extra);
    let mut second_reduction = first_reduction;
    second_reduction = _mm_xor_si128(second_reduction, extra);
    second_reduction = _mm_xor_si128(second_reduction, shifted_1);
    second_reduction = _mm_xor_si128(second_reduction, shifted_2);
    second_reduction = _mm_xor_si128(second_reduction, shifted_7);

    unpack_u128(second_reduction)
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

    #[test]
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
