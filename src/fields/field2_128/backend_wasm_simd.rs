//! Specialized implementation of GF(2^128) arithmetic, targeting the WASM SIMD extension.
//!
//! WASM's available instructions are limited, so we need to use the bit slicing strategy to
//! implement field element multiplication. Furthermore, there is no widening 64 bit * 64 bit -> 128
//! bit multiplication operation. We can however make use of the SIMD extension to perform two 64
//! bit multiplications at the same time.
//!
//! Multiplicands are split into 32-bit words, then each word is split into eight groups of four
//! bits. Masks are used to select one bit from each group, then different masked inputs are
//! multiplied together in different combinations. The product is masked again, to select parity
//! bits that are effectively the XOR of multiple ANDed input bits, representing a partial
//! polynomial multiplication. By repeating this with different masks and combining results, we can
//! compute the full GF(2)[x] polynomial multiplication, such that each bit at position i in the
//! result is equal to the XOR of all conjunctions resulting from ANDing the j-th bit of the left
//! argument with the (i-j)-th bit of the right argument. We then reduce this polynomial
//! multiplication result by the quotient polynomial, to get the 128-bit result of GF(2^128)
//! multiplication.
//!
//! Since polynomial multiplication is significantly more expensive than polynomial addition (i.e.
//! XOR) when targeting WASM, we reduce the number of smaller integer multiplications needed by
//! employing Karatsuba multiplication to decompose the problem.

use core::arch::wasm32::{
    u64x2, u64x2_extract_lane, u64x2_mul, u64x2_shl, u64x2_shr, u64x2_shuffle, u64x2_splat,
    v128_and, v128_or, v128_xor,
};

pub(super) fn galois_multiply(x: u128, y: u128) -> u128 {
    let product = clmul128(x, y);

    reduce(product)
}

pub(super) fn galois_square(x: u128) -> u128 {
    let product = U256 {
        low: galois_square_u64_widening(x as u64),
        high: galois_square_u64_widening((x >> 64) as u64),
    };

    reduce(product)
}

fn galois_square_u64_widening(x: u64) -> u128 {
    let mut x = u64x2(x, 0);
    let x_shl_32 = v128_or(
        u64x2_shl(x, 32),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 32),
    );
    x = v128_or(x, x_shl_32);
    x = v128_and(x, u64x2_splat(0x0000_0000_FFFF_FFFF));
    let x_shl_16 = v128_or(
        u64x2_shl(x, 16),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 48),
    );
    x = v128_or(x, x_shl_16);
    x = v128_and(x, u64x2_splat(0x0000_FFFF_0000_FFFF));
    let x_shl_8 = v128_or(
        u64x2_shl(x, 8),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 56),
    );
    x = v128_or(x, x_shl_8);
    x = v128_and(x, u64x2_splat(0x00FF_00FF_00FF_00FF));
    let x_shl_4 = v128_or(
        u64x2_shl(x, 4),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 60),
    );
    x = v128_or(x, x_shl_4);
    x = v128_and(x, u64x2_splat(0x0F0F_0F0F_0F0F_0F0F));
    let x_shl_2 = v128_or(
        u64x2_shl(x, 2),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 62),
    );
    x = v128_or(x, x_shl_2);
    x = v128_and(x, u64x2_splat(0x3333_3333_3333_3333));
    let x_shl_1 = v128_or(
        u64x2_shl(x, 1),
        u64x2_shr(u64x2_shuffle::<2, 0>(x, u64x2_splat(0)), 63),
    );
    x = v128_or(x, x_shl_1);
    x = v128_and(x, u64x2_splat(0x5555_5555_5555_5555));

    let low = u64x2_extract_lane::<0>(x);
    let high = u64x2_extract_lane::<1>(x);
    (low as u128) | ((high as u128) << 64)
}

struct U256 {
    low: u128,
    high: u128,
}

/// Carryless multiplication of two 128-bit arguments.
fn clmul128(x: u128, y: u128) -> U256 {
    // This multiplication is decomposed into three smaller operations via Karatsuba multiplication.
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let y_lo = y as u64;
    let y_hi = (y >> 64) as u64;

    let r1 = clmul64(x_lo, y_lo);
    let r4 = clmul64(x_hi, y_hi);
    let p_prime = x_lo ^ x_hi;
    let q_prime = y_lo ^ y_hi;
    let s = clmul64(p_prime, q_prime);
    let t = s ^ r1 ^ r4;

    U256 {
        low: r1 ^ (t << 64),
        high: (t >> 64) ^ r4,
    }
}

/// Carryless multiplication of two 64-bit arguments.
fn clmul64(x: u64, y: u64) -> u128 {
    // This multiplication is decomposed into three smaller operations via Karatsuba multiplication.
    let x_lo = x as u32;
    let x_hi = (x >> 32) as u32;
    let y_lo = y as u32;
    let y_hi = (y >> 32) as u32;

    let r1 = clmul32(x_lo, y_lo);
    let r4 = clmul32(x_hi, y_hi);
    let p_prime = x_lo ^ x_hi;
    let q_prime = y_lo ^ y_hi;
    let s = clmul32(p_prime, q_prime);
    let t = s ^ r1 ^ r4;

    let result_low = r1 ^ (t << 32);
    let result_high = (t >> 32) ^ r4;
    result_low as u128 | ((result_high as u128) << 64)
}

/// Carryless multiplication of two 32-bit arguments.
#[cfg(test)]
fn clmul32_no_simd(x: u32, y: u32) -> u64 {
    let x0 = (x & (MASK_0 as u32)) as u64;
    let x1 = (x & (MASK_1 as u32)) as u64;
    let x2 = (x & (MASK_2 as u32)) as u64;
    let x3 = (x & (MASK_3 as u32)) as u64;
    let y0 = (y & (MASK_0 as u32)) as u64;
    let y1 = (y & (MASK_1 as u32)) as u64;
    let y2 = (y & (MASK_2 as u32)) as u64;
    let y3 = (y & (MASK_3 as u32)) as u64;

    let z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)) & MASK_0;
    let z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)) & MASK_1;
    let z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)) & MASK_2;
    let z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)) & MASK_3;

    z0 | z1 | z2 | z3
}

/// Carryless multiplication of two 32-bit arguments.
fn clmul32(x: u32, y: u32) -> u64 {
    let x_splat = u64x2_splat(x as u64);
    let y_splat = u64x2_splat(y as u64);

    let x0_splat = v128_and(x_splat, u64x2_splat(MASK_0));
    let x1_splat = v128_and(x_splat, u64x2_splat(MASK_1));
    let x2_splat = v128_and(x_splat, u64x2_splat(MASK_2));
    let x3_splat = v128_and(x_splat, u64x2_splat(MASK_3));

    let mask_0_1 = u64x2(MASK_0, MASK_1);
    let mask_1_2 = u64x2(MASK_1, MASK_2);
    let mask_2_3 = u64x2(MASK_2, MASK_3);
    let mask_3_0 = u64x2(MASK_3, MASK_0);

    let y0_y1 = v128_and(y_splat, mask_0_1);
    let y2_y3 = v128_and(y_splat, mask_2_3);
    let y3_y0 = v128_and(y_splat, mask_3_0);
    let y1_y2 = v128_and(y_splat, mask_1_2);

    let z0_z1 = v128_and(
        v128_xor(
            v128_xor(u64x2_mul(x0_splat, y0_y1), u64x2_mul(x1_splat, y3_y0)),
            v128_xor(u64x2_mul(x2_splat, y2_y3), u64x2_mul(x3_splat, y1_y2)),
        ),
        mask_0_1,
    );
    let z2_z3 = v128_and(
        v128_xor(
            v128_xor(u64x2_mul(x0_splat, y2_y3), u64x2_mul(x1_splat, y1_y2)),
            v128_xor(u64x2_mul(x2_splat, y0_y1), u64x2_mul(x3_splat, y3_y0)),
        ),
        mask_2_3,
    );

    let or_result = v128_or(z0_z1, z2_z3);

    u64x2_extract_lane::<0>(or_result) | u64x2_extract_lane::<1>(or_result)
}

const MASK_0: u64 = 0x1111_1111_1111_1111;
const MASK_1: u64 = 0x2222_2222_2222_2222;
const MASK_2: u64 = 0x4444_4444_4444_4444;
const MASK_3: u64 = 0x8888_8888_8888_8888;

fn reduce(product: U256) -> u128 {
    let first_reduction = U256 {
        high: (product.high >> (128 - 1))
            ^ (product.high >> (128 - 2))
            ^ (product.high >> (128 - 7)),
        low: product.low
            ^ product.high
            ^ (product.high << 1)
            ^ (product.high << 2)
            ^ (product.high << 7),
    };
    first_reduction.low
        ^ first_reduction.high
        ^ (first_reduction.high << 1)
        ^ (first_reduction.high << 2)
        ^ (first_reduction.high << 7)
}

#[cfg(test)]
mod tests {
    use crate::fields::field2_128::backend_wasm_simd::{clmul32, clmul32_no_simd, galois_multiply};
    use rand::random;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn clmul32_equivalent() {
        fn check(x: u32, y: u32) {
            let expected = clmul32_no_simd(x, y);
            let actual = clmul32(x, y);
            assert_eq!(
                expected, actual,
                "SIMD clmul32 implementation is incorrect: x={x:08x}, y={y:08x} \
                expected={expected:08x}, simd={actual:08x}"
            );
        }

        let special_values = [
            0x0000_0000,
            0x0000_0001,
            0xFFFF_FFFF,
            0xDEAD_BEEF,
            0x8000_0000,
            0x1111_1111,
            0x8888_8888,
            0x3333_3333,
            0x5555_5555,
        ];
        for x in special_values {
            for y in special_values {
                check(x, y);
            }
        }

        for log_x in 0..32 {
            for log_y in 0..32 {
                check(1 << log_x, 1 << log_y);
            }
        }

        for _ in 0..1000 {
            check(random(), random());
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_multiply() {
        assert_eq!(
            galois_multiply(0x1_0000_0000_0000_0000, 0x1_0000_0000_0000_0000),
            0x87
        );
    }
}
