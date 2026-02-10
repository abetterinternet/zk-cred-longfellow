#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
use std::arch::wasm32::{
    u8x16, u8x16_shl, u8x16_shr, u8x16_splat, u8x16_swizzle, u64x2, u64x2_extract_lane, v128_and,
    v128_or,
};
use std::fmt::Debug;

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This fallback implementation uses SIMD-within-a-register techniques. It combines bit slicing
/// with integer multiplication to implement carryless multiplication.
pub(super) fn galois_multiply(x: u128, y: u128) -> u128 {
    // Produce a 255-bit carryless multiplication product.
    let product = clmul128(x, y);

    reduce(product)
}

/// Squares a GF(2^128) element, represented as a `u128`.
///
/// This fallback implementation uses bit manipulation.
pub(super) fn galois_square(x: u128) -> u128 {
    // Squaring when using carryless multiplication looks like interleaving the bits of the input
    // with zeroes. We can accomplish this with shifts, ANDs, and ORs, rather than using many
    // multiplications.
    //
    // The lower half of x will end up in the lower u128 of the result, and the upper half of x
    // will end up in the upper u128 of the result.
    let product = U256 {
        high: galois_square_u64_widening((x >> 64) as u64),
        low: galois_square_u64_widening(x as u64),
    };

    reduce(product)
}

/// Helper for squaring GF(2^128) elements.
///
/// This interleaves the bits of its input with zeroes.
fn galois_square_u64_widening(x: u64) -> u128 {
    // Adapted from https://graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN.
    let x = x as u128;
    let x = (x | (x << 32)) & 0x0000_0000_FFFF_FFFF_0000_0000_FFFF_FFFF;
    let x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF_0000_FFFF_0000_FFFF;
    let x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF_00FF_00FF_00FF_00FF;
    let x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F;
    let x = (x | (x << 2)) & 0x3333_3333_3333_3333_3333_3333_3333_3333;
    (x | (x << 1)) & 0x5555_5555_5555_5555_5555_5555_5555_5555
}

/// Reduce an intermediate 256-bit product by the field's quotient polynomial.
fn reduce(product: U256) -> u128 {
    // Reduce the result by x^128 + x^7 + x^2 + x + 1.
    //
    // First we multiply the upper u128 of the product, all of which has a factor of x^128 in it, by
    // the rest of the reduction polynomial, x^7 + x^2 + x + 1, and then XOR this 134-bit product
    // with the lower u128 of the original product. We perform the multiplication by a constant with
    // shifts and XORs.
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

    // We repeat this to perform a second reduction step, multiplying 6 bits from the upper u128 of
    // the previous step by the same 8 bit constant. This product is 13 bits, so no further
    // reduction step is needed.
    first_reduction.low
        ^ first_reduction.high
        ^ (first_reduction.high << 1)
        ^ (first_reduction.high << 2)
        ^ (first_reduction.high << 7)
}

const MASK_0: u64 = 0x1111_1111_1111_1111;
const MASK_1: u64 = 0x2222_2222_2222_2222;
const MASK_2: u64 = 0x4444_4444_4444_4444;
const MASK_3: u64 = 0x8888_8888_8888_8888;

/// Carryless multiplication of two 64-bit arguments, producing the bottom 64 bits of the product.
fn clmul64_lo(x: u64, y: u64) -> u64 {
    // This uses the technique outlined in
    // https://timtaubert.de/blog/2017/06/verified-binary-multiplication-for-ghash/. Integer
    // multiplications on masked arguments are used to build up a carryless multiplication. All bits
    // except every fourth are masked off, so that the carries that accumulate during one integer
    // multiply won't interfere with the LSB of the next group of four bits in the integer product.
    // The topmost group may have up to 16 addends contributing to one output bit, but there is no
    // next output bit for it to overflow into, and the rest all have 15 or fewer addends. See also
    // https://www.bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c;h=a46f16fee977f6102abea7f7bcdf169a013c3e8e;hb=5f045c759957fdff8c85716e6af99e10901fdac0.

    let x0 = x & MASK_0;
    let x1 = x & MASK_1;
    let x2 = x & MASK_2;
    let x3 = x & MASK_3;
    let y0 = y & MASK_0;
    let y1 = y & MASK_1;
    let y2 = y & MASK_2;
    let y3 = y & MASK_3;

    let z0 = ((x0.wrapping_mul(y0))
        ^ (x1.wrapping_mul(y3))
        ^ (x2.wrapping_mul(y2))
        ^ (x3.wrapping_mul(y1)))
        & MASK_0;
    let z1 = ((x0.wrapping_mul(y1))
        ^ (x1.wrapping_mul(y0))
        ^ (x2.wrapping_mul(y3))
        ^ (x3.wrapping_mul(y2)))
        & MASK_1;
    let z2 = ((x0.wrapping_mul(y2))
        ^ (x1.wrapping_mul(y1))
        ^ (x2.wrapping_mul(y0))
        ^ (x3.wrapping_mul(y3)))
        & MASK_2;
    let z3 = ((x0.wrapping_mul(y3))
        ^ (x1.wrapping_mul(y2))
        ^ (x2.wrapping_mul(y1))
        ^ (x3.wrapping_mul(y0)))
        & MASK_3;

    z0 | z1 | z2 | z3
}

/// Carryless multiplication of two 64-bit arguments, producing the full 127-bit product.
fn clmul64(x: u64, y: u64) -> u128 {
    // We get the bottom half of the result from calling clmul64_lo() directly.
    let lo = clmul64_lo(x, y);
    // We exploit symmetry to get the top half of the result by combining bit reverals and
    // clmul64_lo().
    let (x_reversed, y_reversed) = reverse_bits_x2(x, y);
    let hi = clmul64_lo(x_reversed, y_reversed).reverse_bits();
    (lo as u128) | ((hi as u128) << 63)
}

#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
fn reverse_bits_x2(x: u64, y: u64) -> (u64, u64) {
    (x.reverse_bits(), y.reverse_bits())
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
fn reverse_bits_x2(x: u64, y: u64) -> (u64, u64) {
    let mut packed = u64x2(x, y);
    packed = u8x16_swizzle(
        packed,
        u8x16(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8),
    );
    packed = v128_or(
        u8x16_shl(v128_and(packed, u8x16_splat(0x55)), 1),
        v128_and(u8x16_shr(packed, 1), u8x16_splat(0x55)),
    );
    packed = v128_or(
        u8x16_shl(v128_and(packed, u8x16_splat(0x33)), 2),
        v128_and(u8x16_shr(packed, 2), u8x16_splat(0x33)),
    );
    packed = v128_or(
        u8x16_shl(v128_and(packed, u8x16_splat(0x0F)), 4),
        v128_and(u8x16_shr(packed, 4), u8x16_splat(0x0F)),
    );
    (
        u64x2_extract_lane::<0>(packed),
        u64x2_extract_lane::<1>(packed),
    )
}

/// A 256-bit integer.
#[derive(Clone, Copy, PartialEq, Eq)]
struct U256 {
    high: u128,
    low: u128,
}

impl Debug for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("U256")
            .field("high", &format_args!("0x{:x}", self.high))
            .field("low", &format_args!("0x{:x}", self.low))
            .finish()
    }
}

/// Carryless multiplication of two 128-bit arguments.
fn clmul128(x: u128, y: u128) -> U256 {
    // This uses Karatsuba multiplication.
    let r1 = clmul64(x as u64, y as u64);
    let r4 = clmul64((x >> 64) as u64, (y >> 64) as u64);
    let p_prime = (x as u64) ^ ((x >> 64) as u64);
    let q_prime = (y as u64) ^ ((y >> 64) as u64);
    let s = clmul64(p_prime, q_prime);
    let t = s ^ r1 ^ r4;
    U256 {
        low: r1 ^ (t << 64),
        high: (t >> 64) ^ r4,
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::fields::field2_128::backend_bit_slicing::{
        U256, clmul64, clmul128, galois_multiply,
    };

    #[wasm_bindgen_test(unsupported = test)]
    fn test_clmul64() {
        assert_eq!(clmul64(1, 1), 1);
        assert_eq!(clmul64(1, 2), 2);
        assert_eq!(clmul64(2, 1), 2);
        assert_eq!(clmul64(1, 3), 3);
        assert_eq!(clmul64(3, 1), 3);
        assert_eq!(clmul64(3, 3), 5);
        assert_eq!(
            clmul64(0x8000000000000000, 0x8000000000000000),
            0x40000000000000000000000000000000
        );
        assert_eq!(
            clmul64(0xffffffffffffffff, 0x5555555555555555),
            0x33333333333333333333333333333333
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_clmul128() {
        assert_eq!(clmul128(1, 1).low, 1);
        assert_eq!(clmul128(1, 2).low, 2);
        assert_eq!(clmul128(2, 1).low, 2);
        assert_eq!(clmul128(1, 3).low, 3);
        assert_eq!(clmul128(3, 1).low, 3);
        assert_eq!(clmul128(3, 3).low, 5);
        assert_eq!(
            clmul128(
                0x8000_0000_0000_0000_0000_0000_0000_0000,
                0x8000_0000_0000_0000_0000_0000_0000_0000
            ),
            U256 {
                high: 0x4000_0000_0000_0000_0000_0000_0000_0000,
                low: 0,
            }
        );
        assert_eq!(
            clmul128(
                0x0001_0001_0001_0001_0001_0001_0001_0001,
                0x0000_0000_0000_0000_0000_0000_0000_0101
            ),
            U256 {
                high: 0,
                low: 0x0101_0101_0101_0101_0101_0101_0101_0101,
            }
        );
        assert_eq!(
            clmul128(
                0x0001_0000_0000_0000_0000_0000_0000_0001,
                0x0001_0000_0000_0000_0000_0000_0000_0001
            ),
            U256 {
                high: 0x0000_0001_0000_0000_0000_0000_0000_0000,
                low: 0x0000_0000_0000_0000_0000_0000_0000_0001,
            }
        );
        assert_eq!(
            clmul128(
                0xffffffffffffffffffffffffffffffff,
                0x55555555555555555555555555555555,
            ),
            U256 {
                high: 0x33333333333333333333333333333333,
                low: 0x33333333333333333333333333333333,
            }
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_multiply() {
        assert_eq!(
            galois_multiply(0x1_0000_0000_0000_0000, 0x1_0000_0000_0000_0000),
            0x87
        );
    }
}
