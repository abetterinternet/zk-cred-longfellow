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
fn clmul32(x: u32, y: u32) -> u64 {
    // This uses the technique outlined in
    // https://timtaubert.de/blog/2017/06/verified-binary-multiplication-for-ghash/. Integer
    // multiplications on masked arguments are used to build up a carryless multiplication. All bits
    // except every fourth are masked off, so that the carries that accumulate during one integer
    // multiply won't interfere with the LSB of the next group of four bits in the integer product.

    const MASK_0: u64 = 0x1111_1111_1111_1111;
    const MASK_1: u64 = 0x2222_2222_2222_2222;
    const MASK_2: u64 = 0x4444_4444_4444_4444;
    const MASK_3: u64 = 0x8888_8888_8888_8888;

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
