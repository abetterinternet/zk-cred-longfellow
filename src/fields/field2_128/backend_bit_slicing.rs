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
/// This fallback implementation uses SIMD-within-a-register techniques. It combines bit slicing
/// with integer multiplication to implement carryless multiplication.
pub(super) fn galois_square(x: u128) -> u128 {
    // Produce a 255-bit carryless multiplication product.
    let product = clmul128_square(x);

    reduce(product)
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

const MASK_0: u128 = 0x21084210842108421084210842108421;
const MASK_1: u128 = 0x42108421084210842108421084210842;
const MASK_2: u128 = 0x84210842108421084210842108421084;
const MASK_3: u128 = 0x08421084210842108421084210842108;
const MASK_4: u128 = 0x10842108421084210842108421084210;

/// Carryless multiplication of two 64-bit arguments.
fn clmul64(x: u64, y: u64) -> u128 {
    // This uses the technique outlined in
    // https://timtaubert.de/blog/2017/06/verified-binary-multiplication-for-ghash/. Integer
    // multiplications on masked arguments are used to build up a carryless multiplication. All bits
    // except every fifth are masked off, so that the carries that accumulate during one integer
    // multiply won't interfere with the LSB of the next group of five bits in the integer product.

    let x0 = (x & (MASK_0 as u64)) as u128;
    let x1 = (x & (MASK_1 as u64)) as u128;
    let x2 = (x & (MASK_2 as u64)) as u128;
    let x3 = (x & (MASK_3 as u64)) as u128;
    let x4 = (x & (MASK_4 as u64)) as u128;
    let y0 = (y & (MASK_0 as u64)) as u128;
    let y1 = (y & (MASK_1 as u64)) as u128;
    let y2 = (y & (MASK_2 as u64)) as u128;
    let y3 = (y & (MASK_3 as u64)) as u128;
    let y4 = (y & (MASK_4 as u64)) as u128;

    let z0 = ((x0 * y0) ^ (x1 * y4) ^ (x2 * y3) ^ (x3 * y2) ^ (x4 * y1)) & MASK_0;
    let z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y4) ^ (x3 * y3) ^ (x4 * y2)) & MASK_1;
    let z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y4) ^ (x4 * y3)) & MASK_2;
    let z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0) ^ (x4 * y4)) & MASK_3;
    let z4 = ((x0 * y4) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1) ^ (x4 * y0)) & MASK_4;

    z0 | z1 | z2 | z3 | z4
}

/// Carryless multiplication of one 64-bit argument by itself.
fn clmul64_square(x: u64) -> u128 {
    // Note that most of the terms in `clmul64()` cancel out when x = y, in the case of squaring.
    // This results in a much simpler formula. In fact, the even bits of the output directly
    // correspond to all the bits of the input.

    let x0 = (x & (MASK_0 as u64)) as u128;
    let x1 = (x & (MASK_1 as u64)) as u128;
    let x2 = (x & (MASK_2 as u64)) as u128;
    let x3 = (x & (MASK_3 as u64)) as u128;
    let x4 = (x & (MASK_4 as u64)) as u128;

    let z0 = (x0 * x0) & MASK_0;
    let z1 = (x3 * x3) & MASK_1;
    let z2 = (x1 * x1) & MASK_2;
    let z3 = (x4 * x4) & MASK_3;
    let z4 = (x2 * x2) & MASK_4;

    z0 | z1 | z2 | z3 | z4
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

/// Carryless multiplication of one 128-bit argument by itself.
fn clmul128_square(x: u128) -> U256 {
    // This uses schoolbook multiplication. Since we are squaring in a field of characteristic two,
    // terms that arise from multiplying the low half of the input by the high half of the input (or
    // vice versa) appear twice, and therefore cancel themselves out.
    U256 {
        high: clmul64_square((x >> 64) as u64),
        low: clmul64_square(x as u64),
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
