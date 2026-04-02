use core::arch::aarch64::vmull_p64;

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This follows a similar approach as the x86-specific code, but uses ARM intrinsics.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
pub(super) fn galois_multiply(x: u128, y: u128) -> u128 {
    // Perform carryless multiplication using schoolbook multiplication and the PMULL instruction.
    let product1 = vmull_p64(x as u64, y as u64);
    let product2 = vmull_p64((x >> 64) as u64, y as u64);
    let product3 = vmull_p64(x as u64, (y >> 64) as u64);
    let product4 = vmull_p64((x >> 64) as u64, (y >> 64) as u64);
    let middle = product2 ^ product3;

    let intermediate_middle = reduce(middle, product4);
    reduce(product1, intermediate_middle)
}

/// Squares a GF(2^128) element, represented as a `u128`.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
pub(super) fn galois_square(x: u128) -> u128 {
    // Perform carryless multiplication using schoolbook multiplication and the PMULL instruction.
    //
    // In the terms of the variables used by `galois_multiply()`, we know when squaring that
    // `product2` and `product3` will be equal. Therefore, `middle` will be zero, since the field
    // has characteristic two and `product2` and `product3` cancel out.
    let product1 = vmull_p64(x as u64, x as u64);
    let product4 = vmull_p64((x >> 64) as u64, (x >> 64) as u64);

    let intermediate_middle = reduce(0, product4);
    reduce(product1, intermediate_middle)
}

/// Reduce an intermediate 192-bit result by the field's quotient polynomial.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
fn reduce(result_low: u128, result_middle: u128) -> u128 {
    // See the x86_64 implementation for an explanation of this function.
    let product = vmull_p64((result_middle >> 64) as u64, 0x87);
    result_low ^ (result_middle << 64) ^ product
}
