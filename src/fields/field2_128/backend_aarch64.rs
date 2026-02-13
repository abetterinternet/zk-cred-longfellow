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
    let middle_high = middle >> 64;
    let middle_low = middle << 64;
    let result_low = product1 ^ middle_low;
    let result_high = product4 ^ middle_high;

    reduce(result_low, result_high)
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
    let result_low = product1;
    let result_high = product4;

    reduce(result_low, result_high)
}

/// Reduce an intermediate 256-bit product by the field's quotient polynomial.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
fn reduce(mut result_low: u128, result_high: u128) -> u128 {
    // Perform the first step of the reduction by x^128 + x^7 + x^2 + x + 1. Multiply the top 64
    // bits by x^7 + x^2 + x + 1, and XOR the result in shifted down by 128 bits.
    let first_product = vmull_p64((result_high >> 64) as u64, 0x87);
    let middle = first_product ^ (result_high << 64);
    result_low ^= middle << 64;

    // Perform the second step of the reduction. We again multiply the highest part of the remaining
    // result by (x^7 + x^2 + x + 1), and add it to the low part.
    let second_product = vmull_p64((middle >> 64) as u64, 0x87);
    result_low ^ second_product
}
