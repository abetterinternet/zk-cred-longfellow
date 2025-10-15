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

    // Perform the first step of the reduction by x^128 + x^7 + x^2 + x + 1. Shift the upper u128 of
    // the product several times, and XOR it with the lower u128 of the product.
    let shifted_1 = result_high << 1;
    let shifted_2 = result_high << 2;
    let shifted_7 = result_high << 7;
    let first_reduction = result_low ^ result_high ^ shifted_1 ^ shifted_2 ^ shifted_7;
    let extra =
        (result_high >> (128 - 1)) ^ (result_high >> (128 - 2)) ^ (result_high >> (128 - 7));

    // Perform the second step of the reduction.
    let shifted_1 = extra << 1;
    let shifted_2 = extra << 2;
    let shifted_7 = extra << 7;
    first_reduction ^ extra ^ shifted_1 ^ shifted_2 ^ shifted_7
}
