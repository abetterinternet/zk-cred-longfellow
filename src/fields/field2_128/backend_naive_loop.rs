/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This is a very slow implementation of multiplication, using arrays of booleans and loops.
pub(super) fn galois_multiply(x: u128, y: u128) -> u128 {
    let x = decompose(x);
    let y = decompose(y);

    // Perform carryless product.
    let mut product = [false; 255];
    let mut iter = product.iter_mut().enumerate();
    for _ in 0..128 {
        let (i, out) = iter.next().unwrap();
        for (left, right) in x[0..=i].iter().zip(y[0..=i].iter().rev()) {
            *out ^= *left & right;
        }
    }
    for (i, out) in iter {
        for (left, right) in x[i - 127..=127].iter().zip(y[i - 127..=127].iter().rev()) {
            *out ^= *left & right;
        }
    }

    // Perform modular reduction.
    for i in (0..127).rev() {
        if product[i + 128] {
            product[i + 128] ^= true;
            product[i + 7] ^= true;
            product[i + 2] ^= true;
            product[i + 1] ^= true;
            product[i] ^= true;
        }
    }

    let mut output = 0u128;
    for (i, bit) in product[..128].iter().enumerate() {
        output |= (*bit as u128) << i;
    }
    output
}

fn decompose(value: u128) -> [bool; 128] {
    let mut bits = [false; 128];
    for (i, out) in bits.iter_mut().enumerate() {
        *out = (value >> i) & 1 != 0;
    }
    bits
}

/// Squares a GF(2^128) element, represented as a `u128`.
///
/// This is a very slow implementation of multiplication, using arrays of booleans and loops.
pub(super) fn galois_square(x: u128) -> u128 {
    galois_multiply(x, x)
}
