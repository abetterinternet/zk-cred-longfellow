# This script was used to generate various constants for Field2_128. It can be run in
# https://sagecell.sagemath.org.

# GF(2^128)
GF2 = GF(2)
x = polygen(GF2)
GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)

# Construct the subfield basis described in draft-google-cfrg-libzk-1 2.2.2.
# https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
basis = []
# (2^128 - 1) / (2^16 - 1) = 5192376087906286159508272029171713
g = GF2_128(x)^5192376087906286159508272029171713
for i in range(16):
    basis.append(g^i)

# inject SUMCHECK_P2 (aka the function x) into the subfield
p2_integer = GF2_128(x).to_integer()
p2_injected = GF2_128(0)
for basis_element in basis:
    if p2_integer & 1 == 1:
        p2_injected += basis_element;
    p2_integer = p2_integer >> 1

print("SUMCHECK_P2:", p2_injected.to_integer())
print("SUMCHECK_P2_MUL_INV:", p2_injected.inverse().to_integer())
print("ONE_MINUS_SUMCHECK_P2_MUL_INV:", GF2_128(1 - p2_injected).inverse().to_integer())
print("SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV:", GF2_128(p2_injected^2 - p2_injected).inverse().to_integer())
