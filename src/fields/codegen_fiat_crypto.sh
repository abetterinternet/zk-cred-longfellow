#!/usr/bin/env sh
set -ev

# The fiat-crypto binaries must be on the path already. These are at
# `src/ExtractionOCaml/word_by_word_montgomery`, etc., in the checkout. See
# README.md for compilation instructions.

cd "$(dirname "$0")"

word_by_word_montgomery \
    --lang Rust \
    --inline \
    -o fieldp256/ops.rs \
    p256 \
    64 \
    '2^256 - 2^224 + 2^192 + 2^96 - 1' \
    to_montgomery from_montgomery \
    to_bytes from_bytes \
    add sub opp \
    mul square \
    selectznz \
    one

word_by_word_montgomery \
    --lang Rust \
    --inline \
    -o fieldp256_scalar/ops.rs \
    p256_scalar \
    64 \
    '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551' \
    to_montgomery from_montgomery \
    to_bytes from_bytes \
    add sub opp \
    mul square \
    selectznz \
    one

word_by_word_montgomery \
    --lang Rust \
    --inline \
    -o fieldp128/ops.rs \
    p128 \
    64 \
    '2^128 - 2^108 + 1' \
    to_montgomery from_montgomery \
    to_bytes from_bytes \
    add sub opp \
    mul square \
    selectznz \
    one
