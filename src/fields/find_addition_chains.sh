#!/usr/bin/env bash
set -e

if ! hash addchain; then
    echo "The addchain binary must be on the path already. For installation instructions,"
    echo "see https://github.com/mmcloughlin/addchain/blob/master/README.md#usage."
    exit 1
fi

cd "$(dirname "$0")"/addition_chains

addchain search '0xfffff000000000000000000000000001 - 2' > p128m2.acc
addchain search '0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff - 2' > p256m2.acc
addchain search '2^128 - 2' > gf_2_128_m2.acc
