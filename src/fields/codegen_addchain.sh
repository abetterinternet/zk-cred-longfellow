#!/usr/bin/env bash
set -e

if ! hash addchain; then
    echo "The addchain binary must be on the path already. For installation instructions,"
    echo "see https://github.com/mmcloughlin/addchain/blob/master/README.md#usage."
    exit 1
fi

cd "$(dirname "$0")"/addition_chains

addchain gen -tmpl template.txt -out p128m2.rs p128m2.acc
addchain gen -tmpl template.txt -out p256m2.rs p256m2.acc
addchain gen -tmpl template.txt -out p256_scalar_m2.rs p256_scalar_m2.acc
addchain gen -tmpl template.txt -out gf_2_128_m2.rs gf_2_128_m2.acc
