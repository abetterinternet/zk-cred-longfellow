#!/usr/bin/env sh
set -ev

# The addchain binary must be on the path already. For installation
# instructions, see
# https://github.com/mmcloughlin/addchain/blob/master/README.md#usage.

cd "$(dirname "$0")"/addition_chains

addchain gen -tmpl template.txt -out p128m2.rs p128m2.acc
addchain gen -tmpl template.txt -out p256m2.rs p256m2.acc
addchain gen -tmpl template.txt -out p521m2.rs p521m2.acc
addchain gen -tmpl template.txt -out gf_2_128_m2.rs gf_2_128_m2.acc
