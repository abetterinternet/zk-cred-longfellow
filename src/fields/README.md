# Generating field implementations

Field arithmetic routines (for prime-order fields) are generated using
fiat-crypto using the following procedure.

## Prerequisites

Install and initialize [opam](https://opam.ocaml.org/doc/Install.html), and
clone [mit-plv/fiat-crypto](https://github.com/mit-plv/fiat-crypto/). Run the
following commands to install dependencies, check out the code, and do a clean
build and install.

```sh
opam install coq=8.20.0
eval $(opam env)
git checkout fc8ce4b3ced2e8a24773b708666a74d132a8425e
git submodule update --init --recursive
git clean -xdf
git submodule foreach --recursive git clean -xdf
make standalone-ocaml
```

## Code generation

Once the fiat-crypto binaries have been compiled, ensure they are on your `PATH`
by adding the `src/ExtractionOCaml` subdirectory to the `PATH` environment
variable. Then, run `codegen_fiat_crypto.sh` in this directory.

## Algorithm choice

Multiple algorithms or strategies are provided by fiat-crypto. Of the available
choices, both Word-by-word Montgomery and Unsaturated Solinas provide the
variety of field operations we require.

Word-by-word Montgomery transforms field elements into a different domain, by
multiplying by a specific constant. This enables efficient field element
multiplication using wrapping multiplication instructions.

The Unsaturated Solinas algorithm is named after Solinas primes (also known as
generalized Mersenne primes), which are of the form
$2^m - 2^a \pm 2^b \pm 2^c \pm ... \pm 1$.
"Unsaturated" refers to the fact that multiple-precision arithmetic is
implemented with a radix that is smaller than the machine word size. For more
background, see [Elliptic Curve Cryptography for the
masses](https://eprint.iacr.org/2024/779). Unfortunately, this algorithm does
not work with all Solinas primes, due to [known
issues](https://github.com/mit-plv/fiat-crypto/issues/554) when synthesizing
logic for primes that have a "plus" in their decomposition. For these cases, we
can fall back to using Word-by-word Montgomery.

# Generating addition chain exponentiation routines

Multiplicative inverse operations are implemented with addition chain
exponentiation. These routines are generated using the `addchain` tool.

## Prerequisites

Install [addchain](https://github.com/mmcloughlin/addchain/blob/master/README.md#usage),
either from prebuilt binaries or by compiling it from source.

## Addition chain search

Ensure that `addchain` is on your `PATH`. The addition chain search can be
re-run by executing `find_addition_chains.sh` in this directory.

## Code generation

Run `codegen_addchain.sh` to generate exponentiation routines from addition
chain files and the template file. As before, `addchain` must be on your `PATH`.
