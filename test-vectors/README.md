# Test vectors

## Proofs from one circuit

We include several test vectors that do zero knowledge proofs from a single circuit.

[`draft-google-cfrg-libzk-00`][draft-google-cfrg-libzk] contains a test vector for a serialized
circuit, but it does not appear to correspond to either the structure definitions in that same
document, or to the circuit serialization implementation in
[`longfellow-zk/lib/proto/circuit.h`][longfellow-circuit-proto].

Presumably the test vector was generated from some intermediate version of longfellow-zk, but
there's not much to be done with it.

The test vector format is a JSON document describing the test vector. Alongside it are files
containing:

- `<test-vector>.circuit.zst`: the zstd compressed serialization of the circuit. Circuits are
  compressed using `zstd(1)` with default options:

```sh
> zstd --version
*** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***
> zstd /path/to/uncompressed/circuit test-vectors/circuit/circuit-name.circuit.zst
```

- `<test-vector>.sumcheck-proof`: the serialization of the padded sumcheck proof of the evaluation
  of the circuit. These are not compressed since proofs are padded with random values and thus don't
  compress efficiently. Not every test vector includes a sumcheck proof.

- `<test-vector>.ligero-proof`: the serialization of the Ligero proof. Much like sumcheck proofs,
  they don't compress particularly well. Not every test vector includes a Ligero proof.

[longfellow-circuit-proto]: https://github.com/google/longfellow-zk/blob/main/lib/proto/circuit.h

### `longfellow-rfc-1-87474f308020535e57a778a82394a14106f8be5b-1`

This test vector was generated using [this branch][rfc-1-test-vector-constraints] of longfellow-zk.

Run the `Rfc_testvector1` test:

```sh
make -j 16 && ctest -j 16 -R ZK.Rfc_testvector1
```

The output in `LastTest.log` will include the serialized circuit, Ligero commitment, Ligero proof,
sumcheck proof and Ligero constraints.

[rfc-1-test-vector-constraints]: https://github.com/tgeoghegan/longfellow-zk/tree/zk-test-cleanup

### `longfellow-mac-circuit-66aeaf09a9cc98e36873e868307ac07279d5f7e0-1`

This test vector was generated using [`longfellow-zk/lib/circuits/mac/mac_circuit_test.cc`][mac-test-vector-1]
at commit 66aeaf09a9cc98e36873e868307ac07279d5f7e0 and the serializations for circuits, layers and
quads at that version.

[mac-test-vector-1]: https://github.com/tgeoghegan/longfellow-zk/blob/66aeaf09a9cc98e36873e868307ac07279d5f7e0/lib/circuits/mac/mac_circuit_test.cc

[draft-google-cfrg-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/

## `mdoc_zk`

### `witness_test_vector.json`

This test vector was generated using a custom test from commit
[88fc0a208659a867efe7428ad19939515dc42d07][commit]. It provides all high-level prover inputs, plus
MAC key shares generated randomly or from Fiat-Shamir challenges, and the resulting circuit input
values.

[commit]: https://github.com/divergentdave/longfellow-zk/commit/88fc0a208659a867efe7428ad19939515dc42d07
