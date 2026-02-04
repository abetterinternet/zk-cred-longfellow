# Toolchain installation

Rust can be installed via [rustup](https://rustup.rs/).

Building WASM modules will require installing toolchains for additional targets.
This can be done with `rustup target add wasm32-unknown-unknown wasm32-wasip1`.
The [wasm-pack](https://drager.github.io/wasm-pack/installer/) build tool is
required for wasm32-unknown-unknown builds targeting browsers or Node.js.

# Code generation tool installation

Some of the code for finite field arithmetic is automatically generated.
Instructions for installing and running the relevant tools are at
`src/fields/README.md`.

# Benchmarking

Benchmarks use the [Criterion.rs](https://criterion-rs.github.io/book/) library.
Native benchmarks can be run via `cargo bench`, as usual. WASM benchmarks can be
run against a browser by running `cargo xtask wasm-bench <BENCH>`.
