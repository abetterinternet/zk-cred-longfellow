# V8 API split: analysis and deferred migration plan

## Status

Not implemented. This document lays out the tradeoffs so a future change can be scoped
deliberately, rather than attempted as a side effect of an unrelated PR. See
`abetterinternet/zk-cred-longfellow#222`, divergentdave's review comment on
`src/mdoc_zk/verifier.rs:267`:

> Since the pseudonym circuit needs to be called via a different method with additional
> arguments, I think it might make sense to further separate the public API used for the two
> kinds of circuits... A lot of the input preparation could be shared, but that should just be an
> implementation detail... treat this new circuit as entirely different from the existing
> `mdoc_zk` version 6 and 7 circuits.

A related, narrower comment from the same review (`src/mdoc_zk/mod.rs:49`, divergentdave) asks
whether V8's circuit version number (8) is coordinated with Google/upstream, or whether it should
get its own `zk_system_type`/format name entirely, separate from `mdoc_zk`'s version numbering.
That question is out of scope here too - it is a cross-organization coordination question, not
something a code change alone resolves - but it is closely related: if V8 ends up living under a
different system name rather than `mdoc_zk` version 8, that would itself force a public API split,
making the analysis below partially moot rather than optional.

## Why this exists as an open question

Today, `MdocZkProver` and `MdocZkVerifier` are single types that serve circuit versions 6, 7, and
8:

- `MdocZkProver::prove()` / `MdocZkVerifier::verify()` work for all three versions.
- `MdocZkProver::prove_with_ppid()` / `MdocZkVerifier::verify_with_ppid()` additionally require a
  `verifier_context: &[u8; 32]` argument, and only work for V8 (both now check
  `circuit_version == V8` up front and return an error otherwise - see the fixes in this PR).

This means the type system does not prevent a caller from constructing an `MdocZkProver` for a V6
circuit and calling `prove_with_ppid()` on it (it fails at runtime with a clear error, but not at
compile time), or constructing one for a V8 circuit and calling `prove()` on it (which succeeds,
silently omitting the pseudonym derivation - actually V8's `prove()`/`verify()` paths already
reject a missing `verifier_context`, so this specific case is caught, but only via a runtime check
inside shared code, not via the type signature). divergentdave's point is that a real split - e.g.
`MdocZkPseudonymProver`/`MdocZkPseudonymVerifier` as distinct types, or an enum-dispatched prover
that only exposes the pseudonym methods when constructed with a V8 circuit - would make invalid
combinations unrepresentable instead of runtime-checked.

## What a clean split would look like

Two shapes were considered:

1. **Separate types.** Introduce `MdocZkPseudonymProver` / `MdocZkPseudonymVerifier` (or similar
   names) that only accept V8 circuits at construction time, and only expose
   `prove()`/`verify()` methods that require `verifier_context` (dropping the `_with_ppid` suffix
   since there would be no other variant on that type). `MdocZkProver`/`MdocZkVerifier` would
   become V6/V7-only, and their construction would reject V8 circuits. Shared logic
   (`CircuitInputs::new()`, `CircuitStatements::new()`, the common hash/signature Ligero and
   Sumcheck plumbing) stays factored out as free functions or an internal shared struct, called
   from both public types - matching divergentdave's "that should just be an implementation
   detail" framing.

2. **Enum-gated single type.** Keep one type, but make `circuit_version` part of the type via a
   generic parameter or marker type (e.g. `MdocZkProver<V8Pseudonym>` vs `MdocZkProver<Standard>`),
   so the compiler enforces which methods are available. This avoids duplicating the public type
   name across languages, but is harder to express cleanly through UniFFI/wasm-bindgen, both of
   which need concrete, monomorphic types at the FFI boundary (see below) - this shape was set
   aside for that reason.

Shape 1 is the more realistic option given the FFI constraints below.

## What breaks for existing consumers

`MdocZkProver` and `MdocZkVerifier` are not internal types - they cross two FFI boundaries that
production wallet SDKs already depend on:

- **UniFFI** (`#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]` on both types, plus
  `src/ffi_api.rs`'s `#[uniffi::export]` free functions `initialize_prover`, `prove`,
  `initialize_verifier`, `verify`, and the PPID-specific exports). This is consumed by
  siros-sdk-kotlin and siros-sdk-swift, which generate language bindings from these exact type and
  function signatures.
- **wasm-bindgen** (`#[wasm_bindgen]` on both types, plus `src/js_api.rs` and the
  `prove_with_ppid_wasm`/`verify_with_ppid_wasm`/`initialize_verifier`/`verify_with_ppid_wasm`
  free functions in `src/mdoc_zk/prover.rs`), consumed by any JS/WASM caller.
- A raw C FFI export, `rust_verify_with_ppid` in `src/mdoc_zk/prover.rs`, used by a Go caller (see
  its doc comment, "C FFI for Go CGo verifier").

Introducing `MdocZkPseudonymProver`/`MdocZkPseudonymVerifier` as new types would require:

- New UniFFI object definitions and exported functions, which regenerate as new symbols in the
  Kotlin/Swift bindings - additive, not breaking, *if* the old `MdocZkProver`/`MdocZkVerifier` and
  their `_with_ppid` methods are kept as deprecated wrappers during a transition period.
- Renaming or removing `prove_with_ppid`/`verify_with_ppid` from the existing types would be a
  breaking change for any consumer that already calls them (this repository does not track
  consumer code directly, but the Kotlin/Swift SDKs and any Go caller of `rust_verify_with_ppid`
  would need coordinated updates).
- The C FFI export name and signature would need to either move to the new type's constructor
  path or be kept as-is pointing at whichever type ends up owning V8 verification.

## Suggested migration path (not started)

1. Add the new `MdocZkPseudonymProver`/`MdocZkPseudonymVerifier` types (or whatever names are
   chosen) alongside the existing ones, backed by the same shared internal helpers already
   factored out in this PR (`common_initialization`, `CircuitInputs::new`,
   `CircuitStatements::new`, the `verify_internal` helper added here). No behavior change for
   existing callers.
2. Point new consumers (or a new SDK major version) at the new types.
3. Mark `prove_with_ppid`/`verify_with_ppid` on the existing `MdocZkProver`/`MdocZkVerifier` types
   as deprecated (doc comment, and a `#[deprecated]` attribute where the FFI codegen tooling
   tolerates it - this needs to be verified against both UniFFI and wasm-bindgen, since not all
   attribute macros compose cleanly with FFI derive macros).
4. Once siros-sdk-kotlin and siros-sdk-swift (and any other confirmed consumer) have migrated,
   remove the deprecated methods and, if desired, disallow constructing
   `MdocZkProver`/`MdocZkVerifier` with a V8 circuit at all (currently they accept one, purely
   because the check lives in the `_with_ppid` methods rather than at construction time).

This is a multi-repo, multi-step migration, not a single PR - hence deferring it here rather than
attempting a partial version of it.
