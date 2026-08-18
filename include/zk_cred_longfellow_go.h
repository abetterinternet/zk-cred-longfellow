/*
 * zk_cred_longfellow_go.h — hand-written C header for zk-cred-longfellow's
 * Go (cgo) verifier ABI.
 *
 * This describes the plain `extern "C"` functions exported by
 * `src/go_ffi.rs`, built with the crate's *default* Cargo features (i.e.
 * WITHOUT `--features uniffi`).
 *
 * Do not confuse this with the UniFFI-generated header
 * (bindings/swift/zk_cred_longfellowFFI.h after `make bindings`): that one
 * describes a completely different, RustBuffer-based ABI meant for
 * UniFFI's own Swift/Kotlin scaffolding, built WITH `--features uniffi`.
 * UniFFI does not target Go, and its RustBuffer wire protocol is not
 * cgo-friendly, so this crate exposes a second, separate, ordinary C ABI
 * specifically for Go instead. The two ABIs are built from the same crate
 * but are not interchangeable, and (because Cargo feature flags don't
 * change a cdylib's output filename) are not meant to be built into the
 * same `.so`/`.a` artifact at the same time — pick this header + a
 * default-features build for Go, or the generated header + a
 * `--features uniffi` build for Swift/Kotlin.
 *
 * This header is hand-maintained (not generated); keep it in sync with
 * `src/go_ffi.rs` by hand when that file's exported signatures change.
 */

#ifndef ZK_CRED_LONGFELLOW_GO_H
#define ZK_CRED_LONGFELLOW_GO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque handle to a loaded, compiled circuit. Obtained from
 * rust_initialize_verifier() and released with rust_free_verifier().
 * Never dereference or introspect this type from C/Go; treat it as an
 * opaque pointer.
 */
typedef struct MdocZkVerifier MdocZkVerifier;

/*
 * A single disclosed attribute: an identifier and its CBOR-encoded value.
 *
 * `identifier` must be a NUL-terminated UTF-8 string.
 * `value_cbor` must point to at least `value_cbor_len` bytes (may be NULL
 * only if `value_cbor_len` is 0).
 */
typedef struct {
    const char *identifier;
    const uint8_t *value_cbor;
    size_t value_cbor_len;
} CAttribute;

/*
 * Loads and compiles a circuit, returning an opaque verifier handle, or
 * NULL on failure.
 *
 * `circuit`/`circuit_len`: the decompressed circuit file contents.
 * `circuit_version`: 6, 7, or 8. Any other value is rejected.
 * `num_attributes`: number of attributes this circuit (and every later
 * rust_verify_with_ppid() call using the returned handle) expects, 1-4.
 * `error_out`: optional (may be NULL). On failure, if non-NULL, `*error_out`
 * is set to a newly allocated, NUL-terminated, UTF-8 error string that the
 * caller must eventually pass to rust_free_error_string(). On success,
 * `*error_out` is set to NULL.
 *
 * This is the expensive, one-time part of setting up a verifier: call this
 * once per distinct circuit and reuse the returned handle across many
 * rust_verify_with_ppid() calls (from any number of goroutines/threads),
 * rather than reloading the circuit on every verification.
 */
MdocZkVerifier *rust_initialize_verifier(
    const uint8_t *circuit,
    size_t circuit_len,
    uint8_t circuit_version,
    uint8_t num_attributes,
    char **error_out
);

/*
 * Frees a verifier handle previously returned by rust_initialize_verifier().
 *
 * Passing NULL is a no-op. Passing the same non-NULL pointer more than
 * once, or using the pointer after freeing it, is undefined behavior (the
 * same rules as free() in C). The caller must also ensure no
 * rust_verify_with_ppid() call using this handle is still in flight on
 * another thread when this is called.
 */
void rust_free_verifier(MdocZkVerifier *verifier);

/*
 * Frees an error string previously written into an `error_out`
 * out-parameter by a function in this header. Passing NULL is a no-op.
 */
void rust_free_error_string(char *ptr);

/*
 * Verifies a V8 proof of possession with pairwise-pseudonym (PPID) support.
 *
 * `verifier`: a live handle from rust_initialize_verifier() (must not be
 *   NULL, freed, or concurrently being freed by another thread).
 * `issuer_pk`/`issuer_pk_len`: issuer public key, SEC1-encoded, as found in
 *   the X.509 SubjectPublicKeyInfo.
 * `attributes`/`attributes_len`: the disclosed attributes; the count must
 *   match the `num_attributes` the verifier was initialized with. May be
 *   NULL only if `attributes_len` is 0.
 * `doc_type`: NUL-terminated document type string (e.g.
 *   "org.iso.18013.5.1.mDL"). Must not be NULL.
 * `device_name_spaces_bytes`/`_len`: CBOR-encoded DeviceNameSpacesBytes from
 *   the DeviceResponse (may be an empty CBOR map, e.g. "\xa0"). May be NULL
 *   only if the length is 0.
 * `session_transcript`/`_len`: CBOR-encoded SessionTranscript.
 * `time`: NUL-terminated current time, RFC 3339 format. Must not be NULL.
 * `verifier_context`/`verifier_context_len`: verifier context used to
 *   derive the pseudonym; `verifier_context_len` must be exactly 32.
 * `proof`/`proof_len`: the serialized proof bytes.
 * `error_out`: optional (may be NULL); see rust_initialize_verifier() for
 *   the out-parameter contract.
 *
 * Returns 0 on success. On failure, returns a negative status code
 * (-1: input validation or verification error; -2: an internal panic was
 * caught) and, if `error_out` is non-NULL, writes an owned error message
 * there.
 *
 * This performs the same real cryptographic verification (transcript
 * replay, Sumcheck, Ligero, MAC tag checks, PPID derivation) as the crate's
 * safe Rust API — it is a thin parsing/validation wrapper around it, not a
 * separate, weaker check.
 */
int32_t rust_verify_with_ppid(
    const MdocZkVerifier *verifier,
    const uint8_t *issuer_pk,
    size_t issuer_pk_len,
    const CAttribute *attributes,
    size_t attributes_len,
    const char *doc_type,
    const uint8_t *device_name_spaces_bytes,
    size_t device_name_spaces_bytes_len,
    const uint8_t *session_transcript,
    size_t session_transcript_len,
    const char *time,
    const uint8_t *verifier_context,
    size_t verifier_context_len,
    const uint8_t *proof,
    size_t proof_len,
    char **error_out
);

#ifdef __cplusplus
}
#endif

#endif /* ZK_CRED_LONGFELLOW_GO_H */
