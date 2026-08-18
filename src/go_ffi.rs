//! Plain C-ABI bindings for a Go (cgo) verifier service.
//!
//! `ffi_api.rs` exports a UniFFI-based ABI (RustBuffer wire format, generated
//! Swift/Kotlin scaffolding) for the native wallet SDKs. UniFFI does not
//! target Go, and its RustBuffer protocol is not cgo-friendly, so this module
//! is a separate, hand-written, ordinary `extern "C"` ABI: plain pointers,
//! lengths, and small integer status codes only. A Go process can call these
//! functions directly via cgo without any generated scaffolding.
//!
//! ## Lifecycle
//!
//! 1. [`rust_initialize_verifier`](crate::go_ffi::rust_initialize_verifier) loads and
//!    compiles a circuit exactly once, handing back an opaque
//!    `*mut MdocZkVerifier` handle. Circuit loading involves decoding +
//!    constructing Ligero parameters for two circuits (hash + signature),
//!    which is comparatively expensive; a long-lived Go process should call
//!    this once per distinct circuit and cache the handle, not reload per
//!    verification.
//! 2. [`rust_verify_with_ppid`](crate::go_ffi::rust_verify_with_ppid) is called
//!    (possibly many times, possibly concurrently from multiple
//!    goroutines/OS threads) with that handle plus the attributes/proof/etc.
//!    for one presentation. `MdocZkVerifier` holds no interior mutability
//!    and every verification method takes `&self`, so concurrent reads
//!    through the same handle are sound.
//! 3. [`rust_free_verifier`](crate::go_ffi::rust_free_verifier) releases the handle
//!    when the process is done with that circuit (e.g. on shutdown, or when
//!    evicting an LRU cache of loaded circuits).
//!
//! ## Handle safety
//!
//! The opaque pointer is created via `Box::into_raw` in
//! [`rust_initialize_verifier`](crate::go_ffi::rust_initialize_verifier) and consumed
//! exactly once by [`rust_free_verifier`](crate::go_ffi::rust_free_verifier) via
//! `Box::from_raw`. As with any C handle, the caller must not free the same
//! pointer twice, and must not use it (call
//! [`rust_verify_with_ppid`](crate::go_ffi::rust_verify_with_ppid) with it) after
//! freeing it, and must not free it while a call using it is still in flight
//! on another thread. These are ordinary handle-lifecycle obligations that
//! Rust's type system cannot enforce across an FFI boundary; they are the
//! same obligations any C library imposes on its opaque handles.
//!
//! ## Error reporting
//!
//! Every fallible function here takes an `error_out: *mut *mut c_char`
//! out-parameter (may be null if the caller doesn't want the message). On
//! failure, an owned, NUL-terminated, UTF-8 error string is written there;
//! the caller must eventually pass it to
//! [`rust_free_error_string`](crate::go_ffi::rust_free_error_string) to avoid
//! leaking it. On success, `*error_out` is set to null (if `error_out` itself
//! is non-null). This "owned, caller-freed string" shape was chosen over a
//! thread-local `rust_last_error_message()` accessor because verification
//! calls are expected to run concurrently across goroutines mapped onto
//! multiple OS threads; a thread-local last-error slot would be correct only
//! if Go pinned each logical caller to one OS thread for the duration of the
//! call, which cgo does not guarantee.

use crate::mdoc_zk::{
    CircuitVersion,
    verifier::{Attribute, MdocZkVerifier},
};
use std::ffi::{CStr, CString, c_char};
use std::slice;

/// A single disclosed attribute crossing the C ABI: an identifier string and
/// the CBOR-encoded value bytes.
///
/// Mirrors [`crate::mdoc_zk::verifier::Attribute`], but with plain
/// C-compatible fields (a NUL-terminated string pointer and a pointer+length
/// byte buffer) instead of `String`/`Vec<u8>`, so Go can build an array of
/// these directly via cgo without needing any Rust-side allocation helpers.
#[repr(C)]
pub struct CAttribute {
    /// NUL-terminated attribute identifier (e.g. "given_name"). Must not be
    /// null.
    pub identifier: *const c_char,
    /// Pointer to the CBOR-encoded attribute value bytes. May be null only
    /// if `value_cbor_len` is 0.
    pub value_cbor: *const u8,
    /// Length of `value_cbor` in bytes.
    pub value_cbor_len: usize,
}

/// Converts a raw `u8` circuit version tag into [`CircuitVersion`].
///
/// The only valid values are 6, 7, and 8, matching
/// [`CircuitVersion`]'s own `#[repr]` discriminants.
fn circuit_version_from_u8(value: u8) -> Result<CircuitVersion, anyhow::Error> {
    match value {
        6 => Ok(CircuitVersion::V6),
        7 => Ok(CircuitVersion::V7),
        8 => Ok(CircuitVersion::V8),
        other => Err(anyhow::anyhow!(
            "unsupported circuit_version: {other} (expected 6, 7, or 8)"
        )),
    }
}

/// Reads a NUL-terminated C string as `&str`.
///
/// # Safety
///
/// `ptr` must either be null (rejected with an error) or point to a valid
/// NUL-terminated C string that lives at least as long as the borrow
/// returned here.
unsafe fn cstr_to_str<'a>(ptr: *const c_char, field: &str) -> Result<&'a str, anyhow::Error> {
    if ptr.is_null() {
        return Err(anyhow::anyhow!("{field} must not be null"));
    }
    // SAFETY: forwarded from the caller's safety contract; `ptr` is non-null
    // per the check above.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| anyhow::anyhow!("{field} is not valid UTF-8: {e}"))
}

/// Builds a `&[u8]` from a pointer+length pair, treating a zero length as an
/// empty slice regardless of whether the pointer is null (this matches how
/// Go/cgo commonly represents an empty byte slice as a null data pointer).
///
/// # Safety
///
/// If `len > 0`, `ptr` must be non-null and point to at least `len` valid,
/// initialized bytes that live at least as long as the borrow returned here.
unsafe fn bytes_or_empty<'a>(
    ptr: *const u8,
    len: usize,
    field: &str,
) -> Result<&'a [u8], anyhow::Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(anyhow::anyhow!(
            "{field} has nonzero length ({len}) but a null pointer"
        ));
    }
    // SAFETY: forwarded from the caller's safety contract; `ptr` is non-null
    // and `len` is nonzero per the checks above.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Clears `*error_out` to null, if `error_out` itself is non-null.
///
/// # Safety
///
/// If non-null, `error_out` must point to a valid, writable `*mut c_char`.
unsafe fn clear_error_out(error_out: *mut *mut c_char) {
    if error_out.is_null() {
        return;
    }
    // SAFETY: forwarded from the caller's safety contract.
    unsafe {
        *error_out = std::ptr::null_mut();
    }
}

/// Writes an owned, NUL-terminated copy of `message` into `*error_out`, if
/// `error_out` itself is non-null. The caller becomes responsible for
/// eventually passing the resulting pointer to [`rust_free_error_string`].
///
/// # Safety
///
/// If non-null, `error_out` must point to a valid, writable `*mut c_char`.
unsafe fn set_error_out(error_out: *mut *mut c_char, message: &str) {
    if error_out.is_null() {
        return;
    }
    // `message` is produced from `anyhow::Error::to_string()` or a panic
    // payload, neither of which we expect to contain interior NUL bytes, but
    // guard against it anyway rather than panicking or silently truncating.
    let sanitized = if message.contains('\0') {
        message.replace('\0', "\u{fffd}")
    } else {
        message.to_owned()
    };
    let c_message = CString::new(sanitized).unwrap_or_else(|_| {
        CString::new("error message could not be encoded as a C string")
            .expect("literal has no interior NUL")
    });
    // SAFETY: forwarded from the caller's safety contract.
    unsafe {
        *error_out = c_message.into_raw();
    }
}

/// Formats a `std::panic::catch_unwind` payload into a human-readable
/// message.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        format!("panic in FFI call: {s}")
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("panic in FFI call: {s}")
    } else {
        "panic in FFI call: unknown panic payload".to_owned()
    }
}

/// Loads and compiles a circuit, returning an opaque verifier handle.
///
/// This is the expensive, one-time part of setting up a verifier: a caller
/// (e.g. a long-lived Go process) should call this once per distinct
/// circuit (identified by its content, version, and attribute count) and
/// reuse the returned handle across many [`rust_verify_with_ppid`] calls,
/// rather than reloading the circuit on every verification.
///
/// Returns null on failure, with `*error_out` set to an owned error message
/// (see the module documentation on error reporting).
///
/// # Safety
///
/// * `circuit` must point to at least `circuit_len` valid, initialized
///   bytes (the decompressed circuit file contents).
/// * `error_out` may be null; if non-null, it must point to a valid,
///   writable `*mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_initialize_verifier(
    circuit: *const u8,
    circuit_len: usize,
    circuit_version: u8,
    num_attributes: u8,
    error_out: *mut *mut c_char,
) -> *mut MdocZkVerifier {
    // SAFETY: `error_out`'s validity is part of this function's own safety
    // contract, documented above.
    unsafe {
        clear_error_out(error_out);
    }

    let result = std::panic::catch_unwind(|| -> Result<MdocZkVerifier, anyhow::Error> {
        // SAFETY: `circuit`/`circuit_len`'s validity is part of this
        // function's own safety contract, documented above.
        let circuit = unsafe { bytes_or_empty(circuit, circuit_len, "circuit") }?;
        if circuit.is_empty() {
            return Err(anyhow::anyhow!("circuit must not be empty"));
        }
        let version = circuit_version_from_u8(circuit_version)?;
        MdocZkVerifier::new(circuit, version, usize::from(num_attributes))
    });

    match result {
        Ok(Ok(verifier)) => Box::into_raw(Box::new(verifier)),
        Ok(Err(e)) => {
            // SAFETY: as above.
            unsafe {
                set_error_out(error_out, &e.to_string());
            }
            std::ptr::null_mut()
        }
        Err(panic) => {
            // SAFETY: as above.
            unsafe {
                set_error_out(error_out, &panic_message(&*panic));
            }
            std::ptr::null_mut()
        }
    }
}

/// Frees a verifier handle previously returned by
/// [`rust_initialize_verifier`].
///
/// Passing null is a no-op. Passing the same non-null pointer more than
/// once, or using the pointer after freeing it, is undefined behavior (the
/// same rules as `free()` in C).
///
/// # Safety
///
/// `verifier` must either be null, or a pointer previously returned by
/// [`rust_initialize_verifier`] that has not already been freed, and there
/// must be no other in-flight calls (e.g. [`rust_verify_with_ppid`]) using
/// this handle concurrently with this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_free_verifier(verifier: *mut MdocZkVerifier) {
    if verifier.is_null() {
        return;
    }
    // SAFETY: forwarded from the caller's safety contract, documented above.
    let _ = unsafe { Box::from_raw(verifier) };
}

/// Frees an error string previously written by this module's functions into
/// an `error_out` out-parameter.
///
/// Passing null is a no-op.
///
/// # Safety
///
/// `ptr` must either be null, or a pointer previously written into an
/// `error_out` parameter by a function in this module, that has not already
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_free_error_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: forwarded from the caller's safety contract, documented above.
    let _ = unsafe { CString::from_raw(ptr) };
}

/// Verifies a V8 proof of possession with pairwise-pseudonym (PPID) support.
///
/// This does not weaken any check performed by
/// [`MdocZkVerifier::verify_with_ppid`] — it is a thin, allocation-and-parsing
/// wrapper: raw C inputs are validated and converted to their native Rust
/// representations, and the real verification logic (transcript replay,
/// Sumcheck, Ligero, MAC tag checks, PPID derivation) is delegated to that
/// function unchanged.
///
/// Returns `0` on success. On failure, returns a negative status code
/// (`-1`: input validation or verification error; `-2`: an internal panic
/// was caught) and, if `error_out` is non-null, writes an owned error
/// message there — see the module documentation on error reporting.
///
/// # Safety
///
/// * `verifier` must be a live pointer previously returned by
///   [`rust_initialize_verifier`] (not null, not freed, not concurrently
///   being freed by another thread during this call).
/// * `issuer_pk`/`session_transcript`/`proof`/`device_name_spaces_bytes`
///   must point to at least their respective `_len` valid bytes (or may be
///   null if their length is 0).
/// * `attributes` must point to at least `attributes_len` valid
///   [`CAttribute`] values (or may be null if `attributes_len` is 0); each
///   `CAttribute`'s own pointers must satisfy the safety requirements
///   documented on [`CAttribute`].
/// * `doc_type` and `time` must be non-null, valid NUL-terminated C strings.
/// * `verifier_context` must point to exactly `verifier_context_len` valid
///   bytes; verification requires this to be exactly 32.
/// * `error_out` may be null; if non-null, it must point to a valid,
///   writable `*mut c_char`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rust_verify_with_ppid(
    verifier: *const MdocZkVerifier,
    issuer_pk: *const u8,
    issuer_pk_len: usize,
    attributes: *const CAttribute,
    attributes_len: usize,
    doc_type: *const c_char,
    device_name_spaces_bytes: *const u8,
    device_name_spaces_bytes_len: usize,
    session_transcript: *const u8,
    session_transcript_len: usize,
    time: *const c_char,
    verifier_context: *const u8,
    verifier_context_len: usize,
    proof: *const u8,
    proof_len: usize,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: `error_out`'s validity is part of this function's own safety
    // contract, documented above.
    unsafe {
        clear_error_out(error_out);
    }

    // Raw pointers are `UnwindSafe`, so this closure needs no
    // `AssertUnwindSafe`: nothing mutable is observed across the unwind
    // boundary.
    let result = std::panic::catch_unwind(|| -> Result<(), anyhow::Error> {
        if verifier.is_null() {
            return Err(anyhow::anyhow!("verifier must not be null"));
        }
        // SAFETY: forwarded from this function's safety contract: `verifier`
        // is a live handle from `rust_initialize_verifier`.
        let verifier: &MdocZkVerifier = unsafe { &*verifier };

        // SAFETY: forwarded from this function's safety contract.
        let issuer_pk = unsafe { bytes_or_empty(issuer_pk, issuer_pk_len, "issuer_pk") }?;

        if attributes_len > 0 && attributes.is_null() {
            return Err(anyhow::anyhow!(
                "attributes has nonzero length ({attributes_len}) but a null pointer"
            ));
        }
        let c_attributes: &[CAttribute] = if attributes_len == 0 {
            &[]
        } else {
            // SAFETY: forwarded from this function's safety contract;
            // non-null per the check above.
            unsafe { slice::from_raw_parts(attributes, attributes_len) }
        };
        let mut owned_attributes = Vec::with_capacity(c_attributes.len());
        for (i, attr) in c_attributes.iter().enumerate() {
            // SAFETY: each `CAttribute`'s pointers are forwarded from this
            // function's safety contract.
            let identifier =
                unsafe { cstr_to_str(attr.identifier, &format!("attributes[{i}].identifier")) }?
                    .to_owned();
            // SAFETY: as above.
            let value_cbor = unsafe {
                bytes_or_empty(
                    attr.value_cbor,
                    attr.value_cbor_len,
                    &format!("attributes[{i}].value_cbor"),
                )
            }?
            .to_vec();
            owned_attributes.push(Attribute {
                identifier,
                value_cbor,
            });
        }

        // SAFETY: forwarded from this function's safety contract.
        let doc_type = unsafe { cstr_to_str(doc_type, "doc_type") }?;
        // SAFETY: as above.
        let device_name_spaces_bytes = unsafe {
            bytes_or_empty(
                device_name_spaces_bytes,
                device_name_spaces_bytes_len,
                "device_name_spaces_bytes",
            )
        }?;
        // SAFETY: as above.
        let session_transcript = unsafe {
            bytes_or_empty(
                session_transcript,
                session_transcript_len,
                "session_transcript",
            )
        }?;
        // SAFETY: as above.
        let time = unsafe { cstr_to_str(time, "time") }?;

        if verifier_context_len != 32 {
            return Err(anyhow::anyhow!(
                "verifier_context must be exactly 32 bytes, got {verifier_context_len}"
            ));
        }
        if verifier_context.is_null() {
            return Err(anyhow::anyhow!("verifier_context must not be null"));
        }
        // SAFETY: forwarded from this function's safety contract;
        // `verifier_context_len == 32` was just checked above, and
        // `verifier_context` is non-null per the check above.
        let verifier_context: &[u8; 32] = unsafe { slice::from_raw_parts(verifier_context, 32) }
            .try_into()
            .expect("slice has exactly 32 elements, checked above");

        // SAFETY: forwarded from this function's safety contract.
        let proof = unsafe { bytes_or_empty(proof, proof_len, "proof") }?;
        if proof.is_empty() {
            return Err(anyhow::anyhow!("proof must not be empty"));
        }

        verifier.verify_with_ppid(
            issuer_pk,
            &owned_attributes,
            doc_type,
            device_name_spaces_bytes,
            session_transcript,
            time,
            verifier_context,
            proof,
        )
    });

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            // SAFETY: `error_out`'s validity is part of this function's own
            // safety contract, documented above.
            unsafe {
                set_error_out(error_out, &e.to_string());
            }
            -1
        }
        Err(panic) => {
            // SAFETY: as above.
            unsafe {
                set_error_out(error_out, &panic_message(&*panic));
            }
            -2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use wasm_bindgen_test::wasm_bindgen_test;

    // EU PID mdoc with pseudonym_seed, and its matching V8/2-attribute
    // circuit + fixed transcript/time/verifier_context. These mirror the
    // fixtures in `mdoc_zk::prover_v8_test`'s `test_gary_mdoc_verify` (same
    // `GARY_MDOC_HEX`/transcript/time/verifier context), so a round trip
    // through this file's C ABI can be checked against a known-good,
    // already-verified-by-the-safe-API proof.
    use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver, prover_v8_test::GARY_MDOC_HEX};

    const VERIFIER_CONTEXT: [u8; 32] = [
        0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x40, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn load_v8_2attr_circuit() -> Vec<u8> {
        let compressed = include_bytes!(
            "../test-vectors/mdoc_zk/8_2_4307_2945_bb8e6a26d2700ddad968562d1c4aee83067772fee6f889748a0bc64f2c694ad5"
        );
        zstd::decode_all(compressed.as_slice()).unwrap()
    }

    /// Builds a known-good V8 PPID proof (via the safe Rust API, exactly as
    /// `test_gary_mdoc_verify` does) plus everything needed to verify it
    /// through the raw C ABI in this module.
    struct GoldenProof {
        circuit: Vec<u8>,
        issuer_pk: Vec<u8>,
        given_name_cbor: Vec<u8>,
        ppid_cbor: Vec<u8>,
        transcript: Vec<u8>,
        time: &'static str,
        doc_type: &'static str,
        proof: Vec<u8>,
    }

    fn build_golden_proof() -> GoldenProof {
        use sha2::{Digest, Sha256};

        let mdoc = hex::decode(GARY_MDOC_HEX.trim()).unwrap();
        let transcript = hex::decode(
            "83f6f6847142726f7773657248616e646f76657276315820f93ebac4ce4d9901b9aea472145ae5\
             421f8fbecbe5f0389683f59f08fcf90e455833a363636174016474797065016764657461696c73\
             a1676261736555726c75687474703a2f2f6c6f63616c686f73743a3830383058203c79914b7f81\
             a1c2558fc81619dd4a074d32143e6cf6895fe47da156d1c5b0ae",
        )
        .unwrap();
        let circuit = load_v8_2attr_circuit();

        let prover = MdocZkProver::new(&circuit, CircuitVersion::V8, 2).unwrap();
        let proof = prover
            .prove_with_ppid(
                &mdoc,
                "org.iso.18013.5.1",
                &["given_name", "pairwise_pseudonym"],
                &transcript,
                "2026-05-31T11:27:12Z",
                &VERIFIER_CONTEXT,
            )
            .unwrap();

        let seed = hex::decode("1122334455667788990011223344556677889900112233445566778899001122")
            .unwrap();
        let mut sha_input = seed;
        sha_input.extend_from_slice(&VERIFIER_CONTEXT);
        let ppid: [u8; 32] = Sha256::digest(&sha_input).into();
        let mut ppid_cbor = vec![0x58u8, 0x20];
        ppid_cbor.extend_from_slice(&ppid);

        let mut issuer_pk = vec![0x04u8];
        issuer_pk.extend_from_slice(
            &hex::decode("5cd6234f05b4348613b8bcfba6bb006c28310f6b106cb7ff446bcf2f222a63e4")
                .unwrap(),
        );
        issuer_pk.extend_from_slice(
            &hex::decode("66b83dc937b88e9d07f4b16a465ccaae1d6c56c3d31cef74f22774ef562fc9b4")
                .unwrap(),
        );

        GoldenProof {
            circuit,
            issuer_pk,
            given_name_cbor: b"\x64Gary".to_vec(),
            ppid_cbor,
            transcript,
            time: "2026-05-31T11:27:12Z",
            doc_type: "org.iso.18013.5.1.mDL",
            proof,
        }
    }

    /// Exercises the full lifecycle through the raw `extern "C"` functions
    /// exactly as a cgo caller would: initialize, verify (twice, to prove
    /// the handle is reusable and read-only), then free.
    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_round_trip_succeeds() {
        // SAFETY: test-only exercise of the raw C ABI with well-formed,
        // valid inputs constructed below (mirroring a well-behaved cgo
        // caller); every pointer handed to these functions points at data
        // owned by a local binding that outlives the call.
        unsafe {
            let golden = build_golden_proof();

            let mut error_out: *mut c_char = std::ptr::null_mut();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                8,
                2,
                &mut error_out,
            );
            assert!(!verifier.is_null(), "initialize_verifier failed");
            assert!(error_out.is_null());

            let doc_type = CString::new(golden.doc_type).unwrap();
            let time = CString::new(golden.time).unwrap();
            let given_name_id = CString::new("given_name").unwrap();
            let ppid_id = CString::new("pairwise_pseudonym").unwrap();
            let empty_device_name_spaces: &[u8] = b"\xa0";

            let attrs = [
                CAttribute {
                    identifier: given_name_id.as_ptr(),
                    value_cbor: golden.given_name_cbor.as_ptr(),
                    value_cbor_len: golden.given_name_cbor.len(),
                },
                CAttribute {
                    identifier: ppid_id.as_ptr(),
                    value_cbor: golden.ppid_cbor.as_ptr(),
                    value_cbor_len: golden.ppid_cbor.len(),
                },
            ];

            // Call twice through the same handle to demonstrate it is
            // reusable (not consumed/invalidated by a single verify call).
            for _ in 0..2 {
                let mut error_out: *mut c_char = std::ptr::null_mut();
                let status = rust_verify_with_ppid(
                    verifier,
                    golden.issuer_pk.as_ptr(),
                    golden.issuer_pk.len(),
                    attrs.as_ptr(),
                    attrs.len(),
                    doc_type.as_ptr(),
                    empty_device_name_spaces.as_ptr(),
                    empty_device_name_spaces.len(),
                    golden.transcript.as_ptr(),
                    golden.transcript.len(),
                    time.as_ptr(),
                    VERIFIER_CONTEXT.as_ptr(),
                    VERIFIER_CONTEXT.len(),
                    golden.proof.as_ptr(),
                    golden.proof.len(),
                    &mut error_out,
                );
                assert_eq!(status, 0, "verify_with_ppid failed");
                assert!(error_out.is_null());
            }

            rust_free_verifier(verifier);
        }
    }

    /// A tampered proof must be rejected, and the rejection must come with a
    /// real (non-empty) error message via the out-parameter - i.e. richer
    /// than a bare status code.
    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_rejects_tampered_proof_with_error_message() {
        // SAFETY: as in `c_abi_round_trip_succeeds`.
        unsafe {
            let golden = build_golden_proof();
            let mut tampered_proof = golden.proof.clone();
            let last = tampered_proof.len() - 1;
            tampered_proof[last] ^= 0xff;

            let mut error_out: *mut c_char = std::ptr::null_mut();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                8,
                2,
                &mut error_out,
            );
            assert!(!verifier.is_null());

            let doc_type = CString::new(golden.doc_type).unwrap();
            let time = CString::new(golden.time).unwrap();
            let given_name_id = CString::new("given_name").unwrap();
            let ppid_id = CString::new("pairwise_pseudonym").unwrap();
            let empty_device_name_spaces: &[u8] = b"\xa0";
            let attrs = [
                CAttribute {
                    identifier: given_name_id.as_ptr(),
                    value_cbor: golden.given_name_cbor.as_ptr(),
                    value_cbor_len: golden.given_name_cbor.len(),
                },
                CAttribute {
                    identifier: ppid_id.as_ptr(),
                    value_cbor: golden.ppid_cbor.as_ptr(),
                    value_cbor_len: golden.ppid_cbor.len(),
                },
            ];

            let mut error_out: *mut c_char = std::ptr::null_mut();
            let status = rust_verify_with_ppid(
                verifier,
                golden.issuer_pk.as_ptr(),
                golden.issuer_pk.len(),
                attrs.as_ptr(),
                attrs.len(),
                doc_type.as_ptr(),
                empty_device_name_spaces.as_ptr(),
                empty_device_name_spaces.len(),
                golden.transcript.as_ptr(),
                golden.transcript.len(),
                time.as_ptr(),
                VERIFIER_CONTEXT.as_ptr(),
                VERIFIER_CONTEXT.len(),
                tampered_proof.as_ptr(),
                tampered_proof.len(),
                &mut error_out,
            );
            assert_ne!(status, 0, "tampered proof must not verify");
            assert!(!error_out.is_null(), "expected an error message");
            let message = CStr::from_ptr(error_out).to_str().unwrap();
            assert!(!message.is_empty());
            rust_free_error_string(error_out);

            rust_free_verifier(verifier);
        }
    }

    /// A wrong attribute count must be rejected before ever touching the
    /// cryptographic verification - and must not panic or read out of
    /// bounds, since this is exactly the kind of variable-length input Go
    /// controls.
    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_rejects_wrong_attribute_count() {
        // SAFETY: as in `c_abi_round_trip_succeeds`.
        unsafe {
            let golden = build_golden_proof();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                8,
                2,
                std::ptr::null_mut(),
            );
            assert!(!verifier.is_null());

            let doc_type = CString::new(golden.doc_type).unwrap();
            let time = CString::new(golden.time).unwrap();
            let given_name_id = CString::new("given_name").unwrap();
            let empty_device_name_spaces: &[u8] = b"\xa0";
            // Only one attribute, but this circuit was initialized for 2.
            let attrs = [CAttribute {
                identifier: given_name_id.as_ptr(),
                value_cbor: golden.given_name_cbor.as_ptr(),
                value_cbor_len: golden.given_name_cbor.len(),
            }];

            let mut error_out: *mut c_char = std::ptr::null_mut();
            let status = rust_verify_with_ppid(
                verifier,
                golden.issuer_pk.as_ptr(),
                golden.issuer_pk.len(),
                attrs.as_ptr(),
                attrs.len(),
                doc_type.as_ptr(),
                empty_device_name_spaces.as_ptr(),
                empty_device_name_spaces.len(),
                golden.transcript.as_ptr(),
                golden.transcript.len(),
                time.as_ptr(),
                VERIFIER_CONTEXT.as_ptr(),
                VERIFIER_CONTEXT.len(),
                golden.proof.as_ptr(),
                golden.proof.len(),
                &mut error_out,
            );
            assert_ne!(status, 0);
            assert!(!error_out.is_null());
            rust_free_error_string(error_out);
            rust_free_verifier(verifier);
        }
    }

    /// Null pointers where a value is required must produce a clean error,
    /// not a segfault/UB - this is the main risk cgo callers introduce (Go
    /// zero values are nil pointers).
    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_rejects_null_required_pointers() {
        // SAFETY: as in `c_abi_round_trip_succeeds`; the null pointers
        // passed below are exactly the invalid inputs each call is
        // expected to reject with an error rather than dereference.
        unsafe {
            let mut error_out: *mut c_char = std::ptr::null_mut();
            let verifier = rust_initialize_verifier(std::ptr::null(), 0, 8, 2, &mut error_out);
            assert!(verifier.is_null());
            assert!(!error_out.is_null());
            let message = CStr::from_ptr(error_out).to_str().unwrap();
            assert!(message.contains("circuit"), "message was: {message}");
            rust_free_error_string(error_out);

            let golden = build_golden_proof();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                8,
                2,
                std::ptr::null_mut(),
            );
            assert!(!verifier.is_null());

            // Null `verifier` handle.
            let mut error_out: *mut c_char = std::ptr::null_mut();
            let status = rust_verify_with_ppid(
                std::ptr::null(),
                golden.issuer_pk.as_ptr(),
                golden.issuer_pk.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut error_out,
            );
            assert_ne!(status, 0);
            assert!(!error_out.is_null());
            rust_free_error_string(error_out);

            // Non-null verifier, but null doc_type/time C strings.
            let mut error_out: *mut c_char = std::ptr::null_mut();
            let status = rust_verify_with_ppid(
                verifier,
                golden.issuer_pk.as_ptr(),
                golden.issuer_pk.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                golden.transcript.as_ptr(),
                golden.transcript.len(),
                std::ptr::null(),
                VERIFIER_CONTEXT.as_ptr(),
                VERIFIER_CONTEXT.len(),
                golden.proof.as_ptr(),
                golden.proof.len(),
                &mut error_out,
            );
            assert_ne!(status, 0);
            assert!(!error_out.is_null());
            rust_free_error_string(error_out);

            rust_free_verifier(verifier);
        }
    }

    /// Rejects a `verifier_context` of the wrong length rather than reading
    /// past the caller's buffer.
    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_rejects_wrong_verifier_context_length() {
        // SAFETY: as in `c_abi_round_trip_succeeds`.
        unsafe {
            let golden = build_golden_proof();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                8,
                2,
                std::ptr::null_mut(),
            );
            assert!(!verifier.is_null());

            let doc_type = CString::new(golden.doc_type).unwrap();
            let time = CString::new(golden.time).unwrap();
            let given_name_id = CString::new("given_name").unwrap();
            let ppid_id = CString::new("pairwise_pseudonym").unwrap();
            let empty_device_name_spaces: &[u8] = b"\xa0";
            let attrs = [
                CAttribute {
                    identifier: given_name_id.as_ptr(),
                    value_cbor: golden.given_name_cbor.as_ptr(),
                    value_cbor_len: golden.given_name_cbor.len(),
                },
                CAttribute {
                    identifier: ppid_id.as_ptr(),
                    value_cbor: golden.ppid_cbor.as_ptr(),
                    value_cbor_len: golden.ppid_cbor.len(),
                },
            ];

            let short_context = &VERIFIER_CONTEXT[..16];
            let mut error_out: *mut c_char = std::ptr::null_mut();
            let status = rust_verify_with_ppid(
                verifier,
                golden.issuer_pk.as_ptr(),
                golden.issuer_pk.len(),
                attrs.as_ptr(),
                attrs.len(),
                doc_type.as_ptr(),
                empty_device_name_spaces.as_ptr(),
                empty_device_name_spaces.len(),
                golden.transcript.as_ptr(),
                golden.transcript.len(),
                time.as_ptr(),
                short_context.as_ptr(),
                short_context.len(),
                golden.proof.as_ptr(),
                golden.proof.len(),
                &mut error_out,
            );
            assert_ne!(status, 0);
            assert!(!error_out.is_null());
            let message = CStr::from_ptr(error_out).to_str().unwrap();
            assert!(message.contains("32"), "message was: {message}");
            rust_free_error_string(error_out);

            rust_free_verifier(verifier);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn c_abi_rejects_unsupported_circuit_version() {
        // SAFETY: as in `c_abi_round_trip_succeeds`.
        unsafe {
            let golden = build_golden_proof();
            let mut error_out: *mut c_char = std::ptr::null_mut();
            let verifier = rust_initialize_verifier(
                golden.circuit.as_ptr(),
                golden.circuit.len(),
                9, // only 6, 7, 8 are valid
                2,
                &mut error_out,
            );
            assert!(verifier.is_null());
            assert!(!error_out.is_null());
            rust_free_error_string(error_out);
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn free_null_handles_are_a_no_op() {
        // SAFETY: null is always a valid, documented no-op input to these
        // free functions.
        unsafe {
            rust_free_verifier(std::ptr::null_mut());
            rust_free_error_string(std::ptr::null_mut());
        }
    }

    /// Not part of the normal test run (`#[ignore]`): dumps the same
    /// known-good V8 PPID proof (and its supporting fixtures) used by the
    /// tests above to `target/go-cabi/testdata/`, so a real Go program
    /// linking against `target/go-cabi/libzk_cred_longfellow.so` via cgo
    /// can verify it end-to-end through the actual C ABI, from actual Go.
    /// Run explicitly via:
    ///
    ///   cargo test --release go_ffi::tests::dump_golden_fixture_for_go_smoke_test -- --ignored
    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "run explicitly to regenerate fixtures for the Go cgo smoke test"]
    fn dump_golden_fixture_for_go_smoke_test() {
        let golden = build_golden_proof();
        let out_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/go-cabi/testdata");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(out_dir.join("proof.bin"), &golden.proof).unwrap();
        std::fs::write(out_dir.join("issuer_pk.bin"), &golden.issuer_pk).unwrap();
        std::fs::write(out_dir.join("given_name_cbor.bin"), &golden.given_name_cbor).unwrap();
        std::fs::write(out_dir.join("ppid_cbor.bin"), &golden.ppid_cbor).unwrap();
        std::fs::write(out_dir.join("transcript.bin"), &golden.transcript).unwrap();
        std::fs::write(out_dir.join("verifier_context.bin"), VERIFIER_CONTEXT).unwrap();
        std::fs::write(out_dir.join("doc_type.txt"), golden.doc_type).unwrap();
        std::fs::write(out_dir.join("time.txt"), golden.time).unwrap();
        std::fs::write(out_dir.join("circuit.bin"), &golden.circuit).unwrap();
        eprintln!("wrote golden fixture to {}", out_dir.display());
    }
}
