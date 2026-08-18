// Command go-cabi-smoketest is a minimal, real cgo program that links
// against zk-cred-longfellow's plain C-ABI build (see `make go-cabi` and
// `src/go_ffi.rs`) and calls it end-to-end, exactly the way a Go verifier
// service (e.g. SIROS's `vc` repo) would: load a circuit once, verify a
// known-good V8 pairwise-pseudonym (PPID) proof, and confirm a tampered
// proof is rejected with a real error message.
//
// This exercises the actual C ABI boundary from actual Go/cgo (not just
// Rust-side `#[test]`s calling the `extern "C"` functions directly), and
// is the practical answer to whether a Go process really can drive this
// crate's verifier without UniFFI.
//
// Usage:
//
//  1. Build the library + header:
//     make go-cabi
//
//  2. Generate the known-good fixture (a real proof from the crate's own,
//     already-tested prover):
//     cargo test --release go_ffi::tests::dump_golden_fixture_for_go_smoke_test -- --ignored
//
//  3. Run this program (it needs the shared library on the loader path):
//     cd go-cabi-smoketest
//     LD_LIBRARY_PATH=../target/go-cabi go run .
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../include
#cgo LDFLAGS: -L${SRCDIR}/../target/go-cabi -lzk_cred_longfellow
#include <stdlib.h>
#include "zk_cred_longfellow_go.h"
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", path, err)
		os.Exit(1)
	}
	return data
}

// bytesPtr returns a pointer to the first byte of b and its length, or
// (nil, 0) for an empty slice - matching how rust_verify_with_ppid treats a
// zero length as an empty buffer regardless of the pointer.
//
// Only safe to use for pointers passed directly as top-level cgo call
// arguments (e.g. `circuit`, `proof`): cgo's pointer-passing rules allow a
// direct Go-memory pointer argument as long as the pointed-to memory itself
// contains no further Go pointers, which holds for a plain []byte.
func bytesPtr(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// cBytesCopy copies b into newly C-allocated memory and returns a pointer
// into that copy plus its length, or (nil, 0) for an empty slice. The
// returned pointer must be freed by the caller (C.free) once no longer
// needed.
//
// Unlike bytesPtr, this is required wherever the resulting pointer will be
// stored as a *field* of a struct (here, CAttribute.value_cbor) that is
// itself passed to C by pointer: cgo forbids passing a Go pointer to memory
// that contains other Go pointers, and the CAttribute array's backing
// memory would contain a Go pointer if value_cbor pointed directly into a
// Go byte slice.
func cBytesCopy(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(C.CBytes(b)), C.size_t(len(b))
}

func main() {
	testdataDir := "../target/go-cabi/testdata"
	if len(os.Args) > 1 {
		testdataDir = os.Args[1]
	}

	circuit := mustRead(filepath.Join(testdataDir, "circuit.bin"))
	proof := mustRead(filepath.Join(testdataDir, "proof.bin"))
	issuerPK := mustRead(filepath.Join(testdataDir, "issuer_pk.bin"))
	givenNameCBOR := mustRead(filepath.Join(testdataDir, "given_name_cbor.bin"))
	ppidCBOR := mustRead(filepath.Join(testdataDir, "ppid_cbor.bin"))
	transcript := mustRead(filepath.Join(testdataDir, "transcript.bin"))
	verifierContext := mustRead(filepath.Join(testdataDir, "verifier_context.bin"))
	docType := string(mustRead(filepath.Join(testdataDir, "doc_type.txt")))
	timeStr := string(mustRead(filepath.Join(testdataDir, "time.txt")))

	// 1. Load the circuit exactly once, as a long-lived Go process would.
	var errOut *C.char
	circuitPtr, circuitLen := bytesPtr(circuit)
	verifier := C.rust_initialize_verifier(circuitPtr, circuitLen, 8, 2, &errOut)
	if verifier == nil {
		msg := C.GoString(errOut)
		C.rust_free_error_string(errOut)
		fmt.Fprintf(os.Stderr, "FAIL: rust_initialize_verifier: %s\n", msg)
		os.Exit(1)
	}
	defer C.rust_free_verifier(verifier)
	fmt.Println("OK: rust_initialize_verifier loaded the V8/2-attribute circuit")

	cDocType := C.CString(docType)
	defer C.free(unsafe.Pointer(cDocType))
	cTime := C.CString(timeStr)
	defer C.free(unsafe.Pointer(cTime))
	cGivenNameID := C.CString("given_name")
	defer C.free(unsafe.Pointer(cGivenNameID))
	cPpidID := C.CString("pairwise_pseudonym")
	defer C.free(unsafe.Pointer(cPpidID))

	givenNamePtr, givenNameLen := cBytesCopy(givenNameCBOR)
	defer C.free(unsafe.Pointer(givenNamePtr))
	ppidPtr, ppidLen := cBytesCopy(ppidCBOR)
	defer C.free(unsafe.Pointer(ppidPtr))

	// Build the variable-length attribute array Go controls directly - this
	// is exactly the CAttribute array this whole C ABI generalization exists
	// to support (replacing the old hardcoded given_name+pairwise_pseudonym
	// pair).
	attrs := []C.CAttribute{
		{identifier: cGivenNameID, value_cbor: givenNamePtr, value_cbor_len: givenNameLen},
		{identifier: cPpidID, value_cbor: ppidPtr, value_cbor_len: ppidLen},
	}

	emptyDeviceNameSpaces := []byte{0xa0} // CBOR empty map
	issuerPtr, issuerLen := bytesPtr(issuerPK)
	dnsPtr, dnsLen := bytesPtr(emptyDeviceNameSpaces)
	transcriptPtr, transcriptLen := bytesPtr(transcript)
	vcPtr, vcLen := bytesPtr(verifierContext)
	proofPtr, proofLen := bytesPtr(proof)

	// 2. Verify the known-good proof.
	status := C.rust_verify_with_ppid(
		verifier,
		issuerPtr, issuerLen,
		&attrs[0], C.size_t(len(attrs)),
		cDocType,
		dnsPtr, dnsLen,
		transcriptPtr, transcriptLen,
		cTime,
		vcPtr, vcLen,
		proofPtr, proofLen,
		&errOut,
	)
	if status != 0 {
		msg := "(no message)"
		if errOut != nil {
			msg = C.GoString(errOut)
			C.rust_free_error_string(errOut)
		}
		fmt.Fprintf(os.Stderr, "FAIL: rust_verify_with_ppid: status=%d message=%s\n", status, msg)
		os.Exit(1)
	}
	fmt.Println("OK: rust_verify_with_ppid verified a real V8 PPID proof via cgo")

	// 3. Confirm a tampered proof is rejected, with a real, non-empty error
	// message - not just a bare status code.
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)-1] ^= 0xff
	tamperedPtr, tamperedLen := bytesPtr(tampered)
	var errOut2 *C.char
	status2 := C.rust_verify_with_ppid(
		verifier,
		issuerPtr, issuerLen,
		&attrs[0], C.size_t(len(attrs)),
		cDocType,
		dnsPtr, dnsLen,
		transcriptPtr, transcriptLen,
		cTime,
		vcPtr, vcLen,
		tamperedPtr, tamperedLen,
		&errOut2,
	)
	if status2 == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: tampered proof unexpectedly verified")
		os.Exit(1)
	}
	if errOut2 == nil {
		fmt.Fprintln(os.Stderr, "FAIL: tampered proof was rejected but no error message was set")
		os.Exit(1)
	}
	msg2 := C.GoString(errOut2)
	C.rust_free_error_string(errOut2)
	fmt.Printf("OK: tampered proof rejected (status=%d): %s\n", status2, msg2)

	fmt.Println("ALL OK: real Go/cgo call into zk-cred-longfellow's C ABI succeeded end-to-end")
}
