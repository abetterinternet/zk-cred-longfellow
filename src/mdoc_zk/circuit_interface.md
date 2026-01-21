This document collects notes on the interface of the Longfellow mdoc\_zk
circuits, identified as “longfellow-libzk-v1” internally. This targets version 6
of the “ZK specification”. All information is taken from the [C++
implementation](https://github.com/google/longfellow-zk), which implicitly
defines this interface.

# Assumptions

* Ciphersuite
  * Only the ES256 COSE ciphersuite is supported, for both the issuer’s
    signature and the device authentication signature.
    * Only the P-256 curve is supported, not brainpoolP256r1.
  * The only supported `digestAlgorithm` is SHA-256, not SHA-384 or SHA-512.
* Length of attribute values
  * The SHA-256 invocations for digests are limited to two blocks, for a total
    of 128 bytes. The hash input is the `IssuerSignedItemBytes` type.
  * The length of an `IssuerSignedItem`, and thus `IssuerSignedItemBytes`, will
    depend on the length of the random nonce, the length of the identifier, and
    the length of the value. (plus other constant overheads)
  * ISO 18013-5 requires that the “random” value for each `IssuerSignedItem` be
    at least 16 bytes long.
* Circuits have only been compiled for presentations that disclose one, two,
  three, or four attributes.
* The C++ implementation currently requires that all disclosed attributes be in
  the same namespace. However, the namespace is not part of the circuit’s public
  inputs, and the circuit doesn’t enforce any checks on attribute namespaces.
  The circuit only verifies the execution of the attribute hash, and checks for
  the presence of the attribute hash in the MSO, without fully parsing the MSO’s
  CBOR structure.
* The credential length is limited by the maximum number of SHA-256 blocks
  (modulo some subtractions for Sig\_structure tags added to the message). The
  relevant constants are set to a limit of 35 SHA-256 blocks, for a maximum MSO
  length of 2213 bytes.
* The circuit does not parse the MSO’s CBOR structure, but rather performs byte
  string comparisons, checking that CBOR fragments occur at the claimed
  positions of various fields. The soundness of this approach depends on both
  how issuers form mdoc MSOs, and the length of the byte strings that the
  circuit checks for. We are assuming that MSOs will not contain matching byte
  strings embedded inside attacker-controlled fields, especially bytes like 0x09
  and 0x0A. The byte strings are long enough that the probability of them
  appearing through random chance inside a hash digest or signature are
  negligible.
* All shared witness values across circuits must be nonzero with high
  probability. The MAC used in the circuit is a\*x, not a\*x+b as suggested in
  the paper. This MAC is only hiding when the input x is nonzero. This
  assumption should be fine for the mdoc\_zk circuit, as the MAC messages are
  either the SHA-256 hash of the credential or the device binding key’s public
  key coordinates.
* The signature verification circuit does not have perfect completeness. This
  means that, for certain inputs, standard ECDSA verification may pass while
  this circuit may reject. The paper does not go into detail about what cases
  would be incorrectly rejected. Perhaps the difference is that the standard
  verification procedure only checks the x-coordinate of R, meaning that a
  signer could flip their selection of s, resulting in the y-coordinate of R
  changing sign.
* The signature circuit checks that the hash of the credential is less than the
  scalar field modulus, while standard verification allows any hash value. This
  contributes 2^\-32 or 2.3\*10^\-10 to completeness error.
* The signature circuit also checks that the x- and y-coordinates of the device
  public key are less than the scalar field modulus. Each check contributes
  2^\-130 or 7.7\*10^\-40 to completeness error.
* The `validFrom` and `validUntil` fields must follow RFC 3339 encoding, and
  their lengths must be exactly 20 characters.
* The `deviceKeyInfo` object in the mdoc must contain the required `deviceKey`
  attribute first. There are further limitations on the COSE encoding of the
  device’s public key.

# Circuit Inputs

The circuit interface is reflected in two different parts of the C++ code base,
both circuit compilation and prover code. Constructing the circuit associates
semantic meaning to the circuit’s input wires, based on the calculations and
assertions that depend on those wires. Likewise, the prover’s various
`fill_witness()` functions and methods preprocess inputs, and assemble the list
of inputs to the circuits. This too assigns semantic meaning to each input wire,
depending on which input or preprocessed value was assigned to it. Naturally,
the two parts of the codebase need to agree on the meaning of each wire for
proofs to validate successfully.

During circuit compilation, input wires are allocated in order in imperative
code through `QuadCircuit` method calls. The `input_wire()` method sequentially
allocates the input wire with the next index, and returns the index. The
`private_input()` call demarcates the boundary between public inputs and private
inputs (witness values). The `QuadCircuit` constructor itself allocates the
input wire with index zero, so that the constant value of one can be assigned to
it during evaluation. (This is necessary to allow emulating addition gates and
constant addition gates with the quad gate) The `input_wire()` method gets
wrapped in higher-level constructs inside the `Logic` class. For example,
`Logic::input()` both declares a new input wire and adds an assertion that it is
either zero or one, and `Logic::vinput()` creates multiple new input wires, and
packs them into an array, representing a bit vector value.

When filling the witness, various methods call `DenseFiller::push_back()` to
append field elements to vectors of circuit inputs. Separate `DenseFiller`
instances are maintained for the signature and hash circuit inputs. Method calls
for both fillers are interleaved for convenience. Note that the distinction
between public and private inputs is not explicit in this part of the codebase.
All inputs are added to the same vector for each circuit, and circuit metadata
(previously produced by the circuit compiler) determines how many of them are
public or private.

Note that both during circuit compilation and witness construction, the input
wire numbers are implicitly determined by imperative code sequentially
allocating wires. Thus, the order of execution matters a lot when defining this
interface. As some parts of the circuit and witness change based on the number
of disclosed attributes, the wire numbers assigned to specific values will also
depend on the number of disclosed attributes, if they are allocated after a for
loop that runs a variable number of times. There are parts of the codebase that
still have support for version numbers prior to 6; such conditionals could also
have an impact on wire number assignment or input preprocessing, and we only
need to identify the interface for the latest version.

The `BitPlucker` class is used in both circuits to perform a kind of time-space
tradeoff inside the circuit. When preparing a witness that will be passed to a
bit plucker component, the prover selects multiple bits from a byte string
input, maps those bits to one field element, and assigns it to an input wire.
Within the circuit, the bit plucker subcircuit then computes multiple values
that are each either 0 or 1, unpacking the multiple bits that were encoded into
a single input field element. This allows reducing the total number of input
wires, while adding more gates and possibly increasing the depth of the circuit.
Since the Ligero commitment size scales with the square root of the Ligero
witness size (which is composed of the circuit witness and logarithmic-size
Sumcheck transcript padding) and the Sumcheck proof and transcript scale
linearly with the circuit depth and logarithmically with the size of of each
circuit layer, this can be a worthwhile tradeoff. The optimal tradeoff depends
on the size and structure of the rest of the circuit.
Note that this tradeoff is only worthwhile for private circuit inputs, and not
public circuit inputs.
In practice, the encoding
step maps each chunk of N bits to one of 2^N possible field elements, and the
circuit component evaluates multiple interpolating polynomials to map the packed
field elements to unpacked field elements representing the original bits. The
circuit component also asserts that the unpacked bit values are either zero or
one. The evaluation points that are used are a bit unusual, following the
formula `inject(2 * bits) - inject(2^N - 1)`; the comments indicate this was
chosen to be compatible with a now-removed Lagrange polynomial basis used
elsewhere.

## Signature Circuit Inputs, P-256 Base Field

### Public Inputs (Statement)

#### Implicit 1

Field elements: 1

The first input is an implicit 1 value. This is used internally to represent
gates other than wire-wire multiplications as quad gates.

#### Issuer Public Key

Field elements: 2

The two coordinates of the issuer’s public key are provided as inputs, occupying
one wire each. The x coordinate of the curve point is first, followed by the y
coordinate.

#### Hash of Session Transcript

Field elements: 1

The hash of the message that the device-bound key signs is provided as a single
field element input. While this value, as used in ECDSA, lives in the curve’s
scalar field, this input is instead computed by mapping the hash to an integer,
and then mapping it into the base field.

#### MAC Tags

Field elements: 3 \* 2 \* 128 \= 768

The rest of the public inputs are related to the information-theoretic MAC
linking common witness values across circuits. Note that the MAC function is
defined over GF(2^128), so the verification of the MAC in this circuit relies on
implementing foreign-field arithmetic. Accordingly, the following values are
bit-decomposed and provided as groups of 128 input wires, each with value 0 or
1\. MAC tags for three P-256 base field elements are provided, each consisting
of two decomposed GF(2^128) field elements. The MACs cover the hash used in the
credential signature, and the two coordinates of the device public key. Since
the P-256 base field is twice as large as GF(2^128), each shared witness value
is interpreted as a 32-byte string, split in two, and then interpreted as two
GF(2^128) field elements. Separate MACs are computed on each GF(2^128) field
element.

#### MAC Verifier Key Share

Field elements: 128

Then, the verifier’s share of the MAC key is provided as 128 wires, decomposing
another GF(2^128) element. Note that the same verifier MAC key share is used in
all MACs, while the prover’s share of the MAC key is different for each
GF(2^128) element that is authenticated.

### Private Inputs (Witness)

#### Hash of Credential

Field elements: 1

The hash of the credential (or rather, the Sig\_structure object wrapping the
MSO) is provided on one input wire. As with the other ECDSA signature hash
value, this value lives in the scalar field for the purposes of signature
verification, but this circuit input is in the base field. The hash is mapped
to an integer, and then mapped into the base field.

#### Device Public Key

Field elements: 2

The two coordinates (x and y) of the device’s public key are provided as inputs,
occupying one wire each.

#### ECDSA Signature Witness, Credential

Field elements: 5 \+ 8 \+ 256 \+ 255 \* 3 \= 1034

The ECDSA signature verification circuit relies on many intermediate values
being provided in the witness, in order to reduce the circuit depth of the
verification circuit. The first set of signature witness values are for
verification of the issuer’s signature over the credential, using the issuer's
public key.

##### Signature Components and Inverses

Field elements: 5

Several values derived from the signature are added as single witness inputs.
Some inverses of values in the P-256 base field are included as well, for the
purpose of confirming that inputs are nonzero. (r \* r\-1 can be computed with a
single gate, it is zero if r is zero, and it is 1 if the witness is correctly
constructed) Note that these inverses are not computed over the scalar field, as
they are just for input validation, not the standard ECDSA signature
verification routine.

* r, or rx, the first component of the signature.
* ry, the y-coordinate of the point R computed during the standard verification
  routine.
* rx\-1, the multiplicative inverse of rx above, over the P-256 base field.
* The multiplicative inverse of negative s, from the signature. The negation is
  performed in the P-256 scalar field, then the result is reinterpreted as a
  base field element, and the multiplicative inverse is performed in the P-256
  base field.
* Qx\-1, the multiplicative inverse of the x-coordinate of the public key, over
  the P-256 base field.

##### Precomputed Curve Point Sums

Field elements: 8

A table of eight precomputed curve points is used during the multi-scalar
multiplication verification. These values represent the sums of none, some, or
all of G, the curve generator, Q, the public key point, or R, which is computed
during standard signature verification.
Note that these sums are computed in the elliptic curve group.
When the circuit verifies each step of
the multi-scalar multiplication loop, it looks up one of these eight table
values, depending on the bits of the three scalars, and adds it to the
accumulator after doubling it.

Two of these table entries are fixed, O and G. Two more are already provided
elsewhere as public or private circuit inputs, Q and R. The remaining four table
entries, which are each sums of two or three elliptic curve points, are provided
here in the next eight input wires. For each point, the x-coordinate and
y-coordinate are successive inputs.

* G \+ Q
* G \+ R
* Q \+ R
* G \+ Q \+ R

##### Multi-scalar Multiplication Intermediate Values

Field elements: 256 \+ 255 \* 3 \= 1021

Next are the witnesses for the multi-scalar multiplication used to verify the
signature. This is the last step of Algorithm 4 from
[the Longfellow paper](https://eprint.iacr.org/2024/2010.pdf#subsection.4.1),
computing G * e + Q * r - R * s. Here, e is the hash of the message, and r and s
are the two components of the signature.
The next circuit inputs alternate between table indices, determined by the bits
of e, r, and \-s, and three projective coordinates of the intermediate elliptic
curve points computed by the loop. Note that the negation \-s is computed in the
scalar field. The table index only occupies one input wire, while the projective
coordinates occupy three wires. The relevant loop runs 256 times, starting from
the high bits of the scalars and counting down, but the last loop iteration does
not produce a triplet of input wires for the final result’s projective
coordinates. This point must be the identity, and it is checked in some other
manner, without requiring additional witness inputs.

The table index inputs have the following values:

* \-7: O
* \-5: G
* \-3: Q
* \-1: G \+ Q
* 1: R
* 3: G \+ R
* 5: Q \+ R
* 7: G \+ Q \+ R

#### ECDSA Signature Witness, Device Binding

Field elements: 5 \+ 8 \+ 256 \+ 255 \* 3 \= 1034

All of the above ECDSA signature verification witnesses are repeated again, this
time for the device binding signature and the device's public key.

#### MAC Witnesses

Field elements: 3 \* (128 \+ 128) \= 768

Next, prover MAC keys and messages are provided in inputs. The MACs cover the
hash used in the credential signature, and the two coordinates of the device
public key. Unlike with the MAC tags and verifier key shares provided in the
public inputs, which were decomposed into one bit per input wire, the prover MAC
keys and messages are packed into fewer wires using the `BitPlucker` class, with
two bits per input. The inputs are assigned in the following order.

* MAC for hash used in credential signature
  * Prover key share for first half, packed into 64 wires
  * Prover key share for second half, packed into 64 wires
  * Bit decomposition of message, packed into 128 wires
* Device public key x-coordinate
  * Prover key share for first half, packed into 64 wires
  * Prover key share for second half, packed into 64 wires
  * Bit decomposition of message, packed into 128 wires
* Device public key y-coordinate
  * Prover key share for first half, packed into 64 wires
  * Prover key share for second half, packed into 64 wires
  * Bit decomposition of message, packed into 128 wires

Note that the values for which we are ensuring consistency get encoded twice in
the signature circuit’s witnesses, once as a single field element at the
beginning of the witness wires, and once in a packed bit decomposed form here.
The bit decomposition is necessary in order to compute the MAC function via
foreign field arithmetic. It is trivial to reconstruct the original field
element from the bit decomposition, and then assert that the other witness input
matches.

## Hash Circuit Inputs, GF(2^128)

### Public Inputs (Statement)

#### Implicit 1

Field elements: 1

The first input is an implicit 1 value. This is used internally to represent
gates other than wire-wire multiplications as quad gates.

#### Attributes

Field elements: attributes \* (96 \* 8 \+ 8) \= attributes \* 776

The attributes disclosed in the credential presentation are the first public
inputs. The number of inputs will depend on the number of attributes supported
by the particular circuit. All input wires associated with one particular
attribute appear consecutively.

The `elementIdentifier` and `elementValue` CBOR fields appear consecutively in
the `IssuerSignedItem` object, in the preimage of attribute hashes. The first
section of the public inputs relating to attributes records 96 bytes covering
one and a half key-value pairs in that object, padded with zero bytes. Included
are the CBOR length prefix of the `elementIdentifier` value, the
`elementIdentifier` value itself, the length prefix of the `elementValue` field
name, the `elementValue` field name, and the encoded form of the `elementValue`
value, including necessary CBOR type and length prefixes. These 96 bytes are
encoded into one input wire per bit, for a total of 768 input wires. Following
that, the length of the CBOR data before zero padding is encoded in eight input
wires, with one bit assigned to each.

#### Time

Field elements: 20 \* 8 \= 160

The current time is represented in RFC 3339 format, with four digit years, UTC
time, and no time zone offset. This format takes 20 bytes. The time is encoded
in this form, and then its bits are assigned to one input wire per bit.

#### MAC Tags

Field elements: 3 \* 2 \= 6

Six input wires are assigned to the six MAC tags used for consistency checking.
As described above, two tags cover each P-256 base field element. The messages
covered by the MAC are for the hash used in the issuer’s signature and the x-
and y-coordinate of the device public key.

#### MAC Verifier Key Share

Field elements: 1

The last public input is a single wire for the verifier’s share of the MAC key.

### Private Inputs (Witness)

#### Hash of Credential

Field elements: 256

The hash of the credential, as used in the issuer’s signature, has its bits
assigned to 256 input wires.

#### Device Public Key

Field elements: 2 \* 256 \= 512

The coordinates of the device public key are bit decomposed and assigned to 256
input wires each, first the x-coordinate, then the y-coordinate.

#### Number of SHA-256 Blocks, Credential

Field elements: 8

The number of blocks in the SHA-256 calculation for the issuer’s signature over
the credential is stored in bit decomposed form in eight input wires. This is
the length of the credential, plus Sig\_structure overhead, plus at least 9
bytes for the SHA-256 message padding, divided by the block size of 64 bytes.
The circuit will use this number to determine which intermediate hash value it
compares to the expected final hash output.

#### Padded SHA-256 Input, Credential

Field elements: (35 \* 64 \- 18) \* 8 \= 17776

The hash input used in the credential signature, with the SHA-256 padding
appended, is included in the input wires next. Blocks after the final block are
filled with zero bytes. The entire byte buffer is encoded as one bit per input
wire. A total of 35 blocks are supported, however 18 bytes from the
Sig\_structure prefix are known constants, and excluded from input wires.

#### Intermediate SHA-256 Witness Values

Field elements: 35 \* (48 \* 32 \+ 64 \* 2 \+ 8 \* 32) / 4 \= 35 \* 1472 \=
51520

For each of the 35 SHA-256 blocks, multiple intermediate values are provided.
Each array of multiple 32-bit values is stored in input wires using
`BitPlucker`, with 4 bits per wire. (thus 8 input wires per 32-bit word) Witness
values are grouped first by block number, then three arrays of 32-bit integers
per block are written in each group.

##### Message Schedule

Field elements per SHA-256 block: 48 \* 32 / 4 \= 384

The SHA-256 message schedule starts with a message block, and the remainder is
defined through a recurrence relation. The full message schedule is made up of
64 32-bit words. The first 16 32-bit words are already present in the circuit
inputs, through the earlier wires for the padded input. The remaining 48 32-bit
words of the message schedule are provided on input wires here (packed with 4
bits per wire) so that the message schedule expansion can be verified in
parallel with other verifications, to minimize the circuit depth.

##### State Values, E and A

Field elements per SHA-256 block: 64 \* 2 \* 32 / 4 \= 1024

Each block of input is processed over 64 rounds. In each round, the eight 32-bit
state variables, a, b, c, d, e, f, g, and h, are updated. Six of the updates
just permute values between state variables, while two of the updates add in a
complicated function of other state values. To efficiently verify SHA-256
execution in low depth, it is only necessary to provide these e and a values for
each round. All other state values are readily accessible from existing wire
values derived from the input schedule or state values in prior rounds.
Therefore, the next input wires alternate between providing the e and a state
values for each of the 64 rounds. As described above, these values are bit
decomposed and then packed, 4 bits to a wire.

##### Intermediate Hash Value

Field elements per SHA-256 block: 8 \* 32 / 4 \= 64

After the hash state goes through 64 rounds, the state values are added to the
intermediate hash value from the last round (or the initial hash value,
depending on the round) to produce a new intermediate hash value. The
intermediate hash value consists of eight 32-bit words. These are provided as
witnesses on the next input wires, packed with 4 bits to a wire.

#### CBOR Offsets

Field elements: 4 \* 12 \= 48

The following input wires describe offsets into the mdoc MSO byte string. Each
offset is represented as a 12-bit integer, with one bit assigned to each of
twelve input wires.

##### validFrom

Field elements: 12

This offset points to the start of the `validFrom` key-value pair inside the
credential, nested inside the `validityInfo` object. The offset should point to
the CBOR prefix in front of the field name.

##### validUntil

Field elements: 12

The next offset is to the `validUntil` key-value pair, inside the `validityInfo`
object.

##### deviceKeyInfo

Field elements: 12

The next offset is to the `deviceKeyInfo` key-value pair at the top level.

##### valueDigests

Field elements: 12

The next offset is to the `valueDigests` key-value pair at the top level.

#### Attribute Witnesses

Field elements: attributes * (2 \* 64 \* 8 \+ 2 \* 1472 \+ 12 \+ 12 \+ 12 \+ 12
\+ 12) \= attributes * 4028

Multiple values are provided for each of the attributes disclosed in the
credential presentation. These wires are grouped first by the attribute, and
then appear as follows.

##### Attribute Hash Preimage

Field elements per attribute: 2 \* 64 \* 8 \= 1024

The complete `IssuerSignedItemBytes` input, plus SHA-256 padding, is provided as
a witness. This is two SHA-256 blocks long, and each bit is assigned to an input
wire. The circuit assumes that the `IssuerSignedItemBytes` always requires two
SHA-256 blocks to hash.

##### Intermediate SHA-256 Witness Values

Field elements per attribute: 2 \* 1472 \= 2944

As with the credential hash earlier, additional input wires provide witness
values for the expanded message schedule, per-round state values, and
intermediate hash values. This hash invocation supports two blocks of input, so
the sequence of these witness values repeats twice, following the same formats
as before.

##### CBOR Offset of Digest

Field elements per attribute: 12

Next, a 12-bit offset into the MSO is encoded into twelve input wires. This
should point to the type prefix of the byte string inside `valueDigests` for
this attribute.

##### CBOR Offset in Preimage

Field elements per attribute: 12

Next, a 12-bit offset is encoded, pointing to the offset of the
`elementIdentifier` and `elementValue` inside the attribute hash preimage. This
needs to point to the CBOR prefix before the value of the `elementIdentifier`
attribute. This is the same place that the substring included in the public
inputs above begins. The offset is encoded with one bit per input wire.

##### Unused Offset and Lengths

Field elements per attribute: 12 \+ 12 \+ 12 \= 24

Three more 12-bit fields are encoded, a length, an offset, and a length, but
they are unused. This is likely an artifact of prior circuit interfaces, which
provided the `elementIdentifier` and `elementValue` values separately, with an
offset and length for each, and did not include them in one byte string spanning
multiple CBOR items.

#### MAC Prover Key Shares

Field elements: 3 \* 2 \= 6

The above witness inputs were all in the subfield, which allows for more
efficient encoding of the Ligero proof when operating on all-subfield rows.
These next inputs are not constrained to the subfield.

Six MAC prover key shares are provided next, with one value in each of six input
wires. As before, two MAC prover key shares are used to authenticate two halves
of the shared 256-bit witness values. The first two key shares are for the hash
used in the issuer’s signature, the next two key shares are used for the device
public key x-coordinate, and the last two key shares are used for the device
public key y-coordinate.
