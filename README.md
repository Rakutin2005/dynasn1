# dynasn1

An ASN.1 DER encoder and decoder driven by a description that is itself DER.

The library does two things and nothing else:

1. **Build a description.** A fluent C++ builder produces a description that is serialised as
   ASN.1 DER against a fixed meta-schema, so it is canonical, hashable and storable.
2. **Encode and decode data according to that description**, strictly, as X.690 DER.

There is no ASN.1 text parser and no dependency on any data format. The library never sees JSON,
XML or anything else: its input is already typed values, and its output is octets.

## Why the description is DER

Because one logical record must have exactly one byte sequence. That is what lets a validator be
compiled from a description and run against bytes, and it is the reason DER was chosen over CBOR,
Protobuf or JSON, all of which have several encodings of the same value.

It also means the description is a storable, versionable artifact rather than something that has
to be shipped next to every message.

## Building

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `DYNASN1_BUILD_TESTS` | `ON` | build and register the test suite |
| `DYNASN1_BUILD_BENCHMARKS` | `ON` | build the benchmarks into `<build>/benchmarks` |
| `DYNASN1_INSTALL` | `ON` | generate the install and `find_package` rules |

The benchmarks `speed` and `compare` need `nlohmann/json`, and `compare` additionally needs zlib.
They are skipped when those are absent. **The library itself has no such dependency.**

## Using it

```cpp
#include <dynasn1/ASN1.h>
#include <dynasn1/ASN1Instance.h>

// Build a description.
ASN1 transfer = ASN1::sequence("Transfer");
transfer.field("id", ASN1::integer().withRange(0, 1'000'000));
transfer.field("amount", ASN1::integer());
transfer.field("issuedAt", ASN1::generalizedTime());
transfer.field("digest", ASN1::octetString().withExactSize(32));

// Encode a value.
ASN1Instance instance = transfer.getInstance();
instance.set("id", 4711);
instance.set("amount", ASN1BigInt::fromDecimal("123456789012345678901234567890"));
instance.set("issuedAt", std::chrono::system_clock::time_point(std::chrono::nanoseconds(1765432212123456789LL)));
instance.set("digest", ASN1Digest(digestBytes));
std::vector<std::uint8_t> der = instance.getDER();

// The description is a byte string. Store it, hash it, ship it to the instance that needs it.
const std::vector<std::uint8_t> &description = transfer.notation();
ASN1 restored = ASN1::fromNotation(description);

// Decode against a description.
ASN1Instance back = ASN1Instance::decode(restored, der);
std::int64_t id = back.get("id").asInteger();
```

Adding it to a CMake project:

```cmake
add_subdirectory(dynasn1)
target_link_libraries(your_target PRIVATE dynasn1::dynasn1)
```

or, after `cmake --install`:

```cmake
find_package(dynasn1 REQUIRED)
target_link_libraries(your_target PRIVATE dynasn1::dynasn1)
```

## What the types cover

`BOOLEAN`, `INTEGER` of any width, `NULL`, `OCTET STRING`, `BIT STRING`, the character strings
(`UTF8String`, `IA5String`, `PrintableString`, `NumericString`, `VisibleString`), `UTCTime`,
`GeneralizedTime`, `OBJECT IDENTIFIER`, `ENUMERATED`, `SEQUENCE`, `SET`, `SEQUENCE OF`,
`SET OF`, `CHOICE`, and named types with recursive references.

Constraints: `SIZE`, integer value range, named bits, named numbers. Members may be optional,
carry a default, and carry a non universal tag.

### Values

`ASN1Value` is a variant, not a map of strings. Each ASN.1 type has exactly one C++ carrier:

| ASN.1 | C++ |
|---|---|
| `BOOLEAN` | `bool` |
| `INTEGER`, `ENUMERATED` | `std::int64_t`, `std::uint64_t`, `ASN1BigInt`, or `__int128` |
| `NULL` | `std::nullptr_t` |
| `OCTET STRING` | `std::vector<std::uint8_t>`, `ASN1FixedBytes<N>` |
| `BIT STRING` | `ASN1BitString` |
| character strings | `std::string` |
| `UTCTime`, `GeneralizedTime` | `ASN1Value::Timestamp` |
| `OBJECT IDENTIFIER` | `ASN1Oid` |
| `SEQUENCE`, `SET` | `ASN1Value::Sequence` |
| `SEQUENCE OF`, `SET OF` | `ASN1Value::List` |
| `CHOICE` | `ASN1Value::Choice` |

### Arbitrary precision integers

`ASN1BigInt` is an `INTEGER` of any width, encoded as the shortest two's complement, per X.690
8.3.2. It carries what a codec needs: parsing from decimal or from content octets, the canonical
encoding, comparison, and narrowing to 64 or 128 bits. **There is no arithmetic.** If you need to
add two amounts, do that outside the library.

The ceiling is **512 content octets**, i.e. 4096 bits or about 1234 decimal digits. It is enforced
on both the encoding and the decoding side, so a round trip can never disagree about it. The
decimal parser refuses anything longer before doing any work, so an absurd input cannot turn into a
long loop.

`ASN1BigInt` is verified against vectors computed by Python's arbitrary precision integers:

```sh
python3 tools/ref_bigint.py          # regenerate tests/data/bigint_vectors.txt
python3 tools/ref_bigint.py --wide   # ~55k vectors, for a soak
```

### Timestamps

`ASN1Value::Timestamp` is `time_point<system_clock, nanoseconds>`, spelled out so the precision
does not depend on the platform clock. Values at any clock precision convert in.

`GeneralizedTime` carries a fraction of a second, written with the fewest digits that keep the
value and with no trailing zeros, as X.690 11.7.4 requires. `UTCTime` stays exactly 13 octets and
covers 1950..2049. A nanosecond timestamp therefore covers roughly 1677..2262; outside that an
encoding is refused rather than silently rounded.

### Fixed size binary values

`ASN1FixedBytes<N>` with `ASN1Digest` (32), `ASN1Signature` (64) and `ASN1Key32` (32). The width
is carried by the C++ type and enforced by the description, on the way in and on the way out. Any
other width is one typedef away.

```cpp
using ASN1Rsa2048Modulus = ASN1FixedBytes<256>;
```

## What the decoder guarantees

Strictness is not a preference here, it is what makes a record checkable. The decoder rejects:

- non minimal lengths, indefinite lengths and non minimal `INTEGER` encodings;
- non canonical `SET` ordering;
- times that are not the canonical `GeneralizedTime` or `UTCTime` form: a trailing zero in the
  fraction, a comma as the decimal mark, a time zone offset, a missing `Z`, an impossible date;
- any truncation, any trailing data, nesting deeper than the depth limit;
- a value that violates a `SIZE`, range, named bit or named number constraint.

Failures throw `ASN1DecodeError`, which carries the octet offset and the path to the offending
field. Schema problems throw `ASN1SchemaError`, value problems `ASN1ValueError`; all derive from
`ASN1Exception`.

## Limits worth knowing

- `INTEGER` content is capped at 512 octets, symmetrically on both sides.
- `GeneralizedTime` with nanoseconds spans about 1677..2262.
- Decoding depth is bounded, so hostile input cannot exhaust the stack.
- Constraints describe *shape*: `SIZE`, ranges, named bits and named numbers. There is no regular
  expression or content format constraint, because ASN.1 has none. If you need to know that a
  string is an email address, that belongs outside the description.
- The meta-schema is about 2.8 times larger than a hand packed description of the same thing. It
  carries field names, constraints and choice alternatives uniformly whether or not a particular
  contract needs them.

## Performance

A six field record: **649 ns to encode, 487 ns to decode**, 0.53x the bytes of the same record as
JSON. A custom alias tag costs **0 octets and no measurable time**, because it replaces the
universal tag rather than being added to it.

The one shape where JSON is smaller is a bare array of very small integers, about 4% at one digit,
which inverts at roughly four digits.

Run the benchmarks:

```sh
./build/benchmarks/speed     # throughput and allocations against a JSON parser
./build/benchmarks/size      # byte counts against JSON and XML
./build/benchmarks/domain    # wide amounts, sub second timestamps, alias tags
./build/benchmarks/compare   # thirteen payloads, with compression
```

## Layout

```
include/dynasn1/    public headers
src/                implementation
tests/              the suite; `demo` is the worked example
tests/data/         reference vectors, regenerate with tools/ref_bigint.py
benchmarks/         measurements, not tests
tools/              generators
```

## Thread safety

A description is immutable once published: `ASN1::getInstance()` hands out a snapshot, and the
first modification detaches it. Instances are not shared between threads; the DER cache on an
instance is not synchronised.