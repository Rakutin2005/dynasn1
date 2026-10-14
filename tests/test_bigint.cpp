// Cross check of ASN1BigInt against an independent reference.
//
// The vector file is produced by tools/ref_bigint.py, which computes the minimal two's complement
// encoding with Python's arbitrary precision integers. Nothing here trusts the library to define
// its own expectations: encoding, decoding, declared length and minimality are all checked
// against values computed elsewhere.
//
// Regenerate with:  python3 tools/ref_bigint.py
// Run manually with: ./test_bigint [path/to/vectors.txt]
#include "dynasn1/ASN1BigInt.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

namespace {

int failures = 0;
int checks = 0;

void fail(const std::string &what, const std::string &detail) {
    if (failures < 10) std::printf("  FAIL %s: %s\n", what.c_str(), detail.c_str());
    ++failures;
}

std::string toHex(const std::vector<std::uint8_t> &octets) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(octets.size() * 2);
    for (const std::uint8_t byte : octets) {
        out += digits[byte >> 4];
        out += digits[byte & 0x0F];
    }
    return out;
}

void verifyOne(const std::string &decimal, const std::string &hex, std::size_t expectedOctets);

// Runs every check the reference can support for one value.
void verify(const std::string &decimal, const std::string &hex, std::size_t expectedOctets) {
    ++checks;
    try {
        verifyOne(decimal, hex, expectedOctets);
    } catch (const ASN1Exception &error) {
        // The vector file holds only values the library supports, so nothing here may throw.
        fail("unexpected exception", decimal + ": " + error.what());
    }
}

void verifyOne(const std::string &decimal, const std::string &hex, std::size_t expectedOctets) {
    const ASN1BigInt value = ASN1BigInt::fromDecimal(decimal);

    const std::vector<std::uint8_t> encoded = value.toOctets();
    if (toHex(encoded) != hex) fail("encoding", decimal + ": got " + toHex(encoded) + " want " + hex);
    if (encoded.size() != expectedOctets)
        fail("declared length", decimal + ": got " + std::to_string(encoded.size()) + " want " +
                                    std::to_string(expectedOctets));
    if (value.octetCount() != encoded.size())
        fail("octetCount disagrees with the written octets",
             decimal + ": " + std::to_string(value.octetCount()) + " vs " +
                     std::to_string(encoded.size()));

    // decode, and require the text to come back identical
    const ASN1BigInt decoded = ASN1BigInt::fromOctets(encoded);
    if (decoded.toDecimal() != decimal)
        fail("round trip", decimal + ": got " + decoded.toDecimal());
    if (decoded.toOctets() != encoded) fail("re-encoding differs", decimal);

    // The sign of the decimal text must agree with the value.
    const bool shouldBeNegative = !decimal.empty() && decimal[0] == '-';
    if (value.isNegative() != shouldBeNegative)
        fail("sign", decimal + ": reported " + (value.isNegative() ? "negative" : "non negative"));

    // Minimality, checked without the reference: dropping the final octet, or a redundant sign
    // octet, must change the value.
    if (encoded.size() > 1) {
        const std::vector<std::uint8_t> shorter(encoded.begin(), encoded.end() - 1);
        if (ASN1BigInt::fromOctets(shorter) == value) fail("not minimal", decimal + ": loses an octet");
        if (encoded[0] == 0x00 && (encoded[1] & 0x80) == 0) {
            std::vector<std::uint8_t> stripped(encoded.begin() + 1, encoded.end());
            if (ASN1BigInt::fromOctets(stripped) == value)
                fail("not minimal", decimal + ": loses a sign octet");
        }
        if (encoded[0] == 0xFF && (encoded[1] & 0x80) != 0) {
            std::vector<std::uint8_t> stripped(encoded.begin() + 1, encoded.end());
            if (ASN1BigInt::fromOctets(stripped) == value)
                fail("not minimal", decimal + ": loses a sign octet");
        }
    }
}

}  // namespace

int main(int argc, char **argv) {
    const std::string path = argc > 1 ? argv[1] : "tests/data/bigint_vectors.txt";
    std::ifstream input(path);
    if (!input) {
        std::printf("cannot read %s\n", path.c_str());
        std::printf("regenerate it with: python3 tools/ref_bigint.py\n");
        return 2;
    }

    std::string decimal, hex;
    long octets = 0;
    long long total = 0;
    while (input >> decimal >> hex >> octets) {
        ++total;
        verify(decimal, hex, static_cast<std::size_t>(octets));
    }

    // The parsing edge cases live in the library's own terms, not in the vector file.
    verify("0", "00", 1);
    if (!ASN1BigInt::fromDecimal("-0").isZero()) fail("negative zero", "'-0' is not zero");
    if (ASN1BigInt::fromDecimal("+42").toDecimal() != "42") fail("leading plus", "'+42' is not 42");

    const char *rejected[] = {"", "-", "12a", " 12", "12 ", "1.5", "0x10", "--1", "1-"};
    for (const char *text : rejected) {
        try {
            (void)ASN1BigInt::fromDecimal(text);
            fail("invalid input accepted", std::string("'") + text + "'");
        } catch (const ASN1ValueError &) {
        }
    }
    try {
        (void)ASN1BigInt::fromDecimal(std::string(ASN1BigInt::kMaxDecimalDigits + 1, '9'));
        fail("over long input accepted", "more digits than the supported width");
    } catch (const ASN1ValueError &) {
    }

    // The 512 octet ceiling is a guard on both sides, so a round trip can never disagree about it.
    const std::string tooWide = "1" + std::string(ASN1BigInt::kMaxOctets * 2, '0');
    try {
        const ASN1BigInt wide = ASN1BigInt::fromDecimal(tooWide);
        if (wide.octetCount() > ASN1BigInt::kMaxOctets) {
            try {
                (void)wide.toOctets();
                fail("over wide value encoded", tooWide.size() + " digits exceeds the ceiling");
            } catch (const ASN1ValueError &) {
            }
        }
    } catch (const ASN1ValueError &) {
    }
    {
        std::vector<std::uint8_t> over(ASN1BigInt::kMaxOctets + 1, 0x01);
        try {
            (void)ASN1BigInt::fromOctets(over);
            fail("over wide content accepted", std::to_string(over.size()) + " octets");
        } catch (const ASN1ValueError &) {
        }
    }

    if (total == 0) {
        std::printf("the vector file is empty\n");
        return 2;
    }

    std::printf("%lld vectors, %d checks, from %s: %s", total, checks, path.c_str(),
                failures ? "FAILED\n" : "all agree with the reference\n");
    return failures ? 1 : 0;
}