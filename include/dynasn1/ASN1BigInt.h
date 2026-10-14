//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1BIGINT_H
#define DYNASN1_ASN1BIGINT_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dynasn1/ASN1Exception.h"

#if defined(__SIZEOF_INT128__)
#define DYNASN1_HAS_INT128 1
// A compiler extension rather than standard C++, so the pedantic diagnostic is silenced here and
// the rest of the library keeps building clean under -Wpedantic.
__extension__ typedef unsigned __int128 ASN1UInt128;
__extension__ typedef __int128 ASN1Int128;
#endif

// An INTEGER of any width, as X.690 8.3.2 defines it: a two's complement value in the content
// octets, written in the shortest possible form.
//
// The type carries what a codec needs and nothing more: parsing, the canonical encoding,
// comparison and conversion. Arithmetic is deliberately absent, it is not a number cruncher.
class ASN1BigInt {
public:
    // A guard against absurd input on the untrusted side. 512 content octets is 4096 bits,
    // about 1234 decimal digits.
    static constexpr std::size_t kMaxOctets = 512;
    static constexpr std::size_t kMaxDecimalDigits = 1300;

    ASN1BigInt() = default;

    // Accepts an optional sign, at least one digit, nothing else. "0" and "-0" are both zero.
    static ASN1BigInt fromDecimal(std::string_view digits);
    static ASN1BigInt fromOctets(std::span<const std::uint8_t> content);   // two's complement
    static ASN1BigInt fromMagnitude(std::span<const std::uint8_t> magnitude, bool negative);

    bool isZero() const noexcept { return limbs_.empty(); }
    bool isNegative() const noexcept { return negative_ && !isZero(); }
    std::size_t bitLength() const noexcept;
    std::size_t octetCount() const noexcept;  // minimal two's complement length

    // Signed comparison: -1 < 0 < 1.
    int compare(const ASN1BigInt &rhs) const noexcept;
    bool operator==(const ASN1BigInt &rhs) const noexcept { return compare(rhs) == 0; }
    bool operator!=(const ASN1BigInt &rhs) const noexcept { return compare(rhs) != 0; }
    bool operator<(const ASN1BigInt &rhs) const noexcept { return compare(rhs) < 0; }
    bool operator<=(const ASN1BigInt &rhs) const noexcept { return compare(rhs) <= 0; }
    bool operator>(const ASN1BigInt &rhs) const noexcept { return compare(rhs) > 0; }
    bool operator>=(const ASN1BigInt &rhs) const noexcept { return compare(rhs) >= 0; }

    std::string toDecimal() const;
    std::vector<std::uint8_t> toOctets() const;
    std::size_t writeOctets(std::uint8_t *out) const;  // writes exactly octetCount() octets

    bool fitsInInt64() const noexcept;
    bool fitsInUint64() const noexcept;
    std::int64_t toInt64() const;
    std::uint64_t toUint64() const;

#if defined(DYNASN1_HAS_INT128)
    static ASN1BigInt fromUnsigned128(ASN1UInt128 value);
    static ASN1BigInt fromSigned128(ASN1Int128 value);
    bool fitsInUnsigned128() const noexcept;
    bool fitsInSigned128() const noexcept;
    ASN1UInt128 toUnsigned128() const;
    ASN1Int128 toSigned128() const;
#endif

private:
    // Magnitude, least significant limb first, never with a trailing zero limb.
    std::vector<std::uint32_t> limbs_;
    bool negative_ = false;

    void trim() noexcept;
    void multiplyAdd(std::uint32_t multiplier, std::uint32_t addend) noexcept;   // limbs *= m, += a
    std::uint32_t divide(std::uint32_t divisor) noexcept;                      // limbs /= d, returns remainder
    void setMagnitude(std::span<const std::uint8_t> bigEndian) noexcept;
    int compareMagnitude(const ASN1BigInt &rhs) const noexcept;
    bool isSingleBitAt(std::size_t bits) const noexcept;
};

// A fixed size binary value: digests, signatures, public keys, identifiers that must be exactly
// N octets. It travels as an OCTET STRING, the type distinction stays in the C++ API so that a
// signature cannot be handed over where a plain blob is expected.
//
// The size is additionally enforced by the description, see ASN1::withExactSize().
template <std::size_t Size> struct ASN1FixedBytes {
    static_assert(Size > 0, "a fixed size value needs at least one octet");

    std::array<std::uint8_t, Size> data{};

    ASN1FixedBytes() = default;

    // Throws ASN1ValueError when the input has a different size.
    explicit ASN1FixedBytes(std::span<const std::uint8_t> bytes) {
        if (bytes.size() != Size)
            throw ASN1ValueError("value of " + std::to_string(bytes.size()) +
                                 " octets does not fit a fixed size field of " +
                                 std::to_string(Size) + " octets");
        std::copy(bytes.begin(), bytes.end(), data.begin());
    }

    std::span<const std::uint8_t> bytes() const noexcept {
        return std::span<const std::uint8_t>(data.data(), Size);
    }
    std::span<std::uint8_t> bytes() noexcept { return std::span<std::uint8_t>(data.data(), Size); }
    std::size_t size() const noexcept { return Size; }
    bool operator==(const ASN1FixedBytes &) const = default;
};

using ASN1Digest = ASN1FixedBytes<32>;      // SHA-256, 256 bit
using ASN1Signature = ASN1FixedBytes<64>;   // EdDSA style signature
using ASN1Key32 = ASN1FixedBytes<32>;       // a 256 bit public key

// Any other width is one typedef away, and the compiler then refuses every value of the wrong one:
//   using ASN1Curve25519PublicKey = ASN1FixedBytes<32>;
//   using ASN1Rsa2048Modulus      = ASN1FixedBytes<256>;

#endif //DYNASN1_ASN1BIGINT_H