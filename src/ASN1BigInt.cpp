//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1BigInt.h"

#include <algorithm>
#include <array>
#include <cstdio>

namespace {

// base 1e9 chunks keep the decimal conversion to 32 bit arithmetic.
constexpr std::uint32_t kChunk = 1'000'000'000u;
constexpr std::size_t kChunkDigits = 9;

}  // namespace

// ---------------------------------------------------------------------------------------------
// magnitude helpers
// ---------------------------------------------------------------------------------------------

void ASN1BigInt::trim() noexcept {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
    if (limbs_.empty()) negative_ = false;  // there is no negative zero
}

void ASN1BigInt::multiplyAdd(std::uint32_t multiplier, std::uint32_t addend) noexcept {
    std::uint64_t carry = addend;
    for (std::uint32_t &limb : limbs_) {
        const std::uint64_t product = static_cast<std::uint64_t>(limb) * multiplier + carry;
        limb = static_cast<std::uint32_t>(product);
        carry = product >> 32;
    }
    while (carry != 0) {
        limbs_.push_back(static_cast<std::uint32_t>(carry));
        carry >>= 32;
    }
    trim();
}

std::uint32_t ASN1BigInt::divide(std::uint32_t divisor) noexcept {
    std::uint64_t remainder = 0;
    for (std::size_t i = limbs_.size(); i-- > 0;) {
        const std::uint64_t current = (remainder << 32) | limbs_[i];
        limbs_[i] = static_cast<std::uint32_t>(current / divisor);
        remainder = current % divisor;
    }
    trim();
    return static_cast<std::uint32_t>(remainder);
}

void ASN1BigInt::setMagnitude(std::span<const std::uint8_t> bigEndian) noexcept {
    limbs_.clear();
    std::size_t start = 0;
    while (start < bigEndian.size() && bigEndian[start] == 0) ++start;
    const std::size_t bytes = bigEndian.size() - start;
    limbs_.resize((bytes + 3) / 4, 0);
    // big endian digits into little endian limbs
    for (std::size_t i = 0; i < bytes; ++i) {
        const std::size_t digit = bytes - 1 - i;  // position counted from the least significant
        limbs_[digit / 4] |= static_cast<std::uint32_t>(bigEndian[start + i]) << (8 * (digit % 4));
    }
    trim();
}

// ---------------------------------------------------------------------------------------------
// properties
// ---------------------------------------------------------------------------------------------

std::size_t ASN1BigInt::bitLength() const noexcept {
    if (limbs_.empty()) return 0;
    std::size_t bits = (limbs_.size() - 1) * 32;
    std::uint32_t top = limbs_.back();
    while (top != 0) {
        ++bits;
        top >>= 1;
    }
    return bits;
}

// True when the magnitude is exactly 2^(bits-1), that is a single bit in the leading position.
bool ASN1BigInt::isSingleBitAt(std::size_t bits) const noexcept {
    if (bits == 0) return false;
    for (std::size_t i = 0; i + 1 < limbs_.size(); ++i) {
        if (limbs_[i] != 0) return false;
    }
    return limbs_.back() == (std::uint32_t{1} << ((bits - 1) % 32));
}

std::size_t ASN1BigInt::octetCount() const noexcept {
    if (isZero()) return 1;  // zero is one zero octet
    const std::size_t bits = bitLength();

    // A negative value -m fits into n octets when m <= 2^(8n-1). A positive value of the same
    // magnitude needs one more octet whenever its top bit would land on the sign bit.
    if (isNegative() && bits % 8 == 0 && isSingleBitAt(bits)) return bits / 8;
    return (bits + 8) / 8;
}

int ASN1BigInt::compareMagnitude(const ASN1BigInt &rhs) const noexcept {
    if (limbs_.size() != rhs.limbs_.size()) return limbs_.size() < rhs.limbs_.size() ? -1 : 1;
    for (std::size_t i = limbs_.size(); i-- > 0;) {
        if (limbs_[i] == rhs.limbs_[i]) continue;
        return limbs_[i] < rhs.limbs_[i] ? -1 : 1;
    }
    return 0;
}

int ASN1BigInt::compare(const ASN1BigInt &rhs) const noexcept {
    if (isNegative() != rhs.isNegative()) return isNegative() ? -1 : 1;
    const int magnitudeOrder = compareMagnitude(rhs);
    return isNegative() ? -magnitudeOrder : magnitudeOrder;
}

// ---------------------------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------------------------

ASN1BigInt ASN1BigInt::fromDecimal(std::string_view digits) {
    if (digits.empty()) throw ASN1ValueError("empty decimal integer");
    if (digits.size() > kMaxDecimalDigits)
        throw ASN1ValueError("decimal integer of " + std::to_string(digits.size()) +
                             " digits exceeds the supported width of " +
                             std::to_string(kMaxDecimalDigits) + " digits");

    std::size_t pos = 0;
    bool negative = false;
    if (digits[pos] == '+' || digits[pos] == '-') {
        negative = digits[pos] == '-';
        ++pos;
    }
    if (pos >= digits.size()) throw ASN1ValueError("decimal integer has no digits");

    ASN1BigInt result;
    for (; pos < digits.size(); ++pos) {
        const char c = digits[pos];
        if (c < '0' || c > '9')
            throw ASN1ValueError("invalid character in decimal integer");
        result.multiplyAdd(10, static_cast<std::uint32_t>(c - '0'));
    }
    result.negative_ = negative;
    result.trim();
    if (result.limbs_.size() * 4 > kMaxOctets + 4)
        throw ASN1ValueError("decimal integer is wider than the supported " +
                             std::to_string(kMaxOctets) + " octets");
    return result;
}

ASN1BigInt ASN1BigInt::fromMagnitude(std::span<const std::uint8_t> magnitude, bool negative) {
    if (magnitude.size() > kMaxOctets + 4)
        throw ASN1ValueError("magnitude of " + std::to_string(magnitude.size()) +
                             " octets exceeds the supported width");
    ASN1BigInt result;
    result.setMagnitude(magnitude);
    result.negative_ = negative;
    result.trim();
    return result;
}

ASN1BigInt ASN1BigInt::fromOctets(std::span<const std::uint8_t> content) {
    if (content.empty())
        throw ASN1ValueError("INTEGER content needs at least one octet");
    if (content.size() > kMaxOctets)
        throw ASN1ValueError("INTEGER of " + std::to_string(content.size()) +
                             " octets exceeds the supported " + std::to_string(kMaxOctets) +
                             " octets");

    const bool negative = (content.front() & 0x80u) != 0;
    if (!negative) return fromMagnitude(content, false);

    // Two's complement of a negative number: invert and add one, then the sign is implicit.
    std::vector<std::uint8_t> inverted(content.size());
    std::uint32_t carry = 1;
    for (std::size_t i = content.size(); i-- > 0;) {
        const std::uint32_t sum = (static_cast<std::uint32_t>(~content[i]) & 0xFF) + carry;
        inverted[i] = static_cast<std::uint8_t>(sum);
        carry = sum >> 8;
    }
    ASN1BigInt result = fromMagnitude(inverted, true);
    if (result.isZero()) return result;  // -0 does not exist
    return result;
}

// ---------------------------------------------------------------------------------------------
// formatting
// ---------------------------------------------------------------------------------------------

std::string ASN1BigInt::toDecimal() const {
    if (isZero()) return "0";

    ASN1BigInt work = *this;
    work.negative_ = false;
    std::vector<std::uint32_t> chunks;
    while (!work.limbs_.empty()) chunks.push_back(work.divide(kChunk));

    std::string out;
    if (isNegative()) out += '-';
    out += std::to_string(chunks.back());
    char buffer[kChunkDigits + 1];
    for (std::size_t i = chunks.size() - 1; i-- > 0;) {
        std::snprintf(buffer, sizeof(buffer), "%09u", chunks[i]);
        out += buffer;
    }
    return out;
}

std::size_t ASN1BigInt::writeOctets(std::uint8_t *out) const {
    const std::size_t count = octetCount();
    const std::size_t magnitudeOctets = (bitLength() + 7) / 8;

    // The magnitude goes in right aligned and zero padded; a negative value is then the two's
    // complement negation of that field.
    std::fill(out, out + count, 0x00);
    for (std::size_t octet = 0; octet < magnitudeOctets; ++octet) {
        const std::size_t bits = 8 * (magnitudeOctets - 1 - octet);  // bit offset of this octet
        out[octet + (count - magnitudeOctets)] =
                static_cast<std::uint8_t>(limbs_[bits / 32] >> (8 * ((bits / 8) % 4)));
    }
    if (isNegative()) {
        std::uint32_t carry = 1;
        for (std::size_t i = count; i-- > 0;) {
            const std::uint32_t sum = (static_cast<std::uint32_t>(~out[i]) & 0xFF) + carry;
            out[i] = static_cast<std::uint8_t>(sum);
            carry = sum >> 8;
        }
    }
    return count;
}

std::vector<std::uint8_t> ASN1BigInt::toOctets() const {
    std::vector<std::uint8_t> out(octetCount());
    writeOctets(out.data());
    return out;
}

// ---------------------------------------------------------------------------------------------
// narrowing
// ---------------------------------------------------------------------------------------------

bool ASN1BigInt::fitsInInt64() const noexcept {
    if (isNegative()) {
        static const ASN1BigInt limit = ASN1BigInt::fromMagnitude(
                std::span<const std::uint8_t>(std::array<std::uint8_t, 8>{0x80, 0, 0, 0, 0, 0, 0, 0}),
                true);
        return !(*this < limit);
    }
    static const ASN1BigInt limit = ASN1BigInt::fromMagnitude(
            std::span<const std::uint8_t>(std::array<std::uint8_t, 8>{0x7F, 0xFF, 0xFF, 0xFF, 0xFF,
                                                                        0xFF, 0xFF, 0xFF}),
            false);
    return !(*this > limit);
}

bool ASN1BigInt::fitsInUint64() const noexcept {
    if (isNegative()) return false;  // zero is never negative, it was handled by the caller
    static const ASN1BigInt limit = ASN1BigInt::fromMagnitude(
            std::span<const std::uint8_t>(std::array<std::uint8_t, 8>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                                        0xFF, 0xFF, 0xFF}),
            false);
    return !(*this > limit);
}

std::int64_t ASN1BigInt::toInt64() const {
    if (!fitsInInt64()) throw ASN1ValueError("integer " + toDecimal() + " does not fit into 64 bits");
    std::uint64_t magnitude = 0;
    for (std::size_t i = std::min<std::size_t>(limbs_.size(), 2); i-- > 0;)
        magnitude = (magnitude << 32) | limbs_[i];
    const std::int64_t value = static_cast<std::int64_t>(magnitude);
    return isNegative() ? -value : value;
}

std::uint64_t ASN1BigInt::toUint64() const {
    if (!fitsInUint64()) throw ASN1ValueError("integer " + toDecimal() + " does not fit into 64 bits");
    std::uint64_t magnitude = 0;
    for (std::size_t i = std::min<std::size_t>(limbs_.size(), 2); i-- > 0;)
        magnitude = (magnitude << 32) | limbs_[i];
    return magnitude;
}

#if defined(DYNASN1_HAS_INT128)

ASN1BigInt ASN1BigInt::fromUnsigned128(ASN1UInt128 value) {
    std::array<std::uint8_t, 16> octets{};
    for (std::size_t i = 0; i < 16; ++i)
        octets[15 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    return fromMagnitude(octets, false);
}

ASN1BigInt ASN1BigInt::fromSigned128(ASN1Int128 value) {
    const bool negative = value < 0;
    ASN1UInt128 magnitude =
            negative ? static_cast<ASN1UInt128>(-(value + 1)) + 1 : static_cast<ASN1UInt128>(value);
    std::array<std::uint8_t, 16> octets{};
    for (std::size_t i = 0; i < 16; ++i)
        octets[15 - i] = static_cast<std::uint8_t>(magnitude >> (8 * i));
    return fromMagnitude(octets, negative);
}

bool ASN1BigInt::fitsInUnsigned128() const noexcept {
    if (isNegative()) return false;  // zero is never negative, it was handled by the caller
    static const std::array<std::uint8_t, 16> maxOctets{
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const ASN1BigInt limit = ASN1BigInt::fromOctets(maxOctets);
    return !(*this > limit);
}

bool ASN1BigInt::fitsInSigned128() const noexcept {
    if (isNegative()) {
        static const std::array<std::uint8_t, 16> minOctets{0x80, 0, 0, 0, 0, 0, 0, 0,
                                                            0,  0, 0, 0, 0, 0, 0, 0};
        static const ASN1BigInt limit = ASN1BigInt::fromOctets(minOctets);
        return !(*this < limit);
    }
    static const std::array<std::uint8_t, 16> maxOctets{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const ASN1BigInt limit = ASN1BigInt::fromOctets(maxOctets);
    return !(*this > limit);
}

ASN1UInt128 ASN1BigInt::toUnsigned128() const {
    if (!fitsInUnsigned128()) throw ASN1ValueError("integer does not fit into 128 unsigned bits");
    ASN1UInt128 magnitude = 0;
    for (std::size_t i = std::min<std::size_t>(limbs_.size(), 4); i-- > 0;)
        magnitude = (magnitude << 32) | limbs_[i];
    return magnitude;
}

ASN1Int128 ASN1BigInt::toSigned128() const {
    if (!fitsInSigned128()) throw ASN1ValueError("integer does not fit into 128 signed bits");
    ASN1UInt128 magnitude = 0;
    for (std::size_t i = std::min<std::size_t>(limbs_.size(), 4); i-- > 0;)
        magnitude = (magnitude << 32) | limbs_[i];
    const ASN1Int128 value = static_cast<ASN1Int128>(magnitude);
    return isNegative() ? -value : value;
}

#endif