//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1CODEC_H
#define DYNASN1_ASN1CODEC_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dynasn1/ASN1Schema.h"
#include "dynasn1/ASN1Value.h"

namespace asn1detail {

// Guards against hostile input: every recursive step of a nested structure costs one level.
inline constexpr int kMaxDepth = 64;

// Field path of the value being decoded. Collected while descending, turned into a string only
// when something fails, so a successful decode never allocates one.
class PathStack;

// Minimal DER writer: identifier octets, minimal definite lengths, no nesting of its own.
class DerWriter {
public:
    explicit DerWriter(std::vector<std::uint8_t> &out) noexcept : out_(&out) {}

    void octet(std::uint8_t value);
    void bytes(std::span<const std::uint8_t> data);
    void identifier(ASN1TagClass cls, bool constructed, std::uint32_t tag);
    void length(std::size_t len);

    std::size_t size() const noexcept { return out_->size(); }

    static std::size_t identifierSize(ASN1TagClass cls, std::uint32_t tag) noexcept;
    static std::size_t lengthSize(std::size_t len) noexcept;

private:
    std::vector<std::uint8_t> *out_;
};

struct DerHeader {
    ASN1TagClass tagClass = ASN1TagClass::universal;
    bool constructed = false;
    std::uint32_t tag = 0;
    std::size_t headerSize = 0;  // identifier + length octets
    std::size_t contentOffset = 0;  // absolute offset of the first content octet
    std::span<const std::uint8_t> content{};
};

// Strict DER reader: definite minimal lengths only, no indefinite form, no trailing garbage.
class DerReader {
public:
    explicit DerReader(std::span<const std::uint8_t> data, std::size_t baseOffset = 0) noexcept
        : all_(data), base_(baseOffset) {}

    // Reads one identifier + length pair and validates it against `expected`.
    DerHeader header(ASN1TagClass expectedClass, std::uint32_t expectedTag, bool expectConstructed,
                     const PathStack &path);

    // Reads the identifier/length pair and returns it without checking anything.
    DerHeader anyHeader(const PathStack &path);

    // Reads the next header without consuming anything, to look ahead over absent OPTIONAL
    // members.
    DerHeader peek(const PathStack &path);

    bool empty() const noexcept { return pos_ == all_.size(); }
    std::size_t remaining() const noexcept { return all_.size() - pos_; }
    std::size_t offset() const noexcept { return base_ + pos_; }
    std::size_t absoluteOffset(std::size_t relative) const noexcept { return base_ + relative; }

    // Consumes `count` octets from the front.
    std::span<const std::uint8_t> take(std::size_t count, const PathStack &path);

    [[noreturn]] void fail(const std::string &message, const PathStack &path) const;

private:
    std::uint8_t octet(const PathStack &path);
    DerHeader read(const PathStack &path);

    std::span<const std::uint8_t> all_;
    std::size_t pos_ = 0;
    std::size_t base_ = 0;
};

// Value level codec, shared by the instance codec and by the meta schema codec.
std::size_t encodedSize(const Schema &schema, std::int32_t node, const ASN1Value &value, int depth = 0);
void encodeValue(DerWriter &writer, const Schema &schema, std::int32_t node, const ASN1Value &value,
                 int depth = 0);

// Encodes `value` into a standalone buffer (used for SET OF canonical ordering).
std::vector<std::uint8_t> encodeNode(const Schema &schema, std::int32_t node, const ASN1Value &value,
                                     int depth = 0);

// Decodes the content octets of a value whose header was already read and validated.
ASN1Value decodeValue(const Schema &schema, std::int32_t node, std::span<const std::uint8_t> content,
                      std::size_t offset = 0, const PathStack *path = nullptr, int depth = 0);

// Decodes a complete DER message for the root node of `schema`; rejects trailing octets.
ASN1Value decodeRoot(const Schema &schema, std::span<const std::uint8_t> der, std::string_view path = "");

// Same, but for an arbitrary node, e.g. a DEFAULT value stored inside a description.
ASN1Value decodeNode(const Schema &schema, std::int32_t node, std::span<const std::uint8_t> der,
                     std::string_view path = "");

// Character set / time / OID helpers, shared by the encoder and the decoder.
bool isValidUtf8(std::span<const std::uint8_t> data);

// Returns an empty string when the string is valid for `kind`, the reason otherwise, so that
// the caller can raise the error type that fits its context (value vs. decode).
std::string characterStringProblem(Kind kind, std::span<const std::uint8_t> data);

std::vector<std::uint8_t> formatTime(Kind kind, std::chrono::system_clock::time_point value);
std::chrono::system_clock::time_point parseTime(Kind kind, std::span<const std::uint8_t> data);

}  // namespace asn1detail

#endif //DYNASN1_ASN1CODEC_H