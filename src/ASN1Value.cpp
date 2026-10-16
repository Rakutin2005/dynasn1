//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1Value.h"

#include <limits>

const char *asn1TagClassName(ASN1TagClass cls) noexcept {
    switch (cls) {
        case ASN1TagClass::universal: return "universal";
        case ASN1TagClass::application: return "application";
        case ASN1TagClass::context: return "context-specific";
        case ASN1TagClass::privateClass: return "private";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------------------------
// ASN1Oid
// ---------------------------------------------------------------------------------------------

ASN1Oid ASN1Oid::parse(std::string_view dotted) {
    const std::string text(dotted);
    std::vector<std::uint64_t> arcs;
    std::size_t pos = 0;

    while (pos < dotted.size()) {
        const std::size_t dot = dotted.find('.', pos);
        const std::string_view token =
                dotted.substr(pos, dot == std::string_view::npos ? std::string_view::npos : dot - pos);

        if (token.empty())
            throw ASN1ValueError("empty arc in object identifier '" + text + "'");

        std::uint64_t value = 0;
        for (const char c : token) {
            if (c < '0' || c > '9')
                throw ASN1ValueError("invalid character in arc of object identifier '" + text + "'");
            const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
                throw ASN1ValueError("arc out of range in object identifier '" + text + "'");
            value = value * 10 + digit;
        }
        arcs.push_back(value);

        if (dot == std::string_view::npos) break;
        pos = dot + 1;
    }

    if (arcs.size() < 2)
        throw ASN1ValueError("object identifier '" + text + "' needs at least two arcs");
    if (arcs[0] > 2)
        throw ASN1ValueError("first arc of object identifier '" + text + "' must be 0, 1 or 2");

    return ASN1Oid(std::move(arcs));
}

std::string ASN1Oid::toString() const {
    std::string out;
    for (std::size_t i = 0; i < arcs_.size(); ++i) {
        if (i) out += '.';
        out += std::to_string(arcs_[i]);
    }
    return out;
}

bool operator==(const ASN1Oid &lhs, const ASN1Oid &rhs) noexcept {
    return lhs.arcs() == rhs.arcs();
}

// ---------------------------------------------------------------------------------------------
// ASN1BitString
// ---------------------------------------------------------------------------------------------

std::size_t ASN1BitString::unusedBits() const noexcept {
    return data.empty() ? 0 : (8 - (bitCount % 8)) % 8;
}

void ASN1BitString::setBit(std::size_t index, bool value) {
    const std::size_t byteIndex = index / 8;
    const std::uint8_t mask = static_cast<std::uint8_t>(0x80u >> (index % 8));
    if (byteIndex >= data.size()) data.resize(byteIndex + 1, 0);
    if (value) data[byteIndex] |= mask;
    else data[byteIndex] &= static_cast<std::uint8_t>(~mask);
    if (bitCount < index + 1) bitCount = index + 1;
}

bool ASN1BitString::bit(std::size_t index) const {
    const std::size_t byteIndex = index / 8;
    if (byteIndex >= data.size()) return false;
    return (data[byteIndex] & (0x80u >> (index % 8))) != 0;
}

void ASN1BitString::append(bool value) { setBit(bitCount, value); }

void ASN1BitString::truncate(std::size_t bits) {
    if (bits > data.size() * 8) throw ASN1ValueError("cannot truncate BIT STRING beyond its length");
    bitCount = bits;
    data.resize((bits + 7) / 8, 0);
    if (!data.empty() && bits % 8) {
        const std::uint8_t keep = static_cast<std::uint8_t>((0xFFu << (8 - bits % 8)) & 0xFFu);
        data.back() &= keep;
    }
}

// ---------------------------------------------------------------------------------------------
// ASN1Field / ASN1Choice
// ---------------------------------------------------------------------------------------------

bool operator==(const ASN1Field &lhs, const ASN1Field &rhs) {
    return lhs.name == rhs.name && lhs.value == rhs.value;
}

bool operator==(const ASN1ChoiceEntry &lhs, const ASN1ChoiceEntry &rhs) {
    return lhs.tag == rhs.tag && lhs.value == rhs.value;
}

// ---------------------------------------------------------------------------------------------
// ASN1Value
// ---------------------------------------------------------------------------------------------

ASN1Value::Type ASN1Value::type() const noexcept {
    switch (value_.index()) {
        case 0: return Type::boolean;
        case 1:
        case 2: return Type::integer;
        case 3: return Type::bigInteger;
        case 4: return Type::nullValue;
        case 5: return Type::octetString;
        case 6: return Type::bitString;
        case 7: return Type::string;
        case 8: return Type::time;
        case 9: return Type::objectIdentifier;
        case 10: return Type::sequence;
        case 11: return Type::list;
        case 12: return Type::choice;
        default: return Type::date;
    }
}

const char *ASN1Value::typeNameOf(ASN1Value::Type type) noexcept {
    switch (type) {
        case ASN1Value::Type::boolean: return "BOOLEAN";
        case ASN1Value::Type::integer:
        case ASN1Value::Type::bigInteger: return "INTEGER";
        case ASN1Value::Type::nullValue: return "NULL";
        case ASN1Value::Type::octetString: return "OCTET STRING";
        case ASN1Value::Type::bitString: return "BIT STRING";
        case ASN1Value::Type::string: return "STRING";
        case ASN1Value::Type::time: return "TIME";
        case ASN1Value::Type::objectIdentifier: return "OBJECT IDENTIFIER";
        case ASN1Value::Type::sequence: return "SEQUENCE";
        case ASN1Value::Type::list: return "SEQUENCE OF";
        case ASN1Value::Type::choice: return "CHOICE";
        case ASN1Value::Type::date: return "DATE";
    }
    return "UNKNOWN";
}

std::int64_t ASN1Value::asInteger() const {
    if (const auto *v = std::get_if<std::int64_t>(&value_)) return *v;
    if (const auto *v = std::get_if<std::uint64_t>(&value_)) {
        if (*v <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return static_cast<std::int64_t>(*v);
        }
        throw ASN1ValueError("INTEGER " + std::to_string(*v) +
                             " does not fit into a signed 64 bit integer");
    }
    if (const auto *v = std::get_if<ASN1BigInt>(&value_)) return v->toInt64();
    throw ASN1ValueError(std::string("value holds ") + typeName() + ", not INTEGER");
}

std::uint64_t ASN1Value::asUnsigned() const {
    if (const auto *v = std::get_if<std::uint64_t>(&value_)) return *v;
    if (const auto *v = std::get_if<std::int64_t>(&value_)) {
        if (*v < 0) throw ASN1ValueError("INTEGER " + std::to_string(*v) + " is negative");
        return static_cast<std::uint64_t>(*v);
    }
    if (const auto *v = std::get_if<ASN1BigInt>(&value_)) return v->toUint64();
    throw ASN1ValueError(std::string("value holds ") + typeName() + ", not INTEGER");
}

std::string ASN1Value::choiceTag() const {
    const Choice &choice = asChoice();
    if (choice.empty()) throw ASN1ValueError("CHOICE value has no alternative");
    return choice.front().tag;
}

const ASN1Value &ASN1Value::choiceValue() const {
    const Choice &choice = asChoice();
    if (choice.empty()) throw ASN1ValueError("CHOICE value has no alternative");
    return choice.front().value;
}

bool operator==(const ASN1Value &lhs, const ASN1Value &rhs) {
    if (lhs.index() != rhs.index()) return false;
    return std::visit(
            [](const auto &a, const auto &b) -> bool {
                using A = std::remove_cvref_t<decltype(a)>;
                using B = std::remove_cvref_t<decltype(b)>;
                if constexpr (std::is_same_v<A, B>) return a == b;
                else return false;
            },
            lhs.raw(), rhs.raw());
}