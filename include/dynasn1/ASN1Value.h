//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1VALUE_H
#define DYNASN1_ASN1VALUE_H

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "dynasn1/ASN1BigInt.h"
#include "dynasn1/ASN1Exception.h"

// Tag class of an identifier octet (X.680 8.1). The last class cannot be called `private`, that
// is a keyword, so it carries a suffix.
enum class ASN1TagClass : std::uint8_t {
    universal = 0,
    application = 1,
    context = 2,  // context specific
    privateClass = 3
};

const char *asn1TagClassName(ASN1TagClass cls) noexcept;

// OBJECT IDENTIFIER. Arcs are stored decoded; the textual form is only produced on demand.
class ASN1Oid {
public:
    // Throws ASN1ValueError when the dotted form is malformed (X.660): at least two arcs, first
    // arc <= 2, decimal digits only, no sign.
    static ASN1Oid parse(std::string_view dotted);

    ASN1Oid() = default;
    explicit ASN1Oid(std::vector<std::uint64_t> arcs) : arcs_(std::move(arcs)) {}
    explicit ASN1Oid(std::string_view dotted) : arcs_(parse(dotted).arcs_) {}

    const std::vector<std::uint64_t> &arcs() const noexcept { return arcs_; }
    std::string toString() const;
    bool empty() const noexcept { return arcs_.empty(); }
    bool valid() const noexcept { return !arcs_.empty(); }

private:
    std::vector<std::uint64_t> arcs_;
};

bool operator==(const ASN1Oid &lhs, const ASN1Oid &rhs) noexcept;

// BIT STRING payload: whole bytes plus the number of significant bits inside the last byte.
// Unused trailing bits are always zero, as required by DER.
struct ASN1BitString {
    std::vector<std::uint8_t> data{};
    std::size_t bitCount = 0;

    void append(bool value);
    void setBit(std::size_t index, bool value);
    bool bit(std::size_t index) const;

    // Keeps the first `bits` bits and clears the rest.
    void truncate(std::size_t bits);

    // Number of unused bits in the last byte (0..7).
    std::size_t unusedBits() const noexcept;
};

// ASN1Field and ASN1ChoiceEntry come after ASN1Value, because a data member may not have an
// incomplete type. ASN1Value reaches them through std::vector, which is allowed to be
// instantiated with an incomplete element type until it is first used.
class ASN1Value;
struct ASN1Field;
struct ASN1ChoiceEntry;

// Human readable name of the alternative T of ASN1Value::Storage, used in error messages.
template <class T> const char *asn1ValueAlternativeName() noexcept { return "requested type"; }

// A single ASN.1 value. The alternative held by the variant decides which ASN.1 types the value
// may be used with; the description decides what it is actually encoded as.
//
//   BOOLEAN              -> bool
//   INTEGER, ENUMERATED  -> std::int64_t / std::uint64_t (the latter for magnitudes > INT64_MAX),
//                           or ASN1BigInt / __int128 for anything wider
//   NULL                 -> std::nullptr_t
//   OCTET STRING         -> std::vector<std::uint8_t>, ASN1FixedBytes<N> for fixed size material
//   BIT STRING           -> ASN1BitString
//   character strings    -> std::string
//   UTCTime, GenTime     -> std::chrono::system_clock::time_point
//   OBJECT IDENTIFIER    -> ASN1Oid
//   SEQUENCE, SET        -> Sequence  (std::vector<ASN1Field>, in schema order)
//   SEQUENCE OF, SET OF  -> List      (std::vector<ASN1Value>)
//   CHOICE               -> Choice    (one entry holding the label and the value)
class ASN1Value {
public:
    using Sequence = std::vector<ASN1Field>;
    using List = std::vector<ASN1Value>;
    using Choice = std::vector<ASN1ChoiceEntry>;

    // Timestamps carry nanosecond precision. Spelling the epoch based type out makes that
    // explicit and keeps it the same on every platform, where system_clock::duration is not
    // necessarily nanoseconds.
    using Timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;

    enum class Type {
        boolean,
        integer,
        bigInteger,
        nullValue,
        octetString,
        bitString,
        string,
        time,
        objectIdentifier,
        sequence,
        list,
        choice
    };

    using Storage = std::variant<bool, std::int64_t, std::uint64_t, ASN1BigInt, std::nullptr_t,
                                 std::vector<std::uint8_t>, ASN1BitString, std::string, Timestamp,
                                 ASN1Oid, Sequence, List, Choice>;

    ASN1Value() noexcept : value_(nullptr) {}
    ASN1Value(std::nullptr_t) noexcept : value_(nullptr) {}
    ASN1Value(bool v) noexcept : value_(v) {}

    // Every integral type except bool maps to INTEGER; signed ones stay signed.
    template <class T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
    ASN1Value(T v) noexcept
        : value_(std::is_signed_v<T> ? Storage(static_cast<std::int64_t>(v))
                                     : Storage(static_cast<std::uint64_t>(v))) {}

    // Wider than 64 bits values are carried by ASN1BigInt.
    ASN1Value(const ASN1BigInt &v) : value_(v) {}
    ASN1Value(ASN1BigInt &&v) : value_(std::move(v)) {}

#if defined(DYNASN1_HAS_INT128)
    ASN1Value(ASN1UInt128 v) : value_(ASN1BigInt::fromUnsigned128(v)) {}
    ASN1Value(ASN1Int128 v) : value_(ASN1BigInt::fromSigned128(v)) {}
#endif

    // Digests, signatures and keys keep their identity on the way in, and still travel as an
    // OCTET STRING.
    template <std::size_t Size> ASN1Value(const ASN1FixedBytes<Size> &v) : value_(std::vector<std::uint8_t>(v.data.begin(), v.data.end())) {}

    ASN1Value(const std::string &v) : value_(v) {}
    ASN1Value(std::string_view v) : value_(std::string(v)) {}
    ASN1Value(const char *v) : value_(std::string(v ? v : "")) {}

    // Catches every other string like argument (literals, string_view, char pointers) without
    // competing with the std::string constructor above.
    template <class S, std::enable_if_t<std::is_convertible_v<const S &, std::string_view>
                                             && !std::is_same_v<std::remove_cvref_t<S>, std::string>,
                                         int> = 0>
    ASN1Value(const S &v) : value_(std::string(std::string_view(v))) {}

    ASN1Value(std::vector<std::uint8_t> v) : value_(std::move(v)) {}
    ASN1Value(ASN1BitString v) : value_(std::move(v)) {}
    ASN1Value(ASN1Oid v) : value_(std::move(v)) {}
    // Whatever precision the caller's clock has converts into the nanosecond one the codec uses.
    ASN1Value(std::chrono::system_clock::time_point v)
        : value_(Timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(v.time_since_epoch()))) {}
    ASN1Value(Sequence v) : value_(std::move(v)) {}
    ASN1Value(List v) : value_(std::move(v)) {}
    ASN1Value(Choice v) : value_(std::move(v)) {}

    Type type() const noexcept;
    static const char *typeNameOf(Type type) noexcept;
    const char *typeName() const noexcept { return typeNameOf(type()); }
    std::size_t index() const noexcept { return value_.index(); }
    bool isNull() const noexcept { return std::holds_alternative<std::nullptr_t>(value_); }

    const Storage &raw() const noexcept { return value_; }
    Storage &raw() noexcept { return value_; }

    template <class T> const T *getIf() const noexcept { return std::get_if<T>(&value_); }
    template <class T> T *getIf() noexcept { return std::get_if<T>(&value_); }

    template <class T> bool is() const noexcept { return std::holds_alternative<T>(value_); }
    template <class T> bool is() noexcept { return std::holds_alternative<T>(value_); }

    // Throws ASN1ValueError naming both the actual and the expected type.
    template <class T> const T &as() const {
        if (const T *p = std::get_if<T>(&value_)) return *p;
        throw ASN1ValueError(std::string("value holds ") + typeName() + ", not " +
                             asn1ValueAlternativeName<T>());
    }

    bool asBoolean() const { return as<bool>(); }
    std::int64_t asInteger() const;
    std::uint64_t asUnsigned() const;
    const ASN1BigInt &asBigInt() const { return as<ASN1BigInt>(); }
    const std::vector<std::uint8_t> &asOctets() const { return as<std::vector<std::uint8_t>>(); }
    const ASN1BitString &asBits() const { return as<ASN1BitString>(); }
    const std::string &asString() const { return as<std::string>(); }
    Timestamp asTime() const { return as<Timestamp>(); }
    const ASN1Oid &asOid() const { return as<ASN1Oid>(); }
    const Sequence &asSequence() const { return as<Sequence>(); }
    const List &asList() const { return as<List>(); }
    const Choice &asChoice() const { return as<Choice>(); }

    // Convenience for CHOICE, which always holds exactly one labelled alternative.
    std::string choiceTag() const;
    const ASN1Value &choiceValue() const;

private:
    Storage value_;
};

// One component of a SEQUENCE / SET.
struct ASN1Field {
    std::string name;
    ASN1Value value;
};

// One alternative of a CHOICE, carrying the alternative label.
struct ASN1ChoiceEntry {
    std::string tag;
    ASN1Value value;
};

// A CHOICE value, written as {{"label", value}}.
using ASN1Choice = ASN1Value::Choice;

bool operator==(const ASN1Field &lhs, const ASN1Field &rhs);
bool operator==(const ASN1ChoiceEntry &lhs, const ASN1ChoiceEntry &rhs);
bool operator==(const ASN1Value &lhs, const ASN1Value &rhs);

template <> inline const char *asn1ValueAlternativeName<bool>() noexcept { return "BOOLEAN"; }
template <> inline const char *asn1ValueAlternativeName<std::int64_t>() noexcept { return "INTEGER"; }
template <> inline const char *asn1ValueAlternativeName<std::uint64_t>() noexcept {
    return "INTEGER";
}
template <> inline const char *asn1ValueAlternativeName<ASN1BigInt>() noexcept {
    return "INTEGER";
}
template <> inline const char *asn1ValueAlternativeName<std::nullptr_t>() noexcept { return "NULL"; }
template <> inline const char *asn1ValueAlternativeName<std::vector<std::uint8_t>>() noexcept {
    return "OCTET STRING";
}
template <> inline const char *asn1ValueAlternativeName<ASN1BitString>() noexcept {
    return "BIT STRING";
}
template <> inline const char *asn1ValueAlternativeName<std::string>() noexcept {
    return "a character string";
}
template <>
inline const char *asn1ValueAlternativeName<std::chrono::system_clock::time_point>() noexcept {
    return "a time value";
}
template <> inline const char *asn1ValueAlternativeName<ASN1Oid>() noexcept {
    return "OBJECT IDENTIFIER";
}
template <> inline const char *asn1ValueAlternativeName<ASN1Value::Sequence>() noexcept {
    return "SEQUENCE / SET";
}
template <> inline const char *asn1ValueAlternativeName<ASN1Value::List>() noexcept {
    return "SEQUENCE OF / SET OF";
}
template <> inline const char *asn1ValueAlternativeName<ASN1Value::Choice>() noexcept {
    return "CHOICE";
}

#endif //DYNASN1_ASN1VALUE_H