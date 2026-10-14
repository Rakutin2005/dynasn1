//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1Codec.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>
#include <limits>

namespace asn1detail {
namespace {

constexpr std::uint32_t kClassMask = 0xC0;
constexpr std::uint32_t kConstructed = 0x20;
constexpr std::uint32_t kTagMask = 0x1F;

// ---------------------------------------------------------------------------------------------
// Identifier octets
// ---------------------------------------------------------------------------------------------

std::size_t base128Digits(std::uint64_t value) noexcept {
    std::size_t count = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++count;
    }
    return count;
}

std::vector<std::uint8_t> identifierBytes(ASN1TagClass cls, bool constructed, std::uint32_t tag) {
    std::vector<std::uint8_t> out;
    out.reserve(tag < kTagMask ? 1 : 1 + base128Digits(tag));
    out.push_back(static_cast<std::uint8_t>((static_cast<std::uint8_t>(cls) << 6) |
                                            (constructed ? kConstructed : 0) |
                                            (tag < kTagMask ? tag : kTagMask)));
    if (tag < kTagMask) return out;

    std::array<std::uint8_t, 5> buffer{};
    std::size_t count = 0;
    std::uint32_t rest = tag;
    do {
        buffer[count++] = static_cast<std::uint8_t>(rest & 0x7Fu);
        rest >>= 7;
    } while (rest != 0);
    for (std::size_t i = count; i-- > 0;)
        out.push_back(static_cast<std::uint8_t>(buffer[i] | (i == 0 ? 0x00 : 0x80)));
    return out;
}

// ---------------------------------------------------------------------------------------------
// INTEGER content (X.690 8.3.2: two's complement, minimal length)
std::size_t signedContentSize(std::int64_t value) noexcept {
    // Minimal two's complement length from the bit width, no loop.
    if (value >= 0) {
        const std::size_t bits =
                static_cast<std::size_t>(std::bit_width(static_cast<std::uint64_t>(value)));
        return bits == 0 ? 1 : (bits + 7) / 8;
    }
    const std::size_t bits = static_cast<std::size_t>(std::bit_width(~static_cast<std::uint64_t>(value)));
    return (bits + 8) / 8;
}

std::size_t unsignedContentSize(std::uint64_t value) noexcept {
    const std::size_t bits = static_cast<std::size_t>(std::bit_width(value));
    return bits == 0 ? 1 : (bits + 7) / 8;
}

void writeBigEndian(DerWriter &writer, std::uint64_t value, std::size_t bytes) {
    for (std::size_t i = bytes; i-- > 0;) writer.octet(static_cast<std::uint8_t>(value >> (8 * i)));
}

// ---------------------------------------------------------------------------------------------
// Calendar helpers for UTCTime / GeneralizedTime
// ---------------------------------------------------------------------------------------------

std::int64_t daysFromCivil(std::int64_t year, unsigned month, unsigned day) noexcept {
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto yearOfEra = static_cast<unsigned>(year - era * 400);
    const unsigned dayOfYear = (153u * (month + (month > 2 ? -3u : 9u)) + 2u) / 5u + day - 1u;
    const unsigned dayOfEra = yearOfEra * 365u + yearOfEra / 4u - yearOfEra / 100u + dayOfYear;
    return era * 146097 + static_cast<std::int64_t>(dayOfEra) - 719468;
}

// Inverse of daysFromCivil, from Howard Hinnant's calendar algorithms. The shifted year makes
// the leap day land at the end of the year, so the month shift below stays simple.
void civilFromDays(std::int64_t days, std::int64_t &year, std::uint32_t &month,
                   std::uint32_t &day) noexcept {
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const auto dayOfEra = static_cast<std::uint64_t>(days - era * 146097);          // 0..146096
    const std::uint64_t yearOfEra =
            (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    const std::int64_t shiftedYear = static_cast<std::int64_t>(yearOfEra) + era * 400;
    const std::uint64_t dayOfYear =
            dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);          // 0..365
    const std::uint64_t monthPrime = (5 * dayOfYear + 2) / 153;                    // 0..11
    day = static_cast<std::uint32_t>(dayOfYear - (153 * monthPrime + 2) / 5 + 1);  // 1..31
    month = static_cast<std::uint32_t>(monthPrime + (monthPrime < 10 ? 3u : -9u));  // 1..12
    year = shiftedYear + (month <= 2 ? 1 : 0);
}

bool isLeapYear(std::int64_t year) noexcept {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

unsigned daysInMonth(std::int64_t year, unsigned month) noexcept {
    static constexpr std::array<unsigned, 12> table{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && isLeapYear(year)) return 29;
    return table[month - 1];
}

// ---------------------------------------------------------------------------------------------
// Value accessors with schema driven type checks
// ---------------------------------------------------------------------------------------------

std::string labelOf(const Node &node) { return node.name.empty() ? std::string("<unnamed>") : node.name; }

[[noreturn]] void typeMismatch(const Node &node, const char *expected, const ASN1Value &value) {
    throw ASN1ValueError("field '" + labelOf(node) + "' of type " + kindName(node.kind) + " expects " +
                         expected + ", got " + value.typeName());
}

bool boolOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<bool>()) return *v;
    typeMismatch(node, "BOOLEAN", value);
}

const std::vector<std::uint8_t> &octetsOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<std::vector<std::uint8_t>>()) return *v;
    typeMismatch(node, "OCTET STRING", value);
}

const ASN1BitString &bitsOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<ASN1BitString>()) return *v;
    typeMismatch(node, "BIT STRING", value);
}

const std::string &stringOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<std::string>()) return *v;
    typeMismatch(node, "a character string", value);
}

const ASN1Oid &oidOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<ASN1Oid>()) return *v;
    typeMismatch(node, "OBJECT IDENTIFIER", value);
}

std::chrono::system_clock::time_point timeOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<std::chrono::system_clock::time_point>()) return *v;
    typeMismatch(node, "a time value", value);
}

// INTEGER and ENUMERATED accept the narrow carriers and, when they do not reach, ASN1BigInt.
bool integerOf(const Node &node, const ASN1Value &value, bool &isBig, const ASN1BigInt *&big,
               bool &isSigned, std::int64_t &signedValue, std::uint64_t &unsignedValue) {
    if (const auto *v = value.getIf<std::int64_t>()) {
        isBig = false;
        big = nullptr;
        isSigned = true;
        signedValue = *v;
        return true;
    }
    if (const auto *v = value.getIf<std::uint64_t>()) {
        isBig = false;
        big = nullptr;
        isSigned = false;
        unsignedValue = *v;
        return true;
    }
    if (const auto *v = value.getIf<ASN1BigInt>()) {
        isBig = true;
        big = v;
        return true;
    }
    typeMismatch(node, "INTEGER", value);
}

std::span<const std::uint8_t> textBytes(const std::string &text) {
    return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

const ASN1Value::Sequence &sequenceOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<ASN1Value::Sequence>()) return *v;
    typeMismatch(node, "SEQUENCE / SET", value);
}

const ASN1Value::List &listOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<ASN1Value::List>()) return *v;
    typeMismatch(node, "SEQUENCE OF / SET OF", value);
}

const ASN1Value::Choice &choiceOf(const Node &node, const ASN1Value &value) {
    if (const auto *v = value.getIf<ASN1Value::Choice>()) return *v;
    typeMismatch(node, "CHOICE", value);
}

// ---------------------------------------------------------------------------------------------
// Constraint checks
// ---------------------------------------------------------------------------------------------

void checkSize(const Node &node, std::size_t count) {
    const Constraint &constraint = node.constraint;
    if (constraint.sizeMin && static_cast<std::int64_t>(count) < *constraint.sizeMin) {
        throw ASN1ValueError("field '" + labelOf(node) + "' has " + std::to_string(count) +
                             " element(s), but SIZE requires at least " +
                             std::to_string(*constraint.sizeMin));
    }
    if (constraint.sizeMax && static_cast<std::int64_t>(count) > *constraint.sizeMax) {
        throw ASN1ValueError("field '" + labelOf(node) + "' has " + std::to_string(count) +
                             " element(s), but SIZE requires at most " +
                             std::to_string(*constraint.sizeMax));
    }
}

// Checks that a value satisfies a range constraint. Wide values are compared exactly against the
// bounds when they fit into 64 bits, and rejected outright when they cannot.
void checkRange(const Node &node, bool isBig, const ASN1BigInt *big, bool isSigned,
                std::int64_t signedValue, std::uint64_t unsignedValue) {
    const Constraint &constraint = node.constraint;
    if (!constraint.valueMin && !constraint.valueMax) return;

    bool tooSmall = false;
    bool tooLarge = false;
    if (isBig) {
        // The bounds of a range constraint are 64 bit, so a wide value is compared through the
        // narrow carriers when it has one, and is outside any bound when it has not.
        if (big->fitsInInt64()) {
            const std::int64_t value = big->toInt64();
            tooSmall = constraint.valueMin && value < *constraint.valueMin;
            tooLarge = constraint.valueMax && value > *constraint.valueMax;
        } else if (big->fitsInUint64()) {
            const std::uint64_t value = big->toUint64();
            tooSmall = constraint.valueMin && *constraint.valueMin > 0 &&
                       value < static_cast<std::uint64_t>(*constraint.valueMin);
            tooLarge = constraint.valueMax &&
                       value > static_cast<std::uint64_t>(*constraint.valueMax);
        } else {
            tooSmall = tooLarge = true;
        }
    } else {
        tooSmall = isSigned ? (constraint.valueMin && signedValue < *constraint.valueMin)
                            : (constraint.valueMin && *constraint.valueMin > 0 &&
                               unsignedValue < static_cast<std::uint64_t>(*constraint.valueMin));
        tooLarge = isSigned ? (constraint.valueMax && signedValue > *constraint.valueMax)
                            : (constraint.valueMax &&
                               unsignedValue > static_cast<std::uint64_t>(*constraint.valueMax));
    }
    if (!tooSmall && !tooLarge) return;

    const std::string shown = isBig ? big->toDecimal()
                                    : (isSigned ? std::to_string(signedValue)
                                                : std::to_string(unsignedValue));
    throw ASN1ValueError("field '" + labelOf(node) + "' value " + shown + " is outside the constraint" +
                         (constraint.valueMin ? " " + std::to_string(*constraint.valueMin) : "") +
                         ".." + (constraint.valueMax ? std::to_string(*constraint.valueMax) : ""));
}

void checkNamedNumbers(const Node &node, bool isBig, const ASN1BigInt *big, bool isSigned,
                       std::int64_t signedValue, std::uint64_t unsignedValue) {
    const std::vector<NamedNumber> &named = node.constraint.namedNumbers;
    if (node.kind != Kind::enumerated || named.empty()) return;

    bool found = false;
    if (isBig) {
        for (const NamedNumber &entry : named) {
            // Named numbers are 64 bit, so a wider value can never name one of them.
            if (big->fitsInInt64() && entry.number == big->toInt64()) {
                found = true;
                break;
            }
        }
    } else {
        found = std::any_of(named.begin(), named.end(), [&](const NamedNumber &entry) {
            return isSigned ? entry.number == signedValue
                            : (entry.number >= 0 &&
                               static_cast<std::uint64_t>(entry.number) == unsignedValue);
        });
    }
    if (found) return;

    std::string allowed;
    for (const NamedNumber &entry : named) {
        if (!allowed.empty()) allowed += ", ";
        allowed += entry.name + "(" + std::to_string(entry.number) + ")";
    }
    throw ASN1ValueError("field '" + labelOf(node) + "' value " +
                         (isBig ? big->toDecimal()
                                : (isSigned ? std::to_string(signedValue) : std::to_string(unsignedValue))) +
                         " is not one of the named numbers of the enumeration: " + allowed);
}

void checkNamedBits(const Node &node, const ASN1BitString &bits) {
    const std::vector<std::string> &named = node.constraint.namedBits;
    if (named.empty()) return;
    for (std::size_t i = named.size(); i < bits.bitCount; ++i) {
        if (bits.bit(i))
            throw ASN1ValueError("field '" + labelOf(node) + "' sets bit " + std::to_string(i) +
                                 " which is outside its named bit list of " +
                                 std::to_string(named.size()) + " bit(s)");
    }
}

void checkCharacterString(const Node &node, const std::string &text) {
    const std::string problem = characterStringProblem(node.kind, textBytes(text));
    if (!problem.empty())
        throw ASN1ValueError("field '" + labelOf(node) + "': " + problem);
}

// ---------------------------------------------------------------------------------------------
// Binding values to the nodes that describe them
// ---------------------------------------------------------------------------------------------

// One member that has to be encoded, with the tag it will be written under. The tag is kept as
// plain fields instead of identifier octets so that nothing has to be allocated to sort a SET.
struct Bound {
    std::int32_t node = -1;
    const ASN1Value *value = nullptr;
    ASN1TagClass tagClass = ASN1TagClass::universal;
    std::uint32_t tag = 0;
    bool constructed = false;
};

// X.680 11.6: canonical order of tags, class first, then primitive before constructed, then by
// tag number. Equivalent to comparing the identifier octets, without building them.
bool tagPrecedes(const Bound &lhs, const Bound &rhs) {
    if (lhs.tagClass != rhs.tagClass) return lhs.tagClass < rhs.tagClass;
    if (lhs.constructed != rhs.constructed) return !lhs.constructed;
    return lhs.tag < rhs.tag;
}

// Members of one node, kept on the stack for the usual number of children so that encoding a
// value does not allocate once per node.
class Bindings {
public:
    static constexpr std::size_t kInline = 8;

    void clear() noexcept {
        count_ = 0;
        overflow_.clear();
    }

    void push(const Bound &binding) {
        if (count_ < kInline) inline_[count_] = binding;
        else overflow_.push_back(binding);
        ++count_;
    }

    std::size_t size() const noexcept { return count_; }
    Bound &operator[](std::size_t index) noexcept {
        return index < kInline ? inline_[index] : overflow_[index - kInline];
    }
    const Bound &operator[](std::size_t index) const noexcept {
        return index < kInline ? inline_[index] : overflow_[index - kInline];
    }

    void reserve(std::size_t count) {
        if (count > kInline) overflow_.reserve(count - kInline);
    }

    Bound *begin() noexcept { return inline_.data(); }
    Bound *end() noexcept { return inline_.data() + std::min(count_, kInline); }

private:
    std::array<Bound, kInline> inline_{};
    std::vector<Bound> overflow_;
    std::size_t count_ = 0;
};

void bindChildren(Bindings &bindings, const Schema &schema, const Node &node,
                  const ASN1Value &value) {
    bindings.clear();

    switch (node.kind) {
        case Kind::sequence:
        case Kind::set: {
            const ASN1Value::Sequence &fields = sequenceOf(node, value);
            checkSize(node, fields.size());

            // Positions are used only when the values line up with the declared members; a value
            // tree that was assembled by hand may well be in another order.
            bool aligned = fields.size() == node.children.size();
            for (std::size_t i = 0; aligned && i < node.children.size(); ++i) {
                const std::string &declared = schema.node(node.children[i]).name;
                if (!declared.empty() && fields[i].name != declared) aligned = false;
            }
            if (!aligned) {
                // Every value has to belong to a declared member, otherwise the value tree and
                // the description disagree about the shape.
                std::size_t matched = 0;
                for (const ASN1Field &field : fields) {
                    for (const std::int32_t declaredIndex : node.children) {
                        if (schema.node(declaredIndex).name == field.name) {
                            ++matched;
                            break;
                        }
                    }
                }
                if (matched != fields.size())
                    throw ASN1ValueError("'" + labelOf(node) +
                                         "' does not declare a field carried by the value");
            }

            for (std::size_t i = 0; i < node.children.size(); ++i) {
                const std::int32_t declaredIndex = node.children[i];
                const std::int32_t childIndex = schema.effectiveIndex(declaredIndex);
                const Node &child = schema.node(childIndex);
                const bool optional = schema.node(declaredIndex).optional;
                const bool hasDefault = child.hasDefault;
                const ASN1Value *childValue = nullptr;

                if (aligned) {
                    childValue = &fields[i].value;
                } else {
                    for (const ASN1Field &field : fields) {
                        if (field.name == schema.node(declaredIndex).name) {
                            childValue = &field.value;
                            break;
                        }
                    }
                }

                if (hasDefault && childValue && *childValue == child.defaultValue) continue;  // DER
                if (!childValue && hasDefault) childValue = &child.defaultValue;
                if (!childValue && optional) continue;  // absent OPTIONAL member
                if (!childValue)
                    throw ASN1ValueError("'" + labelOf(node) +
                                         "' has no value for the required field '" + labelOf(child) +
                                         "'");

                bindings.push({childIndex, childValue, child.tagClass, child.tag,
                                    kindIsConstructed(child.kind)});
            }
            break;
        }
        case Kind::sequenceOf:
        case Kind::setOf: {
            if (node.children.empty())
                throw ASN1SchemaError(std::string("SEQUENCE OF / SET OF '") + labelOf(node) +
                                      "' has no element type");
            const ASN1Value::List &elements = listOf(node, value);
            checkSize(node, elements.size());
            const std::int32_t elementIndex = schema.effectiveIndex(node.children.front());
            const Node &element = schema.node(elementIndex);
            bindings.reserve(elements.size());
            for (const ASN1Value &item : elements) {
                bindings.push({elementIndex, &item, element.tagClass, element.tag,
                                    kindIsConstructed(element.kind)});
            }
            break;
        }
        case Kind::choice: {
            const ASN1Value::Choice &choice = choiceOf(node, value);
            if (choice.size() != 1)
                throw ASN1ValueError("CHOICE field '" + labelOf(node) +
                                     "' must hold exactly one labelled alternative, got " +
                                     std::to_string(choice.size()));
            std::string known;
            for (const std::int32_t childIndex : node.children) {
                const std::int32_t effective = schema.effectiveIndex(childIndex);
                const Node &child = schema.node(effective);
                if (!known.empty()) known += ", ";
                known += child.name;
                if (child.name == choice.front().tag) {
                    bindings.push(
                            {effective, &choice.front().value, child.tagClass, child.tag,
                             kindIsConstructed(child.kind)});
                    return;
                }
            }
            throw ASN1ValueError("CHOICE field '" + labelOf(node) + "' has no alternative named '" +
                                 choice.front().tag + "', known alternatives: " + known);
        }
        default:
            break;
    }

    if (node.kind == Kind::set) std::sort(bindings.begin(), bindings.end(), tagPrecedes);
}

// ---------------------------------------------------------------------------------------------
// OBJECT IDENTIFIER content
// ---------------------------------------------------------------------------------------------

std::uint64_t firstSubIdentifier(const ASN1Oid &oid) {
    const std::vector<std::uint64_t> &arcs = oid.arcs();
    if (arcs.size() < 2) throw ASN1ValueError("object identifier needs at least two arcs");
    if (arcs[0] > 2) throw ASN1ValueError("first arc of an object identifier must be 0, 1 or 2");
    if (arcs[1] > std::numeric_limits<std::uint64_t>::max() - arcs[0] * 40)
        throw ASN1ValueError("object identifier arc is too large");
    return arcs[0] * 40 + arcs[1];
}

std::size_t oidContentSize(const ASN1Oid &oid) {
    std::size_t size = base128Digits(firstSubIdentifier(oid));
    for (std::size_t i = 2; i < oid.arcs().size(); ++i) size += base128Digits(oid.arcs()[i]);
    return size;
}

void writeOid(DerWriter &writer, const ASN1Oid &oid) {
    const std::vector<std::uint64_t> &arcs = oid.arcs();

    // X.690 8.19.4: the first two arcs travel as one sub-identifier.
    const auto writeSubIdentifier = [&](std::uint64_t sub) {
        std::array<std::uint8_t, 10> buffer{};
        std::size_t count = 0;
        do {
            buffer[count++] = static_cast<std::uint8_t>(sub & 0x7Fu);
            sub >>= 7;
        } while (sub != 0);
        for (std::size_t k = count; k-- > 0;)
            writer.octet(static_cast<std::uint8_t>(buffer[k] | (k == 0 ? 0x00 : 0x80)));
    };

    writeSubIdentifier(firstSubIdentifier(oid));
    for (std::size_t i = 2; i < arcs.size(); ++i) writeSubIdentifier(arcs[i]);
}

}  // namespace

// The field path of the value being decoded. Names are only collected while descending and are
// turned into a string when something actually fails, so that a successful decode never builds
// a single path string.
class PathStack {
public:
    void push(std::string_view name) noexcept {
        if (depth_ < kMaxDepth) names_[depth_++] = name;
    }

    void pop() noexcept {
        if (depth_ > 0) --depth_;
    }

    std::string str() const {
        std::string result;
        for (std::size_t i = 0; i < depth_; ++i) {
            result += names_[i].empty() ? "?" : names_[i];
            if (i + 1 < depth_) result += '.';
        }
        return result;
    }

private:
    std::array<std::string_view, kMaxDepth> names_{};
    std::size_t depth_ = 0;
};

// RAII helper: pushes a name for the duration of one nested call.
class PathGuard {
public:
    PathGuard(PathStack &path, std::string_view name) noexcept : path_(path) { path_.push(name); }
    ~PathGuard() { path_.pop(); }
    PathGuard(const PathGuard &) = delete;
    PathGuard &operator=(const PathGuard &) = delete;

private:
    PathStack &path_;
};

// ---------------------------------------------------------------------------------------------
// DerWriter
// ---------------------------------------------------------------------------------------------

std::size_t DerWriter::identifierSize(ASN1TagClass cls, std::uint32_t tag) noexcept {
    (void)cls;
    return 1 + (tag < kTagMask ? 0 : base128Digits(tag));
}

std::size_t DerWriter::lengthSize(std::size_t len) noexcept {
    if (len < 0x80) return 1;
    std::size_t count = 0;
    for (std::size_t rest = len; rest != 0; rest >>= 8) ++count;
    return 1 + count;
}

void DerWriter::octet(std::uint8_t value) { out_->push_back(value); }

void DerWriter::bytes(std::span<const std::uint8_t> data) {
    out_->insert(out_->end(), data.begin(), data.end());
}

void DerWriter::identifier(ASN1TagClass cls, bool constructed, std::uint32_t tag) {
    bytes(identifierBytes(cls, constructed, tag));
}

void DerWriter::length(std::size_t len) {
    if (len < 0x80) {
        octet(static_cast<std::uint8_t>(len));
        return;
    }
    std::array<std::uint8_t, 8> buffer{};
    std::size_t count = 0;
    for (std::size_t rest = len; rest != 0; rest >>= 8) buffer[count++] = static_cast<std::uint8_t>(rest);
    octet(static_cast<std::uint8_t>(0x80u | count));
    for (std::size_t i = count; i-- > 0;) octet(buffer[i]);
}

// ---------------------------------------------------------------------------------------------
// DerReader
// ---------------------------------------------------------------------------------------------

void DerReader::fail(const std::string &message, const PathStack &path) const {
    throw ASN1DecodeError(message, offset(), path.str());
}

std::uint8_t DerReader::octet(const PathStack &path) { return take(1, path).front(); }

std::span<const std::uint8_t> DerReader::take(std::size_t count, const PathStack &path) {
    if (remaining() < count) fail("unexpected end of data", path);
    const std::span<const std::uint8_t> result = all_.subspan(pos_, count);
    pos_ += count;
    return result;
}

DerHeader DerReader::read(const PathStack &path) {
    DerHeader header;
    const std::size_t headerStart = pos_;

    const std::uint8_t first = octet(path);
    header.tagClass = static_cast<ASN1TagClass>((first & kClassMask) >> 6);
    header.constructed = (first & kConstructed) != 0;
    header.tag = first & kTagMask;

    if (header.tag == kTagMask) {
        header.tag = 0;
        bool leading = true;
        while (true) {
            const std::uint8_t byte = octet(path);
            if (leading && byte == 0x80) fail("non-minimal multi-byte tag number", path);
            leading = false;
            if (header.tag > (std::numeric_limits<std::uint32_t>::max() >> 7))
                fail("tag number out of range", path);
            header.tag = (header.tag << 7) | (byte & 0x7Fu);
            if ((byte & 0x80u) == 0) break;
        }
        if (header.tag < kTagMask) fail("tag number must use the short form", path);
    }

    const std::uint8_t lengthByte = octet(path);
    std::size_t length = 0;
    if ((lengthByte & 0x80u) == 0) {
        length = lengthByte;
    } else {
        const std::size_t count = lengthByte & 0x7Fu;
        if (count == 0) fail("indefinite lengths are not allowed in DER", path);
        if (count > sizeof(std::size_t)) fail("length does not fit into a size_t", path);
        if (remaining() < count) fail("truncated long form length", path);
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t byte = octet(path);
            if (i == 0 && byte == 0) fail("non-minimal long form length", path);
            length = (length << 8) | byte;
        }
        if (length < 0x80) fail("long form length used for a short value", path);
    }

    if (remaining() < length)
        fail("content of " + std::to_string(length) + " byte(s) exceeds the available " +
             std::to_string(remaining()) + " byte(s)",
             path);

    header.headerSize = pos_ - headerStart;
    header.contentOffset = base_ + pos_;
    header.content = all_.subspan(pos_, length);
    pos_ += length;
    return header;
}

DerHeader DerReader::anyHeader(const PathStack &path) { return read(path); }

DerHeader DerReader::peek(const PathStack &path) {
    const std::size_t saved = pos_;
    DerHeader header = read(path);
    pos_ = saved;
    return header;
}

DerHeader DerReader::header(ASN1TagClass expectedClass, std::uint32_t expectedTag,
                            bool expectConstructed, const PathStack &path) {
    const DerHeader header = read(path);
    if (header.tagClass != expectedClass)
        fail(std::string("expected a ") + asn1TagClassName(expectedClass) + " tag but found " +
                 asn1TagClassName(header.tagClass),
             path);
    if (header.tag != expectedTag)
        fail("expected tag " + std::to_string(expectedTag) + " but found " +
             std::to_string(header.tag),
             path);
    if (header.constructed != expectConstructed)
        fail(expectConstructed ? "expected a constructed encoding" : "expected a primitive encoding",
             path);
    return header;
}

// ---------------------------------------------------------------------------------------------
// Character strings and time
// ---------------------------------------------------------------------------------------------

bool isValidUtf8(std::span<const std::uint8_t> data) {
    std::size_t i = 0;
    while (i < data.size()) {
        const std::uint8_t lead = data[i];
        std::size_t extra = 0;
        std::uint32_t code = 0;
        if (lead < 0x80) {
            ++i;
            continue;
        } else if ((lead & 0xE0) == 0xC0) {
            extra = 1;
            code = lead & 0x1Fu;
        } else if ((lead & 0xF0) == 0xE0) {
            extra = 2;
            code = lead & 0x0Fu;
        } else if ((lead & 0xF8) == 0xF0) {
            extra = 3;
            code = lead & 0x07u;
        } else {
            return false;
        }
        if (i + extra >= data.size()) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const std::uint8_t continuation = data[i + k];
            if ((continuation & 0xC0) != 0x80) return false;
            code = (code << 6) | (continuation & 0x3Fu);
        }
        if ((extra == 1 && code < 0x80) || (extra == 2 && code < 0x800) ||
            (extra == 3 && code < 0x10000))
            return false;  // overlong encoding
        if (code > 0x10FFFF) return false;
        if (code >= 0xD800 && code <= 0xDFFF) return false;  // surrogate
        i += extra + 1;
    }
    return true;
}

std::string characterStringProblem(Kind kind, std::span<const std::uint8_t> data) {
    switch (kind) {
        case Kind::utf8String:
            if (!isValidUtf8(data)) return "string is not well formed UTF-8";
            return {};
        case Kind::ia5String:
            for (const std::uint8_t byte : data) {
                if (byte > 0x7F) return "IA5String contains a non ASCII character";
            }
            return {};
        case Kind::numericString:
            for (const std::uint8_t byte : data) {
                if (byte != ' ' && (byte < '0' || byte > '9'))
                    return "NumericString contains a character outside '0'-'9' and space";
            }
            return {};
        case Kind::printableString:
            for (const std::uint8_t byte : data) {
                const bool allowed = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                                     (byte >= '0' && byte <= '9') || byte == ' ' || byte == '\'' ||
                                     byte == '(' || byte == ')' || byte == '+' || byte == ',' ||
                                     byte == '-' || byte == '.' || byte == '/' || byte == ':' ||
                                     byte == '=' || byte == '?';
                if (!allowed)
                    return "PrintableString contains a character outside the PrintableString set "
                           "(X.680 41.4)";
            }
            return {};
        case Kind::visibleString:
            for (const std::uint8_t byte : data) {
                if (byte < 0x20 || byte > 0x7E) return "VisibleString contains a control character";
            }
            return {};
        default:
            return {};
    }
}

// Writes `value` as exactly `width` zero padded digits and returns the new end of the buffer.
char *writeDigits(char *out, int value, int width) noexcept {
    for (int i = width - 1; i >= 0; --i) {
        out[i] = static_cast<char>('0' + value % 10);
        value /= 10;
    }
    return out + width;
}

// Writes the textual form into `out`, which must have room for 40 characters, and returns the
// number of characters written. Used by both passes of the encoder, so the size that was measured
// is the size that is written.
std::size_t formatTimeInto(Kind kind, std::chrono::system_clock::time_point value, char *out) {
    const bool utc = kind == Kind::utcTime;
    const std::int64_t nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(value.time_since_epoch()).count();
    std::int64_t seconds = nanoseconds / 1'000'000'000;
    std::int64_t fraction = nanoseconds % 1'000'000'000;
    if (fraction < 0) {  // floor division, the fraction itself stays positive
        --seconds;
        fraction += 1'000'000'000;
    }

    // Days from the epoch, then back to a civil date.
    std::int64_t days = seconds / 86400;
    std::int64_t rest = seconds % 86400;
    if (rest < 0) {
        --days;
        rest += 86400;
    }
    std::int64_t year = 0;
    std::uint32_t month = 0;
    std::uint32_t day = 0;
    civilFromDays(days, year, month, day);

    const int hour = static_cast<int>(rest / 3600);
    const int minute = static_cast<int>((rest / 60) % 60);
    const int second = static_cast<int>(rest % 60);

    if (utc && (year < 1950 || year > 2049))
        throw ASN1ValueError("UTCTime covers the years 1950..2049, GeneralizedTime for " +
                             std::to_string(year));

    char buffer[40];
    char *end = buffer;
    end = writeDigits(end, static_cast<int>(utc ? year % 100 : year), utc ? 2 : 4);
    end = writeDigits(end, static_cast<int>(month), 2);
    end = writeDigits(end, static_cast<int>(day), 2);
    end = writeDigits(end, hour, 2);
    end = writeDigits(end, minute, 2);
    end = writeDigits(end, second, 2);
    if (!utc && fraction != 0) {
        // X.690 11.7.4: the fraction is written with as few digits as possible, and a zero
        // fraction is written as no fraction at all.
        *end++ = '.';
        char digits[10];
        char *digitEnd = writeDigits(digits, static_cast<int>(fraction), 9);
        while (digitEnd[-1] == '0') --digitEnd;
        end = std::copy(digits, digitEnd, end);
    }
    *end++ = 'Z';
    std::memcpy(out, buffer, static_cast<std::size_t>(end - buffer));
    return static_cast<std::size_t>(end - buffer);
}

std::chrono::system_clock::time_point parseTime(Kind kind, std::span<const std::uint8_t> data) {
    const bool utc = kind == Kind::utcTime;
    const char *name = utc ? "UTCTime" : "GeneralizedTime";

    std::size_t fractionDigits = 0;
    if (utc) {
        if (data.size() != 13)
            throw ASN1DecodeError("UTCTime must be exactly 13 characters in DER, it has no fraction",
                                  0);
    } else {
        // 15 characters without a fraction (14 digits and the Z), or 17 plus one to nine fraction digits,
        // the decimal mark sitting at index 14.
        if (data.size() != 15 && (data.size() < 17 || data.size() > 25))
            throw ASN1DecodeError("GeneralizedTime must be YYYYMMDDHHMMSS[.f{1,9}]Z", 0);
        if (data.size() > 15) {
            if (data[14] != '.')
                throw ASN1DecodeError("DER requires '.' as the decimal mark of a fraction", 0);
            fractionDigits = data.size() - 16;
        }
    }
    if (data.back() != 'Z')
        throw ASN1DecodeError("DER requires a time to end with 'Z' (UTC); local times and time zone "
                              "offsets are not allowed",
                              0);

    const std::size_t yearOffset = 0;
    const std::size_t monthOffset = utc ? 2 : 4;
    const std::size_t dayOffset = utc ? 4 : 6;
    const std::size_t hourOffset = utc ? 6 : 8;
    const std::size_t minuteOffset = utc ? 8 : 10;
    const std::size_t secondOffset = utc ? 10 : 12;

    auto digits = [&](std::size_t offset, std::size_t count) -> int {
        int result = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t byte = data[offset + i];
            if (byte < '0' || byte > '9')
                throw ASN1DecodeError(std::string(name) + " contains a non digit character", 0);
            result = result * 10 + (byte - '0');
        }
        return result;
    };

    const int shortYear = utc ? digits(yearOffset, 2) : 0;
    const int year = utc ? (shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear)
                         : digits(yearOffset, 4);
    const int month = digits(monthOffset, 2);
    const int day = digits(dayOffset, 2);
    const int hour = digits(hourOffset, 2);
    const int minute = digits(minuteOffset, 2);
    const int second = digits(secondOffset, 2);

    if (month < 1 || month > 12)
        throw ASN1DecodeError(std::string(name) + " month out of range", 0);
    if (day < 1 || day > static_cast<int>(daysInMonth(year, static_cast<unsigned>(month))))
        throw ASN1DecodeError(std::string(name) + " day out of range", 0);
    if (hour > 23 || minute > 59 || second > 59)
        throw ASN1DecodeError(std::string(name) + " time of day out of range", 0);

    std::int64_t nanoseconds = 0;
    if (fractionDigits != 0) {
        // X.690 11.7.4: the fraction carries no trailing zeros, otherwise it is not canonical.
        if (data[data.size() - 2] == '0')
            throw ASN1DecodeError("DER requires the fraction of a time to be written without "
                                  "trailing zeros",
                                  0);
        for (std::size_t i = 0; i < fractionDigits; ++i) {
            const std::uint8_t byte = data[15 + i];
            if (byte < '0' || byte > '9')
                throw ASN1DecodeError("GeneralizedTime fraction contains a non digit character", 0);
            nanoseconds = nanoseconds * 10 + (byte - '0');
        }
        for (std::size_t i = fractionDigits; i < 9; ++i) nanoseconds *= 10;
    }

    const std::int64_t days = daysFromCivil(year, static_cast<unsigned>(month),
                                            static_cast<unsigned>(day));
    const std::int64_t total = days * 86400 + hour * 3600 + minute * 60 + second;
    const std::int64_t scaled = total * 1'000'000'000 + nanoseconds;
    if (scaled < std::numeric_limits<std::int64_t>::min() ||
        scaled > std::numeric_limits<std::int64_t>::max())
        throw ASN1DecodeError(std::string(name) + " is outside the nanosecond range of 1677..2262",
                              0);
    return std::chrono::system_clock::time_point{std::chrono::nanoseconds{scaled}};
}

// ---------------------------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------------------------

namespace {

// Content size of a type that has no members.
std::size_t leafContentSize(const Node &n, const ASN1Value &value) {
    switch (n.kind) {
        case Kind::boolean:
            (void)boolOf(n, value);
            return 1;
        case Kind::integer:
        case Kind::enumerated: {
            bool isBig = false;
            const ASN1BigInt *big = nullptr;
            bool isSigned = false;
            std::int64_t signedValue = 0;
            std::uint64_t unsignedValue = 0;
            (void)integerOf(n, value, isBig, big, isSigned, signedValue, unsignedValue);
            checkRange(n, isBig, big, isSigned, signedValue, unsignedValue);
            checkNamedNumbers(n, isBig, big, isSigned, signedValue, unsignedValue);
            if (isBig) return big->octetCount();
            return isSigned ? signedContentSize(signedValue) : unsignedContentSize(unsignedValue);
        }
        case Kind::nullValue:
            return 0;
        case Kind::octetString: {
            const std::vector<std::uint8_t> &data = octetsOf(n, value);
            checkSize(n, data.size());
            return data.size();
        }
        case Kind::bitString: {
            const ASN1BitString &bits = bitsOf(n, value);
            checkSize(n, bits.bitCount);
            checkNamedBits(n, bits);
            return 1 + bits.data.size();
        }
        case Kind::utf8String:
        case Kind::ia5String:
        case Kind::printableString:
        case Kind::numericString:
        case Kind::visibleString: {
            const std::string &text = stringOf(n, value);
            checkSize(n, text.size());
            checkCharacterString(n, text);
            return text.size();
        }
        case Kind::objectIdentifier:
            return oidContentSize(oidOf(n, value));
        case Kind::utcTime:
        case Kind::generalizedTime: {
            char buffer[40];
            return formatTimeInto(n.kind, timeOf(n, value), buffer);
        }
        default:
            break;
    }
    throw ASN1SchemaError(std::string("cannot size type ") + kindName(n.kind));
}

std::size_t compositeContentSize(const Schema &schema, std::int32_t node, const ASN1Value &value,
                                 int depth);

// Content size of already bound members.
std::size_t boundContentSize(const Schema &schema, const Bindings &bindings, int depth) {
    std::size_t total = 0;
    for (std::size_t i = 0; i < bindings.size(); ++i) {
        const Bound &binding = bindings[i];
        const Node &child = schema.node(binding.node);
        const std::size_t content = kindIsConstructed(child.kind)
                                            ? compositeContentSize(schema, binding.node,
                                                                  *binding.value, depth + 1)
                                            : leafContentSize(child, *binding.value);
        total += DerWriter::identifierSize(binding.tagClass, binding.tag) +
                 DerWriter::lengthSize(content) + content;
    }
    return total;
}

std::size_t compositeContentSize(const Schema &schema, std::int32_t node, const ASN1Value &value,
                                 int depth) {
    if (depth > kMaxDepth) throw ASN1ValueError("structure is nested too deeply");
    Bindings bindings;
    bindChildren(bindings, schema, schema.node(node), value);
    return boundContentSize(schema, bindings, depth);
}

}  // namespace

std::size_t encodedSize(const Schema &schema, std::int32_t node, const ASN1Value &value, int depth) {
    schema.ensureEffective();
    const std::int32_t effective = schema.effectiveIndex(node);
    const Node &n = schema.node(effective);
    const std::size_t content = kindIsConstructed(n.kind)
                                        ? compositeContentSize(schema, effective, value, depth)
                                        : leafContentSize(n, value);
    return DerWriter::identifierSize(n.tagClass, n.tag) + DerWriter::lengthSize(content) + content;
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

namespace {

// Writes the content of a type that has no members.
void writeLeafContent(DerWriter &writer, const Node &n, const ASN1Value &value) {
    switch (n.kind) {
        case Kind::boolean:
            writer.octet(boolOf(n, value) ? 0xFF : 0x00);
            return;
        case Kind::integer:
        case Kind::enumerated: {
            bool isBig = false;
            const ASN1BigInt *big = nullptr;
            bool isSigned = false;
            std::int64_t signedValue = 0;
            std::uint64_t unsignedValue = 0;
            (void)integerOf(n, value, isBig, big, isSigned, signedValue, unsignedValue);
            checkRange(n, isBig, big, isSigned, signedValue, unsignedValue);
            checkNamedNumbers(n, isBig, big, isSigned, signedValue, unsignedValue);
            if (isBig) {
                std::uint8_t buffer[ASN1BigInt::kMaxOctets];
                if (big->octetCount() > sizeof(buffer))
                    throw ASN1ValueError("INTEGER is wider than the supported " +
                                         std::to_string(ASN1BigInt::kMaxOctets) + " octets");
                writer.bytes({buffer, big->writeOctets(buffer)});
                return;
            }
            if (isSigned)
                writeBigEndian(writer, static_cast<std::uint64_t>(signedValue),
                               signedContentSize(signedValue));
            else
                writeBigEndian(writer, unsignedValue, unsignedContentSize(unsignedValue));
            return;
        }
        case Kind::nullValue:
            return;
        case Kind::octetString: {
            const std::vector<std::uint8_t> &data = octetsOf(n, value);
            checkSize(n, data.size());
            writer.bytes(data);
            return;
        }
        case Kind::bitString: {
            const ASN1BitString &bits = bitsOf(n, value);
            checkSize(n, bits.bitCount);
            checkNamedBits(n, bits);
            ASN1BitString normalized = bits;
            normalized.truncate(bits.bitCount);
            writer.octet(static_cast<std::uint8_t>(normalized.unusedBits()));
            writer.bytes(normalized.data);
            return;
        }
        case Kind::utf8String:
        case Kind::ia5String:
        case Kind::printableString:
        case Kind::numericString:
        case Kind::visibleString: {
            const std::string &text = stringOf(n, value);
            checkSize(n, text.size());
            checkCharacterString(n, text);
            writer.bytes(textBytes(text));
            return;
        }
        case Kind::objectIdentifier:
            writeOid(writer, oidOf(n, value));
            return;
        case Kind::utcTime:
        case Kind::generalizedTime: {
            char buffer[40];
            const std::size_t length = formatTimeInto(n.kind, timeOf(n, value), buffer);
            writer.bytes({reinterpret_cast<const std::uint8_t *>(buffer), length});
            return;
        }
        default:
            break;
    }
    throw ASN1SchemaError(std::string("cannot encode type ") + kindName(n.kind));
}

// Writes the members that were already bound, reusing what the length calculation needed.
void writeBoundContent(DerWriter &writer, const Schema &schema, const Node &node,
                       const Bindings &bindings, int depth) {
    if (node.kind == Kind::setOf) {
        // X.690 11.6: components sorted ascending, compared as octet strings.
        std::vector<std::vector<std::uint8_t>> encodings;
        encodings.reserve(bindings.size());
        for (std::size_t i = 0; i < bindings.size(); ++i)
            encodings.push_back(encodeNode(schema, bindings[i].node, *bindings[i].value, depth + 1));
        std::sort(encodings.begin(), encodings.end());
        for (const std::vector<std::uint8_t> &encoded : encodings) writer.bytes(encoded);
        return;
    }
    for (std::size_t i = 0; i < bindings.size(); ++i) {
        const Bound &binding = bindings[i];
        const Node &child = schema.node(binding.node);
        writer.identifier(binding.tagClass, binding.constructed, binding.tag);
        if (kindIsConstructed(child.kind)) {
            Bindings children;
            bindChildren(children, schema, child, *binding.value);
            writer.length(boundContentSize(schema, children, depth + 1));
            writeBoundContent(writer, schema, child, children, depth + 1);
        } else {
            writer.length(leafContentSize(child, *binding.value));
            writeLeafContent(writer, child, *binding.value);
        }
    }
}

}  // namespace

void encodeValue(DerWriter &writer, const Schema &schema, std::int32_t node, const ASN1Value &value,
                 int depth) {
    schema.ensureEffective();
    if (depth > kMaxDepth) throw ASN1ValueError("structure is nested too deeply");

    const std::int32_t effective = schema.effectiveIndex(node);
    const Node &n = schema.node(effective);
    const bool constructed = kindIsConstructed(n.kind);

    if (!constructed) {
        writer.identifier(n.tagClass, false, n.tag);
        writer.length(leafContentSize(n, value));
        writeLeafContent(writer, n, value);
        return;
    }

    // The members are bound once and used for both the length and the content.
    Bindings bindings;
    bindChildren(bindings, schema, n, value);
    writer.identifier(n.tagClass, true, n.tag);
    writer.length(boundContentSize(schema, bindings, depth));
    writeBoundContent(writer, schema, n, bindings, depth);
}

std::vector<std::uint8_t> encodeNode(const Schema &schema, std::int32_t node, const ASN1Value &value,
                                     int depth) {
    std::vector<std::uint8_t> out;
    out.reserve(encodedSize(schema, node, value, depth));
    DerWriter writer(out);
    encodeValue(writer, schema, node, value, depth);
    return out;
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

namespace {

ASN1Value decodeInteger(std::span<const std::uint8_t> content, std::size_t offset,
                        const PathStack &path) {
    if (content.empty())
        throw ASN1DecodeError("INTEGER and ENUMERATED need at least one content octet", offset,
                              path.str());
    if (content.size() > ASN1BigInt::kMaxOctets)
        throw ASN1DecodeError("INTEGER of " + std::to_string(content.size()) +
                                      " octets exceeds the supported " +
                                      std::to_string(ASN1BigInt::kMaxOctets) + " octets",
                              offset, path.str());
    if (content.size() > 1) {
        const bool redundantZero = content[0] == 0x00 && (content[1] & 0x80u) == 0;
        const bool redundantOnes = content[0] == 0xFF && (content[1] & 0x80u) != 0;
        if (redundantZero || redundantOnes)
            throw ASN1DecodeError("non-minimal INTEGER encoding", offset, path.str());
    }
    if (content.size() <= 8) {
        // Two's complement, sign extended to 64 bits so that a negative value survives.
        std::uint64_t accumulator = (content[0] & 0x80u) ? std::numeric_limits<std::uint64_t>::max() : 0;
        for (const std::uint8_t byte : content) accumulator = (accumulator << 8) | byte;
        if ((content[0] & 0x80u) != 0) {
            std::int64_t value = 0;
            static_assert(sizeof(value) == sizeof(accumulator));
            std::memcpy(&value, &accumulator, sizeof(value));
            return ASN1Value(value);
        }
        if (accumulator <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            return ASN1Value(static_cast<std::int64_t>(accumulator));
        return ASN1Value(accumulator);
    }
    return ASN1Value(ASN1BigInt::fromOctets(content));
}

ASN1Value decodeOid(std::span<const std::uint8_t> content, std::size_t offset, const PathStack &path) {
    if (content.empty())
        throw ASN1DecodeError("empty OBJECT IDENTIFIER", offset, path.str());

    std::vector<std::uint64_t> subIdentifiers;
    std::uint64_t accumulator = 0;
    bool leading = true;
    for (const std::uint8_t byte : content) {
        if (leading && byte == 0x80)
            throw ASN1DecodeError("non-minimal OBJECT IDENTIFIER sub-identifier", offset,
                                  path.str());
        leading = false;
        if (accumulator > (std::numeric_limits<std::uint64_t>::max() >> 7))
            throw ASN1DecodeError("OBJECT IDENTIFIER arc is too large", offset, path.str());
        accumulator = (accumulator << 7) | (byte & 0x7Fu);
        if ((byte & 0x80u) == 0) {
            subIdentifiers.push_back(accumulator);
            accumulator = 0;
            leading = true;
        }
    }

    const std::uint64_t first = subIdentifiers.front();
    if (first < 40) {
        subIdentifiers[0] = 0;
        subIdentifiers.insert(subIdentifiers.begin() + 1, first);
    } else if (first < 80) {
        subIdentifiers[0] = 1;
        subIdentifiers.insert(subIdentifiers.begin() + 1, first - 40);
    } else {
        subIdentifiers[0] = 2;
        subIdentifiers.insert(subIdentifiers.begin() + 1, first - 80);
    }
    return ASN1Oid(std::move(subIdentifiers));
}

ASN1Value decodeBits(std::span<const std::uint8_t> content, std::size_t offset, const PathStack &path) {
    if (content.empty())
        throw ASN1DecodeError("empty BIT STRING content", offset, path.str());
    const std::size_t unused = content[0];
    if (unused > 7)
        throw ASN1DecodeError("a BIT STRING can have at most 7 unused bits", offset,
                              path.str());
    if (content.size() == 1 && unused != 0)
        throw ASN1DecodeError("an empty BIT STRING cannot have unused bits", offset,
                              path.str());

    ASN1BitString bits;
    bits.data.assign(content.begin() + 1, content.end());
    if (unused != 0) {
        const std::uint8_t mask = static_cast<std::uint8_t>((1u << unused) - 1u);
        if (!bits.data.empty() && (bits.data.back() & mask) != 0)
            throw ASN1DecodeError("DER requires the unused trailing bits of a BIT STRING to be zero",
                                  offset, path.str());
        if (!bits.data.empty()) bits.data.back() &= static_cast<std::uint8_t>(~mask);
    }
    bits.bitCount = bits.data.size() * 8 - unused;
    return ASN1Value(std::move(bits));
}

}  // namespace

ASN1Value decodeValue(const Schema &schema, std::int32_t node, std::span<const std::uint8_t> content,
                      std::size_t offset, PathStack &path, int depth) {
    schema.ensureEffective();
    if (depth > kMaxDepth)
        throw ASN1DecodeError("structure is nested too deeply", offset, path.str());

    const std::int32_t effective = schema.effectiveIndex(node);
    const Node &n = schema.node(effective);

    switch (n.kind) {
        case Kind::boolean:
            if (content.size() != 1)
                throw ASN1DecodeError("BOOLEAN needs exactly one content octet", offset,
                                      path.str());
            if (content[0] != 0x00 && content[0] != 0xFF)
                throw ASN1DecodeError("DER encodes BOOLEAN as 0x00 or 0xFF", offset, path.str());
            return ASN1Value(content[0] == 0xFF);
        case Kind::integer:
        case Kind::enumerated:
            return decodeInteger(content, offset, path);
        case Kind::nullValue:
            if (!content.empty())
                throw ASN1DecodeError("NULL must have an empty content", offset, path.str());
            return ASN1Value(nullptr);
        case Kind::octetString: {
            checkSize(n, content.size());
            return ASN1Value(std::vector<std::uint8_t>(content.begin(), content.end()));
        }
        case Kind::bitString: {
            ASN1Value bits = decodeBits(content, offset, path);
            checkSize(n, bits.asBits().bitCount);
            checkNamedBits(n, bits.asBits());
            return bits;
        }
        case Kind::utf8String:
        case Kind::ia5String:
        case Kind::printableString:
        case Kind::numericString:
        case Kind::visibleString: {
            const std::string problem = characterStringProblem(n.kind, content);
            if (!problem.empty())
                throw ASN1DecodeError(problem, offset, path.str());
            checkSize(n, content.size());
            return ASN1Value(
                    std::string(reinterpret_cast<const char *>(content.data()), content.size()));
        }
        case Kind::objectIdentifier:
            return decodeOid(content, offset, path);
        case Kind::utcTime:
        case Kind::generalizedTime:
            return ASN1Value(parseTime(n.kind, content));
        default:
            break;
    }

    DerReader reader(content, offset);

    switch (n.kind) {
        case Kind::sequence:
        case Kind::set: {
            // Members that are OPTIONAL or carry a DEFAULT may be absent from the encoding, so
            // the next tag decides which declared member comes next. A SEQUENCE keeps the
            // declared order, a SET is ordered by tag.
            std::vector<std::optional<ASN1Field>> slots(n.children.size());
            std::vector<std::size_t> order;
            std::size_t next = 0;  // first member a SEQUENCE may still match
            Bound previousTag{};

            const auto matches = [&](std::size_t index, const DerHeader &header) {
                const Node &candidate = schema.node(schema.effectiveIndex(n.children[index]));
                return candidate.tagClass == header.tagClass && candidate.tag == header.tag &&
                       kindIsConstructed(candidate.kind) == header.constructed;
            };

            while (!reader.empty()) {
                const DerHeader probe = reader.peek(path);

                std::size_t found = n.children.size();
                for (std::size_t index = n.kind == Kind::set ? 0 : next; index < n.children.size();
                     ++index) {
                    if (slots[index]) continue;
                    if (matches(index, probe)) {
                        found = index;
                        break;
                    }
                }
                if (found == n.children.size())
                    reader.fail("'" + labelOf(n) + "' does not accept a value with tag " +
                                    std::to_string(probe.tag),
                                path);

                const std::int32_t childEffective = schema.effectiveIndex(n.children[found]);
                const Node &child = schema.node(childEffective);
                const std::string &childName = schema.node(n.children[found]).name;
                const PathGuard guard(path, childName);
                const DerHeader header =
                        reader.header(child.tagClass, child.tag, kindIsConstructed(child.kind), path);
                if (n.kind == Kind::set) {
                    const Bound candidate{childEffective, nullptr, child.tagClass, child.tag,
                                          kindIsConstructed(child.kind)};
                    if (tagPrecedes(candidate, previousTag))
                        reader.fail("DER requires the components of a SET to be sorted by tag", path);
                    previousTag = candidate;
                }
                slots[found] = ASN1Field{childName,
                                         decodeValue(schema, childEffective, header.content,
                                                     header.contentOffset, path, depth + 1)};
                order.push_back(found);
                if (n.kind != Kind::set) next = found + 1;
            }

            // Members that were not transmitted: absent when OPTIONAL, filled in when they carry
            // a DEFAULT, an error otherwise.
            for (std::size_t index = 0; index < n.children.size(); ++index) {
                if (slots[index]) continue;
                const std::int32_t childIndex = schema.effectiveIndex(n.children[index]);
                const Node &child = schema.node(childIndex);
                const bool optional = schema.node(n.children[index]).optional;
                if (child.hasDefault) {
                    slots[index] = ASN1Field{schema.node(n.children[index]).name, child.defaultValue};
                    order.push_back(index);
                } else if (!optional) {
                    const PathGuard guard(path, schema.node(n.children[index]).name);
                    reader.fail("required member '" + labelOf(child) + "' is missing", path);
                }
            }

            ASN1Value::Sequence fields;
            fields.reserve(order.size());
            for (const std::size_t index : order) fields.push_back(std::move(*slots[index]));
            checkSize(n, fields.size());
            return ASN1Value(std::move(fields));
        }
        case Kind::sequenceOf:
        case Kind::setOf: {
            if (n.children.empty())
                throw ASN1SchemaError("SET OF / SEQUENCE OF without an element type at '" +
                                      path.str() + "'");
            const std::int32_t elementIndex = schema.effectiveIndex(n.children.front());
            const Node &element = schema.node(elementIndex);
            ASN1Value::List elements;
            std::vector<std::uint8_t> previous;
            const PathGuard guard(path, element.name);
            while (!reader.empty()) {
                const DerHeader header =
                        reader.header(element.tagClass, element.tag, kindIsConstructed(element.kind),
                                      path);
                if (n.kind == Kind::setOf) {
                    // Rebuild this element's octets to verify the canonical SET OF ordering.
                    std::vector<std::uint8_t> encoded;
                    DerWriter head(encoded);
                    head.identifier(element.tagClass, kindIsConstructed(element.kind), element.tag);
                    head.length(header.content.size());
                    encoded.insert(encoded.end(), header.content.begin(), header.content.end());
                    if (encoded < previous)
                        reader.fail("DER requires the components of a SET OF to be sorted ascending",
                                    path);
                    previous = std::move(encoded);
                }
                elements.push_back(decodeValue(schema, elementIndex, header.content,
                                                header.contentOffset, path, depth + 1));
            }
            checkSize(n, elements.size());
            return ASN1Value(std::move(elements));
        }
        case Kind::choice: {
            const DerHeader probe = reader.anyHeader(path);
            std::int32_t chosen = -1;
            for (const std::int32_t childIndex : n.children) {
                const std::int32_t childEffective = schema.effectiveIndex(childIndex);
                const Node &child = schema.node(childEffective);
                if (child.tagClass == probe.tagClass && child.tag == probe.tag &&
                    kindIsConstructed(child.kind) == probe.constructed) {
                    chosen = childEffective;
                    break;
                }
            }
            if (chosen < 0) {
                std::string known;
                for (const std::int32_t childIndex : n.children) {
                    const std::string &name = schema.node(schema.effectiveIndex(childIndex)).name;
                    if (!known.empty()) known += ", ";
                    known += name + "[" + std::to_string(schema.node(schema.effectiveIndex(childIndex)).tag) + "]";
                }
                throw ASN1DecodeError("no alternative of the CHOICE matches tag " +
                                              std::to_string(probe.tag) + ", known alternatives: " + known,
                                      probe.contentOffset, path.str());
            }
            const Node &chosenNode = schema.node(chosen);
            const PathGuard guard(path, chosenNode.name);
            ASN1Value::Choice result;
            result.push_back({chosenNode.name,
                              decodeValue(schema, chosen, probe.content, probe.contentOffset, path,
                                          depth + 1)});
            return ASN1Value(std::move(result));
        }
        default:
            break;
    }

    throw ASN1SchemaError(std::string("cannot decode type ") + kindName(n.kind));
}

ASN1Value decodeNode(const Schema &schema, std::int32_t node, std::span<const std::uint8_t> der,
                     std::string_view path) {
    schema.ensureEffective();
    if (node < 0) throw ASN1SchemaError("cannot decode, the description has no root type");
    const std::int32_t effective = schema.effectiveIndex(node);
    const Node &n = schema.node(effective);

    PathStack fieldPath;
    fieldPath.push(path);
    DerReader reader(der, 0);
    const DerHeader header = reader.header(n.tagClass, n.tag, kindIsConstructed(n.kind), fieldPath);
    if (!reader.empty()) reader.fail("trailing data after the top level value", fieldPath);
    return decodeValue(schema, effective, header.content, header.contentOffset, fieldPath, 0);
}

ASN1Value decodeRoot(const Schema &schema, std::span<const std::uint8_t> der, std::string_view path) {
    schema.ensureEffective();
    return decodeNode(schema, schema.root, der, path);
}

}  // namespace asn1detail