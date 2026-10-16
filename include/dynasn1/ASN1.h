//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1_H
#define DYNASN1_ASN1_H

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "dynasn1/ASN1Exception.h"
#include "dynasn1/ASN1Schema.h"
#include "dynasn1/ASN1Value.h"

class ASN1Instance;

// A dynamically built ASN.1 type description.
//
// The class is builder and description in one: every modifier mutates the object in place and
// returns *this, so the code reads close to the ASN.1 notation it stands for.
//
//   ASN1 request = ASN1::sequence("TransferRequest");
//   request.field("id",    ASN1::integer().withRange(0, INT64_MAX));
//   request.field("memo",  ASN1::utf8String().optional().withSize(0, 64));
//   request.field("tags",  ASN1::sequenceOf(ASN1::utf8String()).withSize(0, 8));
//   request.field("state", ASN1::enumerated("State", {{"new", 0}, {"done", 1}}));
//
//   ASN1Instance instance = request.getInstance();
//   instance.set("id", 42);
//   instance.set("memo", "invoice");
//   const std::vector<std::uint8_t> der = instance.getDER();
//
//   ASN1Instance decoded = ASN1Instance::decode(request, der);
//
// Copies are cheap and independent: the node table is shared until one of the copies is
// modified, and only that copy then continues with a table of its own.
//
// A single description is not thread safe: notation() fills the binary form lazily and the copy
// on write clones the node table in place.
class ASN1 {
public:
    ASN1();

    // --- factories ---------------------------------------------------------------------------
    static ASN1 boolean(std::string name = {});
    static ASN1 integer(std::string name = {});
    static ASN1 nullValue(std::string name = {});
    static ASN1 octetString(std::string name = {});
    static ASN1 bitString(std::string name = {});
    static ASN1 utf8String(std::string name = {});
    static ASN1 ia5String(std::string name = {});
    static ASN1 printableString(std::string name = {});
    static ASN1 numericString(std::string name = {});
    static ASN1 visibleString(std::string name = {});
    static ASN1 utcTime(std::string name = {});
    static ASN1 generalizedTime(std::string name = {});
    static ASN1 date(std::string name = {});
    static ASN1 timeOfDay(std::string name = {});
    static ASN1 dateTime(std::string name = {});
    static ASN1 objectIdentifier(std::string name = {});
    static ASN1 enumerated(std::string name, std::initializer_list<asn1detail::NamedNumber> numbers = {});
    static ASN1 sequence(std::string name);
    static ASN1 set(std::string name);
    static ASN1 choice(std::string name);
    static ASN1 sequenceOf(ASN1 element, std::string elementName = {});
    static ASN1 setOf(ASN1 element, std::string elementName = {});
    static ASN1 reference(std::string typeName);

    // --- modifiers ---------------------------------------------------------------------------

    // OPTIONAL member of a SEQUENCE / SET.
    ASN1 &optional(bool value = true);

    // DEFAULT value, encoded when the field is never set.
    ASN1 &withDefault(ASN1Value value);

    // Replaces the universal tag, e.g. tagged(ASN1TagClass::context, 0) for [0].
    ASN1 &tagged(ASN1TagClass tagClass, std::uint32_t tag);

    // SIZE constraint, checked while encoding and after decoding.
    ASN1 &withSize(std::optional<std::int64_t> min, std::optional<std::int64_t> max = std::nullopt);

    // SIZE constraint of exactly N octets. This is what declares a digest, a signature or a key:
    // the value travels as an ASN1FixedBytes<N> and the width is enforced by the description.
    ASN1 &withExactSize(std::int64_t octets);

    // Value range constraint for INTEGER / ENUMERATED.
    ASN1 &withRange(std::optional<std::int64_t> min, std::optional<std::int64_t> max = std::nullopt);

    // BIT STRING named bit list: position 0 is the first name.
    ASN1 &withNamedBits(std::vector<std::string> names);

    // Renames the type. The name is also the label an element type or a CHOICE alternative is
    // matched by.
    ASN1 &withName(std::string name);

    // Adds a member to a SEQUENCE / SET.
    ASN1 &field(std::string fieldName, ASN1 type);

    // Sets the element type of a SEQUENCE OF / SET OF.
    ASN1 &element(ASN1 type);

    // Adds an alternative to a CHOICE.
    ASN1 &alternative(std::string label, ASN1 type);

    // Registers a named type in this schema. Named types are what makes recursive schemas
    // possible: describe the type once, then refer to it with ASN1::reference(name).
    ASN1 &named(std::string typeName, ASN1 type);

    // Declares a member whose type is the named type `typeName`.
    ASN1 &fieldOf(std::string fieldName, std::string typeName);

    // Sets the informational name of the schema, used by dump() and error messages.
    ASN1 &withSchemaName(std::string name);

    // --- use ---------------------------------------------------------------------------------

    // An empty value bound to a snapshot of this description.
    ASN1Instance getInstance() const;

    // The description in binary form: DER of the meta schema, ready to be stored or sent.
    // The reference stays valid until this description is modified, so copy it when it has to
    // outlive a later change.
    const std::vector<std::uint8_t> &notation() const;

    // Rebuilds a description from its binary form.
    static ASN1 fromNotation(std::span<const std::uint8_t> notation);

    // ASN.1-like textual rendering, for logs and debugging.
    std::string dump() const;

    bool valid() const noexcept;
    std::size_t size() const noexcept;
    std::string name() const;

    // Two descriptions are equal when their binary forms are equal.
    bool operator==(const ASN1 &rhs) const;

private:
    friend class ASN1Instance;

    ASN1(std::shared_ptr<asn1detail::Schema> schema, std::int32_t node);

    // Copy on write: a description shared with somebody else is cloned before it is modified.
    void detach();

    asn1detail::Schema &schema() const;

    // Read only view of the node table, used by the codec and by ASN1Instance. Validates the
    // description on the first call.
    const asn1detail::Schema &internal() const;

    asn1detail::Node &target();
    const asn1detail::Node &target() const;

    // Copies the node table of `type` into this schema and returns its new root index.
    std::int32_t absorb(const ASN1 &type);
    void requireContainer(asn1detail::Kind kind, const char *operation) const;

    static ASN1 make(asn1detail::Kind kind, std::string name);

    std::shared_ptr<asn1detail::Schema> schema_;
    std::int32_t node_ = -1;
};

#endif //DYNASN1_ASN1_H