//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1.h"

#include "dynasn1/ASN1Codec.h"
#include "dynasn1/ASN1Instance.h"

using asn1detail::Constraint;
using asn1detail::Kind;
using asn1detail::NamedNumber;
using asn1detail::Node;
using asn1detail::Schema;
using asn1detail::SchemaBuilder;

// ---------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------

ASN1::ASN1() = default;

ASN1::ASN1(std::shared_ptr<Schema> schema, std::int32_t node)
    : schema_(std::move(schema)), node_(node) {}

ASN1 ASN1::make(Kind kind, std::string name) {
    // Only SEQUENCE, SET and CHOICE are named descriptions of their own; everything else is a
    // type that gets absorbed into one.
    SchemaBuilder builder(kind == Kind::sequence || kind == Kind::set || kind == Kind::choice
                                  ? name
                                  : std::string{});
    const std::int32_t root = builder.addLeaf(kind, name);
    Schema schema = builder.release();
    schema.root = root;
    return ASN1(std::make_shared<Schema>(std::move(schema)), root);
}

ASN1 ASN1::boolean(std::string name) { return make(Kind::boolean, std::move(name)); }
ASN1 ASN1::integer(std::string name) { return make(Kind::integer, std::move(name)); }
ASN1 ASN1::nullValue(std::string name) { return make(Kind::nullValue, std::move(name)); }
ASN1 ASN1::octetString(std::string name) { return make(Kind::octetString, std::move(name)); }
ASN1 ASN1::bitString(std::string name) { return make(Kind::bitString, std::move(name)); }
ASN1 ASN1::utf8String(std::string name) { return make(Kind::utf8String, std::move(name)); }
ASN1 ASN1::ia5String(std::string name) { return make(Kind::ia5String, std::move(name)); }
ASN1 ASN1::printableString(std::string name) { return make(Kind::printableString, std::move(name)); }
ASN1 ASN1::numericString(std::string name) { return make(Kind::numericString, std::move(name)); }
ASN1 ASN1::visibleString(std::string name) { return make(Kind::visibleString, std::move(name)); }
ASN1 ASN1::utcTime(std::string name) { return make(Kind::utcTime, std::move(name)); }
ASN1 ASN1::generalizedTime(std::string name) { return make(Kind::generalizedTime, std::move(name)); }
ASN1 ASN1::objectIdentifier(std::string name) { return make(Kind::objectIdentifier, std::move(name)); }
ASN1 ASN1::sequence(std::string name) { return make(Kind::sequence, std::move(name)); }
ASN1 ASN1::set(std::string name) { return make(Kind::set, std::move(name)); }
ASN1 ASN1::choice(std::string name) { return make(Kind::choice, std::move(name)); }

ASN1 ASN1::enumerated(std::string name, std::initializer_list<NamedNumber> numbers) {
    ASN1 result = make(Kind::enumerated, std::move(name));
    Constraint constraint;
    constraint.namedNumbers.assign(numbers.begin(), numbers.end());
    result.target().constraint = std::move(constraint);
    result.schema_->invalidate();
    return result;
}

ASN1 ASN1::sequenceOf(ASN1 element, std::string elementName) {
    ASN1 result = make(Kind::sequenceOf, std::move(elementName));
    result.element(std::move(element));
    return result;
}

ASN1 ASN1::setOf(ASN1 element, std::string elementName) {
    ASN1 result = make(Kind::setOf, std::move(elementName));
    result.element(std::move(element));
    return result;
}

ASN1 ASN1::reference(std::string typeName) {
    ASN1 result = make(Kind::reference, typeName);
    result.schema_->nodes[static_cast<std::size_t>(result.node_)].refName = typeName;
    return result;
}

// ---------------------------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------------------------

bool ASN1::valid() const noexcept {
    return schema_ && node_ >= 0 && static_cast<std::size_t>(node_) < schema_->nodes.size();
}

std::size_t ASN1::size() const noexcept { return schema_ ? schema_->nodes.size() : 0; }

std::string ASN1::name() const {
    if (!schema_) return {};
    if (schema_->name.empty()) return schema_->node(node_).name;
    return schema_->name;
}

const Schema &ASN1::internal() const {
    if (!valid()) throw ASN1SchemaError("ASN1 object does not describe a type yet");
    schema_->ensureEffective();
    return *schema_;
}

const Node &ASN1::target() const {
    if (!valid())
        throw ASN1SchemaError("ASN1 object does not describe a type yet");
    return schema_->node(node_);
}

Node &ASN1::target() {
    if (!valid())
        throw ASN1SchemaError("ASN1 object does not describe a type yet");
    detach();
    return schema_->nodes[static_cast<std::size_t>(node_)];
}

void ASN1::detach() {
    if (!schema_) throw ASN1SchemaError("ASN1 object does not describe a type yet");
    if (schema_.use_count() > 1) {
        Schema copy = *schema_;  // deep copy of the node table, shares nothing mutable
        schema_ = std::make_shared<Schema>(std::move(copy));
    }
}

std::int32_t ASN1::absorb(const ASN1 &type) {
    if (!type.valid()) throw ASN1SchemaError("cannot use an empty ASN1 object as a type");
    if (schema_ == type.schema_)
        throw ASN1SchemaError("a type cannot be absorbed into itself");

    SchemaBuilder builder(*schema_);
    const std::int32_t child = builder.absorb(*type.schema_);
    schema_ = std::make_shared<Schema>(builder.release());
    schema_->invalidate();
    return child;
}

void ASN1::requireContainer(Kind kind, const char *operation) const {
    const Node &node = target();
    if (node.kind == kind) return;
    if (kind == Kind::sequence && node.kind == Kind::set) return;  // SEQUENCE and SET hold fields
    throw ASN1SchemaError(std::string("'") + node.name + "' is a " + asn1detail::kindName(node.kind) +
                          " and cannot " + operation);
}

// ---------------------------------------------------------------------------------------------
// Modifiers
// ---------------------------------------------------------------------------------------------

ASN1 &ASN1::optional(bool value) {
    Node &node = target();
    node.optional = value;
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::withDefault(ASN1Value value) {
    Node &node = target();
    if (node.kind == Kind::reference)
        throw ASN1SchemaError("a referenced type cannot carry a default value");
    node.hasDefault = true;
    node.defaultValue = std::move(value);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::tagged(ASN1TagClass tagClass, std::uint32_t tag) {
    Node &node = target();
    if (tagClass == ASN1TagClass::universal && tag == 0)
        throw ASN1SchemaError("tag 0 of the universal class is reserved for end of content");
    node.tagClass = tagClass;
    node.tag = tag;
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::withSize(std::optional<std::int64_t> min, std::optional<std::int64_t> max) {
    if (min && max && *min > *max)
        throw ASN1SchemaError("SIZE constraint has min > max");
    Node &node = target();
    node.constraint.sizeMin = min;
    node.constraint.sizeMax = max;
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::withExactSize(std::int64_t octets) {
    if (octets < 0) throw ASN1SchemaError("SIZE constraint cannot be negative");
    return withSize(octets, octets);
}

ASN1 &ASN1::withRange(std::optional<std::int64_t> min, std::optional<std::int64_t> max) {
    if (min && max && *min > *max)
        throw ASN1SchemaError("value range constraint has min > max");
    Node &node = target();
    node.constraint.valueMin = min;
    node.constraint.valueMax = max;
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::withNamedBits(std::vector<std::string> names) {
    Node &node = target();
    if (node.kind != Kind::bitString)
        throw ASN1SchemaError("a named bit list can only be declared for a BIT STRING, not for a " +
                              std::string(asn1detail::kindName(node.kind)));
    for (std::size_t i = 0; i + 1 < names.size(); ++i) {
        if (names[i] == names[i + 1])
            throw ASN1SchemaError("named bit '" + names[i] + "' appears twice");
    }
    node.constraint.namedBits = std::move(names);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::withName(std::string name) {
    target().name = std::move(name);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::field(std::string fieldName, ASN1 type) {
    requireContainer(Kind::sequence, "receive a field");
    const std::int32_t child = absorb(type);
    schema_->nodes[static_cast<std::size_t>(child)].name = std::move(fieldName);
    schema_->nodes[static_cast<std::size_t>(node_)].children.push_back(child);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::element(ASN1 type) {
    const Node &node = target();
    if (node.kind != Kind::sequenceOf && node.kind != Kind::setOf)
        throw ASN1SchemaError(std::string("'") + node.name + "' is a " + asn1detail::kindName(node.kind) +
                              " and cannot receive an element type");
    const std::int32_t child = absorb(type);
    schema_->nodes[static_cast<std::size_t>(node_)].children.assign(1, child);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::alternative(std::string label, ASN1 type) {
    requireContainer(Kind::choice, "receive an alternative");
    const std::int32_t child = absorb(type);
    schema_->nodes[static_cast<std::size_t>(child)].name = std::move(label);
    schema_->nodes[static_cast<std::size_t>(node_)].children.push_back(child);
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::named(std::string typeName, ASN1 type) {
    if (!type.valid()) throw ASN1SchemaError("cannot register the empty type '" + typeName + "'");
    const std::int32_t index = absorb(type);
    if (!schema_->named.emplace(typeName, index).second)
        throw ASN1SchemaError("type '" + typeName + "' is already defined in this schema");
    if (schema_->nodes[static_cast<std::size_t>(index)].name.empty())
        schema_->nodes[static_cast<std::size_t>(index)].name = typeName;
    schema_->invalidate();
    return *this;
}

ASN1 &ASN1::fieldOf(std::string fieldName, std::string typeName) {
    return field(std::move(fieldName), reference(std::move(typeName)));
}

ASN1 &ASN1::withSchemaName(std::string name) {
    detach();
    schema_->name = std::move(name);
    schema_->invalidate();
    return *this;
}

// ---------------------------------------------------------------------------------------------
// Use
// ---------------------------------------------------------------------------------------------

const std::vector<std::uint8_t> &ASN1::notation() const {
    if (!schema_) throw ASN1SchemaError("ASN1 object does not describe a type yet");
    if (schema_->stale) {
        schema_->notation = asn1detail::encodeSchema(*schema_);
        schema_->stale = false;
    }
    return schema_->notation;
}

ASN1 ASN1::fromNotation(std::span<const std::uint8_t> notation) {
    if (notation.empty()) throw ASN1SchemaError("schema notation is empty");
    Schema schema = asn1detail::decodeSchema(notation);
    const std::int32_t root = schema.root;
    return ASN1(std::make_shared<Schema>(std::move(schema)), root);
}

std::string ASN1::dump() const {
    if (!schema_) return "<empty ASN1 description>\n";
    return asn1detail::dumpSchema(*schema_);
}

bool ASN1::operator==(const ASN1 &rhs) const {
    if (!schema_ || !rhs.schema_) return schema_ == rhs.schema_;
    return notation() == rhs.notation();
}

ASN1Instance ASN1::getInstance() const {
    if (!valid()) throw ASN1SchemaError("ASN1 object does not describe a type yet");
    // Validates references, tags and constraints before any value is built.
    schema_->ensureEffective();
    return ASN1Instance(std::make_shared<const ASN1>(*this));
}