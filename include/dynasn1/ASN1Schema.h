//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1SCHEMA_H
#define DYNASN1_ASN1SCHEMA_H

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "dynasn1/ASN1Exception.h"
#include "dynasn1/ASN1Value.h"

namespace asn1detail {

// Every ASN.1 type the module can describe. `reference` is not an ASN.1 type but a link to a
// named type, which is what makes recursive schemas possible.
enum class Kind : std::uint8_t {
    boolean,
    integer,
    nullValue,
    octetString,
    bitString,
    utf8String,
    ia5String,
    printableString,
    numericString,
    visibleString,
    utcTime,
    generalizedTime,
    objectIdentifier,
    enumerated,
    sequence,
    set,
    sequenceOf,
    setOf,
    choice,
    reference
};

std::uint32_t defaultUniversalTag(Kind kind) noexcept;
bool kindIsConstructed(Kind kind) noexcept;
const char *kindName(Kind kind) noexcept;
Kind kindFromIndex(std::int64_t index);

// ENUMERATED companion of an ENUMERATED type (name + number) or of a BIT STRING (named bits
// are plain positions, kept in Constraint::namedBits).
struct NamedNumber {
    std::string name;
    std::int64_t number = 0;

    bool operator==(const NamedNumber &rhs) const noexcept {
        return name == rhs.name && number == rhs.number;
    }
};

// Subtype constraints that are validated while encoding.
struct Constraint {
    std::optional<std::int64_t> sizeMin;
    std::optional<std::int64_t> sizeMax;
    std::optional<std::int64_t> valueMin;
    std::optional<std::int64_t> valueMax;
    std::vector<std::string> namedBits;     // BIT STRING named bit list, position = order
    std::vector<NamedNumber> namedNumbers;  // INTEGER / ENUMERATED named numbers
};

// One entry of the flat node table. Composite types point at their members, so a table can
// describe arbitrarily deep and recursive structures.
struct Node {
    std::string name;             // label: field name, alternative label or element label
    Kind kind = Kind::nullValue;
    ASN1TagClass tagClass = ASN1TagClass::universal;
    std::uint32_t tag = 0;        // 0 -> universal default of `kind`
    bool optional = false;
    bool hasDefault = false;
    ASN1Value defaultValue{};
    Constraint constraint{};
    std::string refName;          // Kind::reference: name of the referenced type
    std::int32_t ref = -1;        // Kind::reference: resolved index
    std::vector<std::int32_t> children;
};

// The complete description of one schema. `notation` holds the DER encoding of the very same
// description in the meta schema defined below, and is the authoritative binary form.
struct Schema {
    std::string name;
    std::int32_t root = -1;
    std::vector<Node> nodes;
    std::unordered_map<std::string, std::int32_t> named;
    std::vector<std::uint8_t> notation;
    bool stale = true;  // notation has to be regenerated
    mutable std::vector<std::int32_t> effective;
    mutable bool effectiveValid = false;

    void invalidate() noexcept {
        stale = true;
        effectiveValid = false;
    }

    const Node &node(std::int32_t index) const;

    // Index of the node that actually describes the value: identical to `index` unless the node
    // is a reference. Requires ensureEffective() to have run once.
    std::int32_t effectiveIndex(std::int32_t index) const;

    // Resolves references, checks indices, duplicate names, CHOICE tags, constraints.
    void ensureEffective() const;
};

// Incremental construction of a node table. Used by the public builder and by the meta schema.
class SchemaBuilder {
public:
    explicit SchemaBuilder(std::string schemaName = {}) : schema_() { schema_.name = std::move(schemaName); }

    // Continues an existing node table, e.g. when a nested description is merged in.
    explicit SchemaBuilder(Schema schema) noexcept : schema_(std::move(schema)) {}

    std::int32_t addNode(Node node);

    std::int32_t addLeaf(Kind kind, std::string name = {});
    std::int32_t addSequence(std::string name = {});
    std::int32_t addSet(std::string name = {});
    std::int32_t addChoice(std::string name = {});
    std::int32_t addList(Kind listKind, std::int32_t element, std::string elementName = {});
    std::int32_t addReference(std::string typeName);

    // Appends `child` to `parent` and gives the child the label `fieldName`.
    void addChild(std::int32_t parent, std::int32_t child, std::string fieldName = {});

    // Attribute setters for an already created node.
    void setOptional(std::int32_t node, bool value = true);
    void setDefault(std::int32_t node, ASN1Value value);
    void setTag(std::int32_t node, ASN1TagClass tagClass, std::uint32_t tag);
    void setConstraint(std::int32_t node, Constraint constraint);

    // Registers a type under `typeName` so that references can point at it.
    void define(std::string typeName, std::int32_t node);

    // Copies the node table of `other` (a nested or registered schema) into this one, shifting
    // all indices, and returns the index of the copied root. Named types are carried over.
    std::int32_t absorb(const Schema &other);

    const Schema &schema() const noexcept { return schema_; }
    Schema &schema() noexcept { return schema_; }
    Schema release();

private:
    Schema schema_;
};

// ---------------------------------------------------------------------------------------------
// Meta schema: the ASN.1 notation in which a schema description itself is stored.
//
//   PqliAsn1Schema ::= SEQUENCE { schemaName UTF8String, root INTEGER, types SEQUENCE OF TypeDef,
//                                 namedTypes SEQUENCE OF NamedType }
//   TypeDef        ::= SEQUENCE { name UTF8String, kind TypeKind, tagClass TagClass, tag INTEGER,
//                                 optional BOOLEAN, hasDefault BOOLEAN, defaultValue OCTET STRING,
//                                 refName UTF8String OPTIONAL, constraint TypeConstraint,
//                                 children SEQUENCE OF INTEGER }
//   TypeKind       ::= ENUMERATED { ... }     -- one value per Kind
//   TagClass       ::= ENUMERATED { universal, application, context, private }
//   TypeConstraint ::= SEQUENCE { sizeMin INTEGER OPTIONAL, sizeMax INTEGER OPTIONAL,
//                                 valueMin INTEGER OPTIONAL, valueMax INTEGER OPTIONAL,
//                                 namedBits SEQUENCE OF UTF8String OPTIONAL,
//                                 namedNumbers SEQUENCE OF NamedNumber OPTIONAL }
//   NamedNumber    ::= SEQUENCE { name UTF8String, number INTEGER }
//   NamedType      ::= SEQUENCE { name UTF8String, index INTEGER }
// ---------------------------------------------------------------------------------------------

// The meta schema itself, built once and shared.
const Schema &metaSchema();

// Index of every field of the meta schema, used when writing / reading a description.
struct MetaField {
    std::int32_t schemaName = -1;
    std::int32_t root = -1;
    std::int32_t types = -1;
    std::int32_t namedTypes = -1;
    std::int32_t ntName = -1;
    std::int32_t ntIndex = -1;
    std::int32_t tdName = -1;
    std::int32_t tdKind = -1;
    std::int32_t tdTagClass = -1;
    std::int32_t tdTag = -1;
    std::int32_t tdOptional = -1;
    std::int32_t tdHasDefault = -1;
    std::int32_t tdDefaultValue = -1;
    std::int32_t tdRefName = -1;
    std::int32_t tdConstraint = -1;
    std::int32_t tdChildren = -1;
    std::int32_t namedNumber = -1;
    std::int32_t nnName = -1;
    std::int32_t nnNumber = -1;
    std::int32_t cSizeMin = -1;
    std::int32_t cSizeMax = -1;
    std::int32_t cValueMin = -1;
    std::int32_t cValueMax = -1;
    std::int32_t cNamedBits = -1;
    std::int32_t cNamedNumbers = -1;
};

const MetaField &metaFields() noexcept;

// Schema description -> DER and back.
std::vector<std::uint8_t> encodeSchema(const Schema &schema);
Schema decodeSchema(std::span<const std::uint8_t> der);

// ASN.1-like textual rendering of a schema, for logs and debugging.
std::string dumpSchema(const Schema &schema);

}  // namespace asn1detail

#endif //DYNASN1_ASN1SCHEMA_H