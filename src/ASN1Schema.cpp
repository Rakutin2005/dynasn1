//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1Schema.h"

#include <algorithm>
#include <set>
#include <sstream>

#include "dynasn1/ASN1Codec.h"

namespace asn1detail {
namespace {

constexpr std::uint32_t kNoTag = 0;

bool kindIsCollection(Kind kind) noexcept {
    return kind == Kind::sequenceOf || kind == Kind::setOf;
}

bool kindIsMemberContainer(Kind kind) noexcept {
    return kind == Kind::sequence || kind == Kind::set || kind == Kind::choice;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Kinds
// ---------------------------------------------------------------------------------------------

std::uint32_t defaultUniversalTag(Kind kind) noexcept {
    switch (kind) {
        case Kind::boolean: return 1;
        case Kind::integer: return 2;
        case Kind::bitString: return 3;
        case Kind::octetString: return 4;
        case Kind::nullValue: return 5;
        case Kind::objectIdentifier: return 6;
        case Kind::enumerated: return 10;
        case Kind::utf8String: return 12;
        case Kind::sequence:
        case Kind::sequenceOf: return 16;
        case Kind::set:
        case Kind::setOf: return 17;
        case Kind::numericString: return 18;
        case Kind::printableString: return 19;
        case Kind::ia5String: return 22;
        case Kind::utcTime: return 23;
        case Kind::generalizedTime: return 24;
        case Kind::visibleString: return 26;
        case Kind::date: return 31;
        case Kind::timeOfDay: return 32;
        case Kind::dateTime: return 33;
        case Kind::choice:
        case Kind::reference: return kNoTag;
    }
    return kNoTag;
}

bool kindIsConstructed(Kind kind) noexcept {
    switch (kind) {
        case Kind::sequence:
        case Kind::set:
        case Kind::sequenceOf:
        case Kind::setOf:
        case Kind::choice: return true;
        default: return false;
    }
}

const char *kindName(Kind kind) noexcept {
    switch (kind) {
        case Kind::boolean: return "BOOLEAN";
        case Kind::integer: return "INTEGER";
        case Kind::nullValue: return "NULL";
        case Kind::octetString: return "OCTET STRING";
        case Kind::bitString: return "BIT STRING";
        case Kind::utf8String: return "UTF8String";
        case Kind::ia5String: return "IA5String";
        case Kind::printableString: return "PrintableString";
        case Kind::numericString: return "NumericString";
        case Kind::visibleString: return "VisibleString";
        case Kind::utcTime: return "UTCTime";
        case Kind::generalizedTime: return "GeneralizedTime";
        case Kind::objectIdentifier: return "OBJECT IDENTIFIER";
        case Kind::enumerated: return "ENUMERATED";
        case Kind::sequence: return "SEQUENCE";
        case Kind::set: return "SET";
        case Kind::sequenceOf: return "SEQUENCE OF";
        case Kind::setOf: return "SET OF";
        case Kind::choice: return "CHOICE";
        case Kind::reference: return "REFERENCE";
        case Kind::date: return "DATE";
        case Kind::timeOfDay: return "TIME-OF-DAY";
        case Kind::dateTime: return "DATE-TIME";
    }
    return "UNKNOWN";
}

Kind kindFromIndex(std::int64_t index) {
    if (index < 0 || index > static_cast<std::int64_t>(Kind::dateTime))
        throw ASN1SchemaError("schema description contains an unknown type kind " + std::to_string(index));
    return static_cast<Kind>(index);
}

// ---------------------------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------------------------

const Node &Schema::node(std::int32_t index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= nodes.size())
        throw ASN1SchemaError("node " + std::to_string(index) + " does not exist");
    return nodes[static_cast<std::size_t>(index)];
}

std::int32_t Schema::effectiveIndex(std::int32_t index) const {
    if (!effectiveValid || effective.size() != nodes.size())
        throw ASN1Exception("internal error: schema references were not resolved");
    if (index < 0 || static_cast<std::size_t>(index) >= effective.size())
        throw ASN1SchemaError("node index " + std::to_string(index) + " is out of range");
    return effective[static_cast<std::size_t>(index)];
}

void Schema::ensureEffective() const {
    if (effectiveValid && effective.size() == nodes.size()) return;

    const std::size_t count = nodes.size();
    effective.assign(count, -1);

    if (count == 0)
        throw ASN1SchemaError("schema is empty" +
                              (name.empty() ? std::string() : " ('" + name + "')"));
    if (root < 0 || static_cast<std::size_t>(root) >= count)
        throw ASN1SchemaError("schema has no root type" +
                              (name.empty() ? std::string() : " ('" + name + "')"));

    const std::string where = name.empty() ? std::string() : " in schema '" + name + "'";

    // Follow reference chains; a pure reference cycle cannot be resolved.
    for (std::size_t i = 0; i < count; ++i) {
        std::int32_t current = static_cast<std::int32_t>(i);
        std::set<std::int32_t> visited;
        while (nodes[static_cast<std::size_t>(current)].kind == Kind::reference) {
            if (!visited.insert(current).second)
                throw ASN1SchemaError("reference cycle while resolving type '" +
                                      nodes[static_cast<std::size_t>(current)].refName + "'" + where);
            const auto found = named.find(nodes[static_cast<std::size_t>(current)].refName);
            if (found == named.end())
                throw ASN1SchemaError("unknown type reference '" +
                                      nodes[static_cast<std::size_t>(current)].refName + "'" + where);
            current = found->second;
        }
        effective[i] = current;
    }

    for (std::size_t i = 0; i < count; ++i) {
        const Node &node = nodes[i];

        if (node.kind == Kind::choice && node.tagClass == ASN1TagClass::universal &&
            node.tag == kNoTag)
            throw ASN1SchemaError("CHOICE '" + node.name +
                                  "' needs an explicit tag, e.g. tagged(ASN1TagClass::context, 0)" +
                                  where);

        for (const std::int32_t child : node.children) {
            if (child < 0 || static_cast<std::size_t>(child) >= count)
                throw ASN1SchemaError("'" + node.name + "' refers to node " + std::to_string(child) +
                                      " which does not exist" + where);
        }

        switch (node.kind) {
            case Kind::sequenceOf:
            case Kind::setOf:
                if (node.children.size() != 1)
                    throw ASN1SchemaError(std::string(kindName(node.kind)) + " '" + node.name +
                                          "' needs exactly one element type but declares " +
                                          std::to_string(node.children.size()) + where);
                break;
            case Kind::choice:
                if (node.children.empty())
                    throw ASN1SchemaError("CHOICE '" + node.name + "' has no alternatives" + where);
                break;
            case Kind::sequence:
            case Kind::set: {
                std::set<std::string> names;
                for (const std::int32_t child : node.children) {
                    const std::string &childName = nodes[static_cast<std::size_t>(child)].name;
                    if (!names.insert(childName).second)
                        throw ASN1SchemaError(std::string(kindName(node.kind)) + " '" + node.name +
                                              "' declares the field '" + childName + "' twice" + where);
                }
                if (node.kind == Kind::set) {
                    std::set<std::uint64_t> tags;
                    for (const std::int32_t child : node.children) {
                        const Node &childNode = nodes[static_cast<std::size_t>(effective[static_cast<std::size_t>(child)])];
                        const std::uint64_t key =
                                (static_cast<std::uint64_t>(childNode.tagClass) << 32) | childNode.tag;
                        if (!tags.insert(key).second)
                            throw ASN1SchemaError("SET '" + node.name + "' has two components with tag " +
                                                  std::to_string(childNode.tag) + ", which cannot be "
                                                  "decoded unambiguously" + where);
                    }
                }
                break;
            }
            default:
                if (!node.children.empty())
                    throw ASN1SchemaError(std::string(kindName(node.kind)) + " '" + node.name +
                                          "' cannot have members" + where);
                break;
        }

        if (node.constraint.sizeMin && node.constraint.sizeMax &&
            *node.constraint.sizeMin > *node.constraint.sizeMax)
            throw ASN1SchemaError("SIZE constraint of '" + node.name + "' has min > max" + where);
        if (node.constraint.valueMin && node.constraint.valueMax &&
            *node.constraint.valueMin > *node.constraint.valueMax)
            throw ASN1SchemaError("value constraint of '" + node.name + "' has min > max" + where);
    }

    effectiveValid = true;
}

// ---------------------------------------------------------------------------------------------
// SchemaBuilder
// ---------------------------------------------------------------------------------------------

std::int32_t SchemaBuilder::addNode(Node node) {
    if (node.tag == kNoTag && node.tagClass == ASN1TagClass::universal)
        node.tag = defaultUniversalTag(node.kind);
    schema_.nodes.push_back(std::move(node));
    schema_.invalidate();
    return static_cast<std::int32_t>(schema_.nodes.size() - 1);
}

std::int32_t SchemaBuilder::addLeaf(Kind kind, std::string name) {
    Node node;
    node.kind = kind;
    node.name = std::move(name);
    return addNode(std::move(node));
}

std::int32_t SchemaBuilder::addSequence(std::string name) {
    return addLeaf(Kind::sequence, std::move(name));
}

std::int32_t SchemaBuilder::addSet(std::string name) {
    return addLeaf(Kind::set, std::move(name));
}

std::int32_t SchemaBuilder::addChoice(std::string name) {
    return addLeaf(Kind::choice, std::move(name));
}

std::int32_t SchemaBuilder::addList(Kind listKind, std::int32_t element, std::string elementName) {
    const std::int32_t index = addLeaf(listKind, std::move(elementName));
    schema_.nodes[static_cast<std::size_t>(index)].children.push_back(element);
    schema_.invalidate();
    return index;
}

std::int32_t SchemaBuilder::addReference(std::string typeName) {
    Node node;
    node.kind = Kind::reference;
    node.refName = std::move(typeName);
    return addNode(std::move(node));
}

void SchemaBuilder::addChild(std::int32_t parent, std::int32_t child, std::string fieldName) {
    if (parent < 0 || static_cast<std::size_t>(parent) >= schema_.nodes.size())
        throw ASN1SchemaError("cannot add a member to node " + std::to_string(parent) +
                              ", it does not exist");
    if (!fieldName.empty()) schema_.nodes[static_cast<std::size_t>(child)].name = std::move(fieldName);
    schema_.nodes[static_cast<std::size_t>(parent)].children.push_back(child);
    schema_.invalidate();
}

void SchemaBuilder::setOptional(std::int32_t node, bool value) {
    schema_.nodes[static_cast<std::size_t>(node)].optional = value;
    schema_.invalidate();
}

void SchemaBuilder::setDefault(std::int32_t node, ASN1Value value) {
    schema_.nodes[static_cast<std::size_t>(node)].hasDefault = true;
    schema_.nodes[static_cast<std::size_t>(node)].defaultValue = std::move(value);
    schema_.invalidate();
}

void SchemaBuilder::setTag(std::int32_t node, ASN1TagClass tagClass, std::uint32_t tag) {
    schema_.nodes[static_cast<std::size_t>(node)].tagClass = tagClass;
    schema_.nodes[static_cast<std::size_t>(node)].tag = tag;
    schema_.invalidate();
}

void SchemaBuilder::setConstraint(std::int32_t node, Constraint constraint) {
    schema_.nodes[static_cast<std::size_t>(node)].constraint = std::move(constraint);
    schema_.invalidate();
}

void SchemaBuilder::define(std::string typeName, std::int32_t node) {
    if (!schema_.named.emplace(typeName, node).second)
        throw ASN1SchemaError("type '" + typeName + "' is defined twice in schema '" + schema_.name +
                              "'");
    schema_.invalidate();
}

std::int32_t SchemaBuilder::absorb(const Schema &other) {
    const auto base = static_cast<std::int32_t>(schema_.nodes.size());
    schema_.nodes.reserve(schema_.nodes.size() + other.nodes.size());
    for (Node node : other.nodes) {
        for (std::int32_t &child : node.children) child += base;
        if (node.kind == Kind::reference && node.ref >= 0) node.ref += base;
        schema_.nodes.push_back(std::move(node));
    }
    for (const auto &[name, index] : other.named) {
        if (!schema_.named.emplace(name, index + base).second)
            throw ASN1SchemaError("type '" + name + "' is defined both in schema '" + other.name +
                                  "' and in schema '" + schema_.name + "'");
    }
    schema_.invalidate();
    return other.root < 0 ? -1 : other.root + base;
}

Schema SchemaBuilder::release() {
    schema_.invalidate();
    return std::move(schema_);
}

// ---------------------------------------------------------------------------------------------
// Meta schema
// ---------------------------------------------------------------------------------------------

namespace {

Schema buildMetaSchema() {
    SchemaBuilder builder("PqliAsn1Schema");
    MetaField meta;

    // NamedNumber ::= SEQUENCE { name UTF8String, number INTEGER }
    const std::int32_t namedNumber = builder.addSequence("NamedNumber");
    meta.nnName = builder.addLeaf(Kind::utf8String, "name");
    meta.nnNumber = builder.addLeaf(Kind::integer, "number");
    builder.addChild(namedNumber, meta.nnName);
    builder.addChild(namedNumber, meta.nnNumber);

    // Constraint ::= SEQUENCE { sizeMin INTEGER OPTIONAL, sizeMax INTEGER OPTIONAL,
    //                           valueMin INTEGER OPTIONAL, valueMax INTEGER OPTIONAL,
    //                           namedBits SEQUENCE OF UTF8String OPTIONAL,
    //                           namedNumbers SEQUENCE OF NamedNumber OPTIONAL }
    const std::int32_t constraint = builder.addSequence("constraint");
    meta.cSizeMin = builder.addLeaf(Kind::integer, "sizeMin");
    meta.cSizeMax = builder.addLeaf(Kind::integer, "sizeMax");
    meta.cValueMin = builder.addLeaf(Kind::integer, "valueMin");
    meta.cValueMax = builder.addLeaf(Kind::integer, "valueMax");
    meta.cNamedBits = builder.addLeaf(Kind::sequenceOf, "namedBits");
    builder.addChild(meta.cNamedBits, builder.addLeaf(Kind::utf8String), "bit");
    meta.cNamedNumbers = builder.addLeaf(Kind::sequenceOf, "namedNumbers");
    builder.addChild(meta.cNamedNumbers, namedNumber, "NamedNumber");
    for (const std::int32_t member :
         {meta.cSizeMin, meta.cSizeMax, meta.cValueMin, meta.cValueMax, meta.cNamedBits,
          meta.cNamedNumbers})
        builder.setOptional(member);
    // Adjacent OPTIONAL members of the same type would be ambiguous while decoding (a SEQUENCE
    // OF NamedNumber could be mistaken for a SEQUENCE OF UTF8String), so every member gets its
    // own context specific tag.
    builder.setTag(meta.cSizeMin, ASN1TagClass::context, 0);
    builder.setTag(meta.cSizeMax, ASN1TagClass::context, 1);
    builder.setTag(meta.cValueMin, ASN1TagClass::context, 2);
    builder.setTag(meta.cValueMax, ASN1TagClass::context, 3);
    builder.setTag(meta.cNamedBits, ASN1TagClass::context, 4);
    builder.setTag(meta.cNamedNumbers, ASN1TagClass::context, 5);
    builder.addChild(constraint, meta.cSizeMin);
    builder.addChild(constraint, meta.cSizeMax);
    builder.addChild(constraint, meta.cValueMin);
    builder.addChild(constraint, meta.cValueMax);
    builder.addChild(constraint, meta.cNamedBits);
    builder.addChild(constraint, meta.cNamedNumbers);

    // TypeDef ::= SEQUENCE { name UTF8String, kind TypeKind, tagClass TagClass, tag INTEGER,
    //                        optional BOOLEAN, hasDefault BOOLEAN, defaultValue OCTET STRING,
    //                        refName UTF8String OPTIONAL, constraint Constraint,
    //                        children SEQUENCE OF INTEGER }
    const std::int32_t typeDef = builder.addSequence("TypeDef");
    meta.tdName = builder.addLeaf(Kind::utf8String, "name");
    meta.tdKind = builder.addLeaf(Kind::enumerated, "kind");
    builder.setConstraint(meta.tdKind,
                          {{}, {},
                           {},
                           {},
                           {},
                           {{"boolean", static_cast<std::int64_t>(Kind::boolean)},
                            {"integer", static_cast<std::int64_t>(Kind::integer)},
                            {"nullValue", static_cast<std::int64_t>(Kind::nullValue)},
                            {"octetString", static_cast<std::int64_t>(Kind::octetString)},
                            {"bitString", static_cast<std::int64_t>(Kind::bitString)},
                            {"utf8String", static_cast<std::int64_t>(Kind::utf8String)},
                            {"ia5String", static_cast<std::int64_t>(Kind::ia5String)},
                            {"printableString", static_cast<std::int64_t>(Kind::printableString)},
                            {"numericString", static_cast<std::int64_t>(Kind::numericString)},
                            {"visibleString", static_cast<std::int64_t>(Kind::visibleString)},
                            {"utcTime", static_cast<std::int64_t>(Kind::utcTime)},
                            {"generalizedTime", static_cast<std::int64_t>(Kind::generalizedTime)},
                            {"objectIdentifier", static_cast<std::int64_t>(Kind::objectIdentifier)},
                            {"enumerated", static_cast<std::int64_t>(Kind::enumerated)},
                            {"sequence", static_cast<std::int64_t>(Kind::sequence)},
                            {"set", static_cast<std::int64_t>(Kind::set)},
                            {"sequenceOf", static_cast<std::int64_t>(Kind::sequenceOf)},
                            {"setOf", static_cast<std::int64_t>(Kind::setOf)},
                            {"choice", static_cast<std::int64_t>(Kind::choice)},
                            {"date", static_cast<std::int64_t>(Kind::date)},
                            {"timeOfDay", static_cast<std::int64_t>(Kind::timeOfDay)},
                            {"dateTime", static_cast<std::int64_t>(Kind::dateTime)},
                            {"reference", static_cast<std::int64_t>(Kind::reference)}}});
    meta.tdTagClass = builder.addLeaf(Kind::enumerated, "tagClass");
    builder.setConstraint(meta.tdTagClass,
                          {{}, {},
                           {},
                           {},
                           {},
                           {{"universal", static_cast<std::int64_t>(ASN1TagClass::universal)},
                            {"application", static_cast<std::int64_t>(ASN1TagClass::application)},
                            {"context", static_cast<std::int64_t>(ASN1TagClass::context)},
                            {"private", static_cast<std::int64_t>(ASN1TagClass::privateClass)}}});
    meta.tdTag = builder.addLeaf(Kind::integer, "tag");
    meta.tdOptional = builder.addLeaf(Kind::boolean, "optional");
    meta.tdHasDefault = builder.addLeaf(Kind::boolean, "hasDefault");
    meta.tdDefaultValue = builder.addLeaf(Kind::octetString, "defaultValue");
    meta.tdRefName = builder.addLeaf(Kind::utf8String, "refName");
    builder.setOptional(meta.tdRefName);
    meta.tdConstraint = constraint;
    meta.tdChildren = builder.addLeaf(Kind::sequenceOf, "children");
    builder.addChild(meta.tdChildren, builder.addLeaf(Kind::integer), "index");

    for (const std::int32_t member :
         {meta.tdName, meta.tdKind, meta.tdTagClass, meta.tdTag, meta.tdOptional, meta.tdHasDefault,
          meta.tdDefaultValue, meta.tdRefName, meta.tdConstraint, meta.tdChildren})
        builder.addChild(typeDef, member);

    // PqliAsn1Schema ::= SEQUENCE { schemaName UTF8String, root INTEGER, types SEQUENCE OF TypeDef,
    //                               namedTypes SEQUENCE OF NamedType }
    const std::int32_t namedType = builder.addSequence("NamedType");
    meta.ntName = builder.addLeaf(Kind::utf8String, "name");
    meta.ntIndex = builder.addLeaf(Kind::integer, "index");
    builder.addChild(namedType, meta.ntName);
    builder.addChild(namedType, meta.ntIndex);
    meta.namedTypes = builder.addLeaf(Kind::sequenceOf, "namedTypes");
    builder.addChild(meta.namedTypes, namedType, "NamedType");

    const std::int32_t root = builder.addSequence("PqliAsn1Schema");
    meta.schemaName = builder.addLeaf(Kind::utf8String, "schemaName");
    meta.root = builder.addLeaf(Kind::integer, "root");
    meta.types = builder.addLeaf(Kind::sequenceOf, "types");
    builder.addChild(meta.types, typeDef, "TypeDef");
    builder.addChild(root, meta.schemaName);
    builder.addChild(root, meta.root);
    builder.addChild(root, meta.types);
    builder.addChild(root, meta.namedTypes);

    Schema schema = builder.release();
    schema.root = root;
    schema.ensureEffective();
    return schema;
}

}  // namespace

const Schema &metaSchema() {
    static const Schema schema = buildMetaSchema();
    return schema;
}

const MetaField &metaFields() noexcept {
    // The meta schema never changes, so its field indices are read back from the node table once.
    static const MetaField fields = [] {
        const Schema &schema = metaSchema();
        MetaField meta;

        const Node &root = schema.node(schema.root);
        meta.schemaName = root.children[0];
        meta.root = root.children[1];
        meta.types = root.children[2];
        meta.namedTypes = root.children[3];

        const Node &namedType = schema.node(schema.node(meta.namedTypes).children.front());
        meta.ntName = namedType.children[0];
        meta.ntIndex = namedType.children[1];

        const Node &typeDef = schema.node(schema.node(root.children[2]).children.front());
        meta.tdName = typeDef.children[0];
        meta.tdKind = typeDef.children[1];
        meta.tdTagClass = typeDef.children[2];
        meta.tdTag = typeDef.children[3];
        meta.tdOptional = typeDef.children[4];
        meta.tdHasDefault = typeDef.children[5];
        meta.tdDefaultValue = typeDef.children[6];
        meta.tdRefName = typeDef.children[7];
        meta.tdConstraint = typeDef.children[8];
        meta.tdChildren = typeDef.children[9];

        const Node &constraint = schema.node(meta.tdConstraint);
        meta.cSizeMin = constraint.children[0];
        meta.cSizeMax = constraint.children[1];
        meta.cValueMin = constraint.children[2];
        meta.cValueMax = constraint.children[3];
        meta.cNamedBits = constraint.children[4];
        meta.cNamedNumbers = constraint.children[5];

        const Node &namedNumber = schema.node(schema.node(meta.cNamedNumbers).children.front());
        meta.namedNumber = meta.cNamedNumbers;
        meta.nnName = namedNumber.children[0];
        meta.nnNumber = namedNumber.children[1];
        return meta;
    }();
    return fields;
}

// ---------------------------------------------------------------------------------------------
// Schema description -> DER
// ---------------------------------------------------------------------------------------------

namespace {

ASN1Value constraintValue(const Constraint &constraint) {
    ASN1Value::Sequence fields;

    // min and max are always written together so that the description stays unambiguous.
    if (constraint.sizeMin || constraint.sizeMax) {
        fields.push_back({"sizeMin", ASN1Value(constraint.sizeMin ? *constraint.sizeMin : 0)});
        fields.push_back(
                {"sizeMax", ASN1Value(constraint.sizeMax ? *constraint.sizeMax : *constraint.sizeMin)});
    }
    if (constraint.valueMin || constraint.valueMax) {
        fields.push_back({"valueMin", ASN1Value(constraint.valueMin ? *constraint.valueMin : 0)});
        fields.push_back(
                {"valueMax", ASN1Value(constraint.valueMax ? *constraint.valueMax : *constraint.valueMin)});
    }
    if (!constraint.namedBits.empty()) {
        ASN1Value::List bits;
        bits.reserve(constraint.namedBits.size());
        for (const std::string &bit : constraint.namedBits) bits.push_back(ASN1Value(bit));
        fields.push_back({"namedBits", ASN1Value(std::move(bits))});
    }
    if (!constraint.namedNumbers.empty()) {
        ASN1Value::List numbers;
        numbers.reserve(constraint.namedNumbers.size());
        for (const NamedNumber &number : constraint.namedNumbers) {
            ASN1Value::Sequence entry;
            entry.push_back({"name", ASN1Value(number.name)});
            entry.push_back({"number", ASN1Value(number.number)});
            numbers.push_back(ASN1Value(std::move(entry)));
        }
        fields.push_back({"namedNumbers", ASN1Value(std::move(numbers))});
    }
    return ASN1Value(std::move(fields));
}

ASN1Value typeDefValue(const Schema &schema, std::int32_t index) {
    const Node &node = schema.node(index);

    // A default value is stored as the DER of the value itself, encoded against this node.
    std::vector<std::uint8_t> encodedDefault;
    if (node.hasDefault) {
        if (node.kind == Kind::reference)
            throw ASN1SchemaError("a referenced type cannot carry a default value");
        encodedDefault = encodeNode(schema, index, node.defaultValue);
    }

    ASN1Value::List children;
    children.reserve(node.children.size());
    for (const std::int32_t child : node.children)
        children.push_back(ASN1Value(static_cast<std::int64_t>(child)));

    ASN1Value::Sequence fields;
    fields.reserve(10);
    fields.push_back({"name", ASN1Value(node.name)});
    fields.push_back({"kind", ASN1Value(static_cast<std::int64_t>(node.kind))});
    fields.push_back({"tagClass", ASN1Value(static_cast<std::int64_t>(node.tagClass))});
    fields.push_back({"tag", ASN1Value(static_cast<std::int64_t>(node.tag))});
    fields.push_back({"optional", ASN1Value(node.optional)});
    fields.push_back({"hasDefault", ASN1Value(node.hasDefault)});
    fields.push_back({"defaultValue", ASN1Value(std::move(encodedDefault))});
    if (!node.refName.empty()) fields.push_back({"refName", ASN1Value(node.refName)});
    fields.push_back({"constraint", constraintValue(node.constraint)});
    fields.push_back({"children", ASN1Value(std::move(children))});
    return ASN1Value(std::move(fields));
}

}  // namespace

std::vector<std::uint8_t> encodeSchema(const Schema &schema) {
    schema.ensureEffective();
    (void)metaFields();

    ASN1Value::List types;
    types.reserve(schema.nodes.size());
    for (std::size_t i = 0; i < schema.nodes.size(); ++i)
        types.push_back(typeDefValue(schema, static_cast<std::int32_t>(i)));

    // Sorted by name, so that the binary form of one description is always byte identical.
    ASN1Value::List namedTypes;
    namedTypes.reserve(schema.named.size());
    for (const auto &[name, index] : schema.named) {
        ASN1Value::Sequence entry;
        entry.push_back({"name", ASN1Value(name)});
        entry.push_back({"index", ASN1Value(static_cast<std::int64_t>(index))});
        namedTypes.push_back(ASN1Value(std::move(entry)));
    }
    std::sort(namedTypes.begin(), namedTypes.end(),
              [](const ASN1Value &lhs, const ASN1Value &rhs) {
                  return lhs.asSequence().front().value.asString() <
                         rhs.asSequence().front().value.asString();
              });

    ASN1Value::Sequence root;
    root.push_back({"schemaName", ASN1Value(schema.name)});
    root.push_back({"root", ASN1Value(static_cast<std::int64_t>(schema.root))});
    root.push_back({"types", ASN1Value(std::move(types))});
    root.push_back({"namedTypes", ASN1Value(std::move(namedTypes))});

    return encodeNode(metaSchema(), metaSchema().root, ASN1Value(std::move(root)));
}

// ---------------------------------------------------------------------------------------------
// DER -> Schema description
// ---------------------------------------------------------------------------------------------

namespace {

std::int64_t requireInteger(const ASN1Value &value, const char *what) {
    if (const auto *v = value.getIf<std::int64_t>()) return *v;
    if (const auto *v = value.getIf<std::uint64_t>())
        return static_cast<std::int64_t>(*v);
    throw ASN1SchemaError(std::string("schema description field '") + what + "' is not an INTEGER");
}

std::int32_t nodeIndex(const ASN1Value &value, const char *what) {
    const std::int64_t index = requireInteger(value, what);
    if (index < 0 || index > 0x7FFFFFFF)
        throw ASN1SchemaError(std::string("schema description field '") + what +
                              "' is not a valid node index");
    return static_cast<std::int32_t>(index);
}

const ASN1Field &field(const ASN1Value::Sequence &fields, const char *name) {
    for (const ASN1Field &entry : fields) {
        if (entry.name == name) return entry;
    }
    throw ASN1SchemaError(std::string("schema description has no field '") + name + "'");
}

bool boolField(const ASN1Value::Sequence &fields, const char *name) {
    const auto *value = field(fields, name).value.getIf<bool>();
    if (!value)
        throw ASN1SchemaError(std::string("schema description field '") + name + "' is not a BOOLEAN");
    return *value;
}

Constraint constraintFrom(const ASN1Value::Sequence &fields) {
    Constraint constraint;
    for (const ASN1Field &entry : fields) {
        if (entry.name == "sizeMin") {
            constraint.sizeMin = requireInteger(entry.value, "sizeMin");
        } else if (entry.name == "sizeMax") {
            constraint.sizeMax = requireInteger(entry.value, "sizeMax");
        } else if (entry.name == "valueMin") {
            constraint.valueMin = requireInteger(entry.value, "valueMin");
        } else if (entry.name == "valueMax") {
            constraint.valueMax = requireInteger(entry.value, "valueMax");
        } else if (entry.name == "namedBits") {
            for (const ASN1Value &item : entry.value.asList())
                constraint.namedBits.push_back(item.asString());
        } else if (entry.name == "namedNumbers") {
            for (const ASN1Value &item : entry.value.asList()) {
                const ASN1Value::Sequence &number = item.asSequence();
                constraint.namedNumbers.push_back({field(number, "name").value.asString(),
                                                   requireInteger(field(number, "number").value, "number")});
            }
        }
    }
    return constraint;
}

}  // namespace

Schema decodeSchema(std::span<const std::uint8_t> der) {
    const ASN1Value root = decodeRoot(metaSchema(), der, "PqliAsn1Schema");
    const ASN1Value::Sequence &rootFields = root.asSequence();

    Schema schema;
    schema.name = field(rootFields, "schemaName").value.asString();
    schema.root = nodeIndex(field(rootFields, "root").value, "root");

    // Default values are DER blobs that need the finished node table, so they are decoded in a
    // second pass.
    std::vector<std::vector<std::uint8_t>> rawDefaults;

    for (const ASN1Value &item : field(rootFields, "types").value.asList()) {
        const ASN1Value::Sequence &fields = item.asSequence();

        Node node;
        node.name = field(fields, "name").value.asString();
        node.kind = kindFromIndex(requireInteger(field(fields, "kind").value, "kind"));
        node.tagClass =
                static_cast<ASN1TagClass>(requireInteger(field(fields, "tagClass").value, "tagClass"));
        node.tag = static_cast<std::uint32_t>(requireInteger(field(fields, "tag").value, "tag"));
        node.optional = boolField(fields, "optional");
        node.hasDefault = boolField(fields, "hasDefault");
        node.constraint = constraintFrom(field(fields, "constraint").value.asSequence());

        for (const ASN1Field &entry : fields) {
            if (entry.name == "refName") {
                node.refName = entry.value.asString();
            } else if (entry.name == "children") {
                for (const ASN1Value &child : entry.value.asList())
                    node.children.push_back(nodeIndex(child, "children"));
            } else if (entry.name == "defaultValue") {
                rawDefaults.emplace_back(entry.value.asOctets());
            }
        }

        if (node.hasDefault && node.kind == Kind::reference)
            throw ASN1SchemaError("a referenced type cannot carry a default value");

        schema.nodes.push_back(std::move(node));
    }

    schema.invalidate();

    // The registry of named types is what turns a flat node table into a self describing
    // description again: references are resolved against it.
    const auto namedTypes = std::find_if(rootFields.begin(), rootFields.end(),
                                         [](const ASN1Field &entry) {
                                             return entry.name == "namedTypes";
                                         });
    if (namedTypes != rootFields.end()) {
        for (const ASN1Value &item : namedTypes->value.asList()) {
            const ASN1Value::Sequence &entry = item.asSequence();
            const std::string name = field(entry, "name").value.asString();
            if (!schema.named.emplace(name, nodeIndex(field(entry, "index").value, "index")).second)
                throw ASN1SchemaError("schema description defines the type '" + name + "' twice");
        }
    }

    for (std::size_t i = 0; i < schema.nodes.size(); ++i) {
        if (!schema.nodes[i].hasDefault) continue;
        if (rawDefaults[i].empty())
            throw ASN1SchemaError("node '" + schema.nodes[i].name +
                                  "' declares a default value but carries none");
        schema.nodes[i].defaultValue = decodeNode(schema, static_cast<std::int32_t>(i), rawDefaults[i],
                                                   "default of " + schema.nodes[i].name);
    }

    schema.invalidate();
    schema.notation.assign(der.begin(), der.end());
    schema.stale = false;
    schema.ensureEffective();
    return schema;
}

// ---------------------------------------------------------------------------------------------
// Textual rendering
// ---------------------------------------------------------------------------------------------

namespace {

std::string constraintText(const Constraint &constraint) {
    std::string text;
    const auto bound = [](const std::optional<std::int64_t> &value) {
        return value ? std::to_string(*value) : std::string("MAX");
    };
    if (constraint.sizeMin || constraint.sizeMax)
        text += " (SIZE (" + (constraint.sizeMin ? std::to_string(*constraint.sizeMin) : std::string("0")) +
               ".." + bound(constraint.sizeMax) + "))";
    if (constraint.valueMin || constraint.valueMax)
        text += " (" + (constraint.valueMin ? std::to_string(*constraint.valueMin) : std::string("MIN")) +
               ".." + bound(constraint.valueMax) + ")";
    if (!constraint.namedBits.empty()) {
        text += " { ";
        for (std::size_t i = 0; i < constraint.namedBits.size(); ++i) {
            if (i) text += ", ";
            text += constraint.namedBits[i] + " (" + std::to_string(i) + ")";
        }
        text += " }";
    }
    if (!constraint.namedNumbers.empty()) {
        text += " { ";
        for (std::size_t i = 0; i < constraint.namedNumbers.size(); ++i) {
            if (i) text += ", ";
            text += constraint.namedNumbers[i].name + " (" +
                    std::to_string(constraint.namedNumbers[i].number) + ")";
        }
        text += " }";
    }
    return text;
}

std::string tagClassShortName(ASN1TagClass cls) {
    switch (cls) {
        case ASN1TagClass::universal: return "UNIVERSAL";
        case ASN1TagClass::application: return "APPLICATION";
        case ASN1TagClass::context: return "CONTEXT";
        case ASN1TagClass::privateClass: return "PRIVATE";
    }
    return "UNKNOWN";
}

std::string typeText(const Node &node) {
    std::string text;
    const std::uint32_t universal = defaultUniversalTag(node.kind);
    if (node.tagClass == ASN1TagClass::universal) {
        if (node.tag != universal) text += "[" + std::to_string(node.tag) + "] ";
    } else if (node.tag == 0) {
        text += "[" + tagClassShortName(node.tagClass) + "] ";
    } else {
        text += "[" + tagClassShortName(node.tagClass) + " " + std::to_string(node.tag) + "] ";
    }
    // A collection prints as "SEQUENCE OF X" / "SET OF X", so only the container word belongs here.
    switch (node.kind) {
        case Kind::sequenceOf:
        case Kind::setOf: text += node.kind == Kind::sequenceOf ? "SEQUENCE" : "SET"; break;
        default: text += kindName(node.kind); break;
    }
    text += constraintText(node.constraint);
    return text;
}

// Renders one type. References are printed by name, which is what makes recursive schemas
// terminate here.
std::string renderType(const Schema &schema, std::int32_t index, const std::string &indent,
                       std::set<std::int32_t> &active) {
    const Node &raw = schema.node(index);
    if (raw.kind == Kind::reference) return raw.refName;

    const std::int32_t effective = schema.effectiveIndex(index);
    const Node &node = schema.node(effective);
    if (!kindIsCollection(node.kind) && !kindIsMemberContainer(node.kind)) return typeText(node);

    if (!active.insert(effective).second) return node.name.empty() ? "<recursive>" : node.name;

    std::string text;
    if (kindIsCollection(node.kind)) {
        text = typeText(node) + " OF " + renderType(schema, node.children.front(), indent, active);
    } else {
        text = typeText(node) + " {\n";
        const std::string inner = indent + "    ";
        for (std::size_t i = 0; i < node.children.size(); ++i) {
            const std::int32_t childIndex = node.children[i];
            const Node &child = schema.node(childIndex);
            text += inner;
            text += child.name.empty() ? "" : child.name + " ";
            text += renderType(schema, childIndex, inner, active);
            if (node.kind != Kind::choice && schema.node(childIndex).optional) text += " OPTIONAL";
            if (i + 1 < node.children.size()) text += ",";
            text += "\n";
        }
        text += indent + "}";
    }

    active.erase(effective);
    return text;
}

}  // namespace

std::string dumpSchema(const Schema &schema) {
    schema.ensureEffective();

    std::ostringstream out;

    // Sorted, so that two identical descriptions dump identically.
    std::vector<std::pair<std::string, std::int32_t>> named(schema.named.begin(), schema.named.end());
    std::sort(named.begin(), named.end());

    std::vector<std::int32_t> order;
    std::set<std::int32_t> emitted;
    for (const auto &[typeName, index] : named) {
        if (emitted.insert(index).second) order.push_back(index);
    }
    if (schema.root >= 0 && emitted.insert(schema.root).second) order.push_back(schema.root);

    for (const std::int32_t index : order) {
        std::string typeName = schema.name.empty() ? "Root" : schema.name;
        for (const auto &[candidate, defined] : named) {
            if (defined == index) {
                typeName = candidate;
                break;
            }
        }
        std::set<std::int32_t> active;
        out << typeName << " ::= " << renderType(schema, index, "", active) << "\n\n";
    }
    return out.str();
}

}  // namespace asn1detail