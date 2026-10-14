//
// Created by aigol on 10/14/26.
//

#include "dynasn1/ASN1Instance.h"

#include <algorithm>
#include <typeinfo>

#include "dynasn1/ASN1Codec.h"
#include "dynasn1/ASN1Schema.h"

using asn1detail::Kind;
using asn1detail::Node;
using asn1detail::Schema;

namespace {

// Bridges a std::any onto ASN1Value for the carriers the module understands.
ASN1Value anyToValue(const std::any &value) {
    if (!value.has_value()) return ASN1Value(nullptr);
    if (value.type() == typeid(ASN1Value)) return std::any_cast<ASN1Value>(value);
    if (value.type() == typeid(bool)) return ASN1Value(std::any_cast<bool>(value));
    if (value.type() == typeid(std::int8_t)) return ASN1Value(std::int64_t(std::any_cast<std::int8_t>(value)));
    if (value.type() == typeid(std::int16_t)) return ASN1Value(std::int64_t(std::any_cast<std::int16_t>(value)));
    if (value.type() == typeid(std::int32_t)) return ASN1Value(std::int64_t(std::any_cast<std::int32_t>(value)));
    if (value.type() == typeid(std::int64_t)) return ASN1Value(std::any_cast<std::int64_t>(value));
    if (value.type() == typeid(std::uint8_t)) return ASN1Value(std::uint64_t(std::any_cast<std::uint8_t>(value)));
    if (value.type() == typeid(std::uint16_t)) return ASN1Value(std::uint64_t(std::any_cast<std::uint16_t>(value)));
    if (value.type() == typeid(std::uint32_t)) return ASN1Value(std::uint64_t(std::any_cast<std::uint32_t>(value)));
    if (value.type() == typeid(std::uint64_t)) return ASN1Value(std::any_cast<std::uint64_t>(value));
    if (value.type() == typeid(std::string)) return ASN1Value(std::any_cast<const std::string &>(value));
    if (value.type() == typeid(std::string_view))
        return ASN1Value(std::any_cast<std::string_view>(value));
    if (value.type() == typeid(const char *)) return ASN1Value(std::any_cast<const char *>(value));
    if (value.type() == typeid(std::vector<std::uint8_t>))
        return ASN1Value(std::any_cast<const std::vector<std::uint8_t> &>(value));
    if (value.type() == typeid(ASN1BitString))
        return ASN1Value(std::any_cast<const ASN1BitString &>(value));
    if (value.type() == typeid(ASN1Oid)) return ASN1Value(std::any_cast<const ASN1Oid &>(value));
    if (value.type() == typeid(std::chrono::system_clock::time_point))
        return ASN1Value(std::any_cast<std::chrono::system_clock::time_point>(value));

    throw ASN1ValueError("std::any holds '" + std::string(value.type().name()) +
                         "', which has no ASN.1 counterpart; wrap it into an ASN1Value first");
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------

ASN1Instance::ASN1Instance(std::shared_ptr<const ASN1> schema) : schema_(std::move(schema)) {
    if (!schema_ || !schema_->valid())
        throw ASN1SchemaError("an ASN.1 instance needs a description with a root type");

    const Schema &internal = schema_->internal();
    internal.ensureEffective();
    const std::int32_t root = internal.effectiveIndex(internal.root);
    const Node &node = internal.node(root);

    // The value of a SEQUENCE / SET starts out as an empty field list; anything else starts as
    // the zero value of its type.
    if (node.kind == Kind::sequence || node.kind == Kind::set)
        value_ = ASN1Value(ASN1Value::Sequence{});
    else if (node.kind == Kind::sequenceOf || node.kind == Kind::setOf)
        value_ = ASN1Value(ASN1Value::List{});
    else if (node.kind == Kind::choice)
        value_ = ASN1Value(ASN1Value::Choice{});
    else
        value_ = ASN1Value(nullptr);
}

ASN1Instance::ASN1Instance(const ASN1 &schema)
    : ASN1Instance(std::make_shared<const ASN1>(schema)) {}

void ASN1Instance::requireFields() const {
    if (!schema_) throw ASN1SchemaError("this ASN.1 instance has no description");
    const Schema &internal = schema_->internal();
    internal.ensureEffective();
    const Node &node = internal.node(internal.effectiveIndex(internal.root));
    if (node.kind != Kind::sequence && node.kind != Kind::set)
        throw ASN1ValueError("'" + schema_->name() +
                             "' is a " + asn1detail::kindName(node.kind) + ", it has no named fields");
}

ASN1Value::Sequence &ASN1Instance::mutableFields() {
    requireFields();
    invalidate();
    auto *fields = value_.getIf<ASN1Value::Sequence>();
    if (!fields) value_ = ASN1Value(ASN1Value::Sequence{});
    return *value_.getIf<ASN1Value::Sequence>();
}

// ---------------------------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------------------------

void ASN1Instance::set(std::string_view fieldName, ASN1Value value) {
    const Schema &internal = schema_->internal();
    internal.ensureEffective();
    const Node &root = internal.node(internal.effectiveIndex(internal.root));
    if (root.kind != Kind::sequence && root.kind != Kind::set)
        throw ASN1ValueError("'" + schema_->name() + "' is a " + asn1detail::kindName(root.kind) +
                             ", it has no named fields");

    std::size_t slot = 0;
    for (; slot < root.children.size(); ++slot) {
        // The field name belongs to the declared member, which may be a reference.
        if (internal.node(root.children[slot]).name == fieldName) break;
    }
    if (slot == root.children.size())
        throw ASN1ValueError("'" + schema_->name() + "' has no field named '" + std::string(fieldName) +
                             "'");

    // Encode the value on its own first: this checks the type, the constraints and the nesting
    // depth, and it means a bad value never reaches the instance.
    asn1detail::encodeNode(internal, root.children[slot], value);

    ASN1Value::Sequence &fields = mutableFields();
    for (ASN1Field &entry : fields) {
        if (entry.name != fieldName) continue;
        entry.value = std::move(value);
        return;
    }

    // Members are kept in schema order, whatever order they were set in, so that the value tree
    // and its DER encoding agree.
    std::size_t before = 0;
    while (before < fields.size()) {
        std::size_t other = 0;
        for (; other < root.children.size(); ++other) {
            if (internal.node(root.children[other]).name == fields[before].name) break;
        }
        if (other > slot) break;
        ++before;
    }
    fields.insert(fields.begin() + static_cast<std::ptrdiff_t>(before), {std::string(fieldName), std::move(value)});
}

void ASN1Instance::setAny(std::string_view field, const std::any &value) {
    set(field, ASN1Value(anyToValue(value)));
}

const ASN1Value &ASN1Instance::get(std::string_view field) const {
    if (const ASN1Value *found = find(field)) return *found;
    throw ASN1ValueError("field '" + std::string(field) + "' is not set");
}

const ASN1Value *ASN1Instance::find(std::string_view field) const {
    if (!schema_) return nullptr;
    const auto *fields = value_.getIf<ASN1Value::Sequence>();
    if (!fields) return nullptr;
    for (const ASN1Field &entry : *fields) {
        if (entry.name == field) return &entry.value;
    }
    return nullptr;
}

bool ASN1Instance::has(std::string_view field) const { return find(field) != nullptr; }

void ASN1Instance::unset(std::string_view field) {
    ASN1Value::Sequence &fields = mutableFields();
    const auto entry = std::find_if(fields.begin(), fields.end(),
                                    [&](const ASN1Field &candidate) { return candidate.name == field; });
    if (entry == fields.end())
        throw ASN1ValueError("field '" + std::string(field) + "' is not set");
    fields.erase(entry);
}

std::vector<std::string> ASN1Instance::fields() const {
    std::vector<std::string> names;
    if (!schema_) return names;
    const Schema &internal = schema_->internal();
    internal.ensureEffective();
    const Node &root = internal.node(internal.effectiveIndex(internal.root));
    names.reserve(root.children.size());
    for (const std::int32_t child : root.children) names.push_back(internal.node(child).name);
    return names;
}

// ---------------------------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------------------------

void ASN1Instance::encodeTo(std::vector<std::uint8_t> &out) const {
    if (!schema_) throw ASN1SchemaError("this ASN.1 instance has no description");
    const Schema &internal = schema_->internal();
    asn1detail::DerWriter writer(out);
    asn1detail::encodeValue(writer, internal, internal.root, value_);
}

std::vector<std::uint8_t> ASN1Instance::getDER() const {
    if (!schema_) throw ASN1SchemaError("this ASN.1 instance has no description");
    if (cacheValid_) return der_;

    const Schema &internal = schema_->internal();
    std::vector<std::uint8_t> buffer;
    buffer.reserve(asn1detail::encodedSize(internal, internal.root, value_));
    asn1detail::DerWriter writer(buffer);
    asn1detail::encodeValue(writer, internal, internal.root, value_);

    der_ = std::move(buffer);
    cacheValid_ = true;
    return der_;
}

std::size_t ASN1Instance::encodedSize() const {
    if (!schema_) throw ASN1SchemaError("this ASN.1 instance has no description");
    return asn1detail::encodedSize(schema_->internal(), schema_->internal().root, value_);
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

ASN1Instance ASN1Instance::decode(std::shared_ptr<const ASN1> schema,
                                  std::span<const std::uint8_t> der) {
    ASN1Instance instance(std::move(schema));
    instance.value_ = asn1detail::decodeRoot(instance.schema_->internal(), der);
    instance.invalidate();
    return instance;
}

ASN1Instance ASN1Instance::decode(const ASN1 &schema, std::span<const std::uint8_t> der) {
    return decode(std::make_shared<const ASN1>(schema), der);
}

// ---------------------------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------------------------

const ASN1 &ASN1Instance::schema() const {
    if (!schema_) throw ASN1SchemaError("this ASN.1 instance has no description");
    return *schema_;
}

bool ASN1Instance::operator==(const ASN1Instance &rhs) const {
    if (bool(schema_) != bool(rhs.schema_)) return false;
    if (schema_ && schema_->notation() != rhs.schema_->notation()) return false;
    return value_ == rhs.value_;
}