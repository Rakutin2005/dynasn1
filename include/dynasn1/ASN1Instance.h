//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1INSTANCE_H
#define DYNASN1_ASN1INSTANCE_H

#include <any>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Exception.h"
#include "dynasn1/ASN1Value.h"

class ASN1;

// One value of a dynamically built ASN.1 type.
//
// The instance keeps a const pointer to the description it was created from, so it can encode
// itself into DER and, in the other direction, be reconstructed from DER. The description is a
// snapshot: later changes to the builder do not affect instances that already exist.
class ASN1Instance {
public:
    ASN1Instance() = default;
    explicit ASN1Instance(std::shared_ptr<const ASN1> schema);
    explicit ASN1Instance(const ASN1 &schema);

    // --- building ----------------------------------------------------------------------------

    // Sets a field of the top level SEQUENCE / SET. Throws ASN1ValueError when the field is not
    // declared, when the C++ type does not fit the ASN.1 type of the field, or when a constraint
    // of that field is violated. Members are stored in the order the description declares them,
    // whatever order they are set in.
    //
    //   instance.set("id", 42);                  // INTEGER
    //   instance.set("memo", "invoice");         // UTF8String
    //   instance.set("ok", true);                // BOOLEAN
    //   instance.set("payload", bytes);          // OCTET STRING
    void set(std::string_view field, ASN1Value value);

    // Same as set(), for callers that keep their values in a std::any. Supported carriers are the
    // types ASN1Value is constructible from; anything else raises ASN1ValueError.
    void setAny(std::string_view field, const std::any &value);

    // Typed convenience, equivalent to set() with an explicit cast.
    template <class T> void setAs(std::string_view field, const T &value) {
        set(field, ASN1Value(value));
    }

    bool has(std::string_view field) const;
    void unset(std::string_view field);

    // Reads a field; throws ASN1ValueError when it is not set. The reference stays valid until
    // the field is changed, so nested access does not copy.
    const ASN1Value &get(std::string_view field) const;

    // Reads a field, nullptr when it is not set.
    const ASN1Value *find(std::string_view field) const;

    // Typed convenience.
    template <class T> T getAs(std::string_view field) const { return get(field).as<T>(); }

    // --- DER ---------------------------------------------------------------------------------

    // Canonical DER encoding of the value. The result is cached until the value changes; the
    // returned buffer is a copy, so it may be moved or modified freely.
    std::vector<std::uint8_t> getDER() const;

    // Appends the DER encoding to `out`, avoiding a temporary buffer.
    void encodeTo(std::vector<std::uint8_t> &out) const;

    // Exact size getDER() would return.
    std::size_t encodedSize() const;

    // --- decoding ----------------------------------------------------------------------------

    // Reads a complete DER message for the given description. Strict DER only: definite minimal
    // lengths, canonical SET ordering, minimal INTEGERs. Errors carry the byte offset and the
    // path of the field that failed.
    static ASN1Instance decode(const ASN1 &schema, std::span<const std::uint8_t> der);
    static ASN1Instance decode(std::shared_ptr<const ASN1> schema, std::span<const std::uint8_t> der);
    static ASN1Instance decode(const ASN1 &schema, const std::vector<std::uint8_t> &der) {
        return decode(schema, std::span<const std::uint8_t>(der.data(), der.size()));
    }

    // --- inspection --------------------------------------------------------------------------

    const ASN1 &schema() const;
    std::shared_ptr<const ASN1> schemaRef() const noexcept { return schema_; }

    // The complete value tree; a SEQUENCE / SET is a Sequence of named fields.
    const ASN1Value &value() const noexcept { return value_; }
    ASN1Value &value() noexcept { invalidate(); return value_; }

    // Field names in schema order.
    std::vector<std::string> fields() const;

    bool empty() const noexcept { return !schema_; }

    bool operator==(const ASN1Instance &rhs) const;

private:
    friend class ASN1;

    void invalidate() const noexcept { cacheValid_ = false; }
    void requireFields() const;
    ASN1Value::Sequence &mutableFields();

    std::shared_ptr<const ASN1> schema_;
    ASN1Value value_;

    // Encoding is deterministic, so the result can be reused until the value changes.
    mutable std::vector<std::uint8_t> der_;
    mutable bool cacheValid_ = false;
};

#endif //DYNASN1_ASN1INSTANCE_H