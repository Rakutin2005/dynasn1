//
// Created by aigol on 10/14/26.
//

#ifndef DYNASN1_ASN1EXCEPTION_H
#define DYNASN1_ASN1EXCEPTION_H

#include <cstddef>
#include <stdexcept>
#include <string>

// Base of every error raised by the ASN.1 module.
class ASN1Exception : public std::runtime_error {
public:
    explicit ASN1Exception(const std::string &what) : std::runtime_error(what) {}
};

// The schema itself is malformed: unknown reference, missing tag, duplicate field name, ...
class ASN1SchemaError : public ASN1Exception {
public:
    explicit ASN1SchemaError(const std::string &what) : ASN1Exception(what) {}
};

// A value does not match the schema it is used with (wrong C++ type, constraint violated,
// required field never set, ...).
class ASN1ValueError : public ASN1Exception {
public:
    explicit ASN1ValueError(const std::string &what) : ASN1Exception(what) {}
};

// Malformed or non-canonical DER input. Carries the byte offset of the problem and the
// dotted path of the field being decoded, e.g. "TransferRequest.header.signature".
class ASN1DecodeError : public ASN1Exception {
public:
    explicit ASN1DecodeError(std::string what, std::size_t offset = 0, std::string path = {})
        : ASN1Exception(describe(std::move(what), offset, path)),
          offset_(offset),
          path_(std::move(path)) {}

    // Absolute offset inside the buffer that was passed to the decoder.
    std::size_t offset() const noexcept { return offset_; }

    // Field path, empty when the failure happened on the root value.
    const std::string &path() const noexcept { return path_; }

private:
    static std::string describe(const std::string &what, std::size_t offset, const std::string &path) {
        std::string text = what;
        text += " at offset " + std::to_string(offset);
        if (!path.empty()) text += " of field '" + path + "'";
        return text;
    }

    std::size_t offset_;
    std::string path_;
};

#endif //DYNASN1_ASN1EXCEPTION_H