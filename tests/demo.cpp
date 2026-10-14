//
// Created by aigol on 10/14/26.
//
// Round trip demo for the dynamic ASN.1 builder: build a description, encode an instance to
// DER, decode it again and compare.
//

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

namespace {

int failures = 0;

void check(bool condition, const std::string &what) {
    if (condition) {
        std::cout << "  ok    " << what << "\n";
        return;
    }
    ++failures;
    std::cout << "  FAIL  " << what << "\n";
}

template <class Callable> void checkThrows(Callable &&call, const std::string &what) {
    try {
        call();
    } catch (const ASN1Exception &) {
        std::cout << "  ok    " << what << "\n";
        return;
    } catch (const std::exception &error) {
        ++failures;
        std::cout << "  FAIL  " << what << " (wrong exception: " << error.what() << ")\n";
        return;
    }
    ++failures;
    std::cout << "  FAIL  " << what << " (nothing was thrown)\n";
}

std::string hex(const std::vector<std::uint8_t> &data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (i) out << ' ';
        out << std::setw(2) << static_cast<int>(data[i]);
    }
    return out.str();
}

// A recursive named type, the reason the node table is indexed instead of being a tree.
ASN1 buildProcedureSchema() {
    ASN1 procedure = ASN1::sequence("Procedure");
    procedure.field("name", ASN1::utf8String().withSize(1, 32));
    procedure.field("weight", ASN1::integer().withRange(0, 1'000'000));
    procedure.field("clauses", ASN1::sequenceOf(ASN1::reference("Clause")));

    ASN1 clause = ASN1::sequence("Clause");
    clause.field("guard", ASN1::boolean());
    clause.field("target", ASN1::reference("Clause").optional());
    clause.field("amount", ASN1::octetString().withSize(0, 64));

    ASN1 schema = ASN1::sequence("ExecutionPlan");
    schema.named("Clause", clause);
    schema.named("Procedure", procedure);
    schema.field("procedure", ASN1::reference("Procedure"));
    schema.field("version", ASN1::integer().withDefault(1));
    schema.field("origin", ASN1::objectIdentifier());
    schema.field("issuedAt", ASN1::generalizedTime());
    schema.field("flags", ASN1::bitString().withNamedBits({"readable", "writable", "executable"}));
    return schema;
}

void demoBasics() {
    std::cout << "\n== flat structure, encode and decode ==\n";

    ASN1 request = ASN1::sequence("TransferRequest");
    request.field("id", ASN1::integer().withRange(0, 1'000'000));
    request.field("memo", ASN1::utf8String().optional().withSize(0, 64));
    request.field("urgent", ASN1::boolean());
    request.field("amount", ASN1::integer());
    request.field("payload", ASN1::octetString().optional());
    request.field("tags", ASN1::sequenceOf(ASN1::utf8String()).withSize(0, 8));

    std::cout << request.dump();

    ASN1Instance instance = request.getInstance();
    instance.set("id", 4711);
    instance.set("urgent", true);
    instance.set("amount", -1234567890123LL);
    instance.set("memo", "invoice #7");
    instance.set("tags", ASN1Value::List{ASN1Value("alpha"), ASN1Value("beta")});

    const std::vector<std::uint8_t> der = instance.getDER();
    std::cout << "  DER (" << der.size() << " bytes): " << hex(der) << "\n";
    check(instance.encodedSize() == der.size(), "encodedSize() matches the produced DER");
    check(instance.getDER() == der, "encoding is deterministic");

    const ASN1Instance decoded = ASN1Instance::decode(request, der);
    check(decoded.get("id").asInteger() == 4711, "INTEGER survives the round trip");
    check(decoded.get("urgent").asBoolean(), "BOOLEAN survives the round trip");
    check(decoded.get("amount").asInteger() == -1234567890123LL, "negative INTEGER survives");
    check(decoded.get("memo").asString() == "invoice #7", "UTF8String survives");
    check(!decoded.has("payload"), "an absent OPTIONAL field stays absent");
    check(decoded.get("tags").asList().size() == 2, "SEQUENCE OF survives");
    check(decoded.get("tags").asList()[1].asString() == "beta", "SEQUENCE OF order is preserved");

    checkThrows([&] { instance.get("payload"); }, "reading an unset field throws");
    checkThrows([&] { instance.set("unknown", 1); }, "setting an unknown field throws");
    checkThrows([&] { instance.set("id", "text"); }, "setting a wrong C++ type throws");

    ASN1Instance partial = request.getInstance();
    partial.set("id", 1);
    checkThrows([&] { partial.getDER(); }, "a missing required field fails the encoding");
    partial.set("urgent", false);
    partial.set("amount", 1);
    partial.set("tags", ASN1Value::List{});
    check(partial.getDER().size() > 0, "an OPTIONAL field is simply left out");
    check(!ASN1Instance::decode(request, partial.getDER()).has("payload"),
          "the decoded value has no OPTIONAL field that was left out");

    checkThrows([&] { ASN1 bad = ASN1::choice("Ambiguous"); bad.getInstance(); },
                "a CHOICE without a tag is rejected");
}

void demoNotation() {
    std::cout << "\n== the description in binary form ==\n";

    const ASN1 schema = buildProcedureSchema();
    const std::vector<std::uint8_t> &notation = schema.notation();
    std::cout << "  notation (" << notation.size() << " bytes): " << hex(notation) << "\n";

    const ASN1 restored = ASN1::fromNotation(notation);
    check(restored == schema, "notation round trips into an equal description");
    check(restored.dump() == schema.dump(), "the restored description dumps identically");

    // Everything below runs against the restored description only, which proves that the binary
    // form carries the whole description and not just the parts used by the builder.
    ASN1Instance instance = restored.getInstance();
    instance.set("version", 3);
    instance.set("origin", ASN1Oid("1.3.6.1.4.1.99999.1"));
    instance.set("issuedAt", std::chrono::system_clock::time_point{std::chrono::seconds{1'700'000'000}});
    ASN1BitString flags;
    flags.append(true);
    flags.append(false);
    flags.append(true);
    instance.set("flags", flags);
    ASN1Value::List clauses = {
            // The recursive field "target" holds a whole Clause again, here one level deeper.
            ASN1Value::Sequence{
                    ASN1Field{"guard", ASN1Value(true)},
                    ASN1Field{"target", ASN1Value::Sequence{
                                                  ASN1Field{"guard", ASN1Value(false)},
                                                  ASN1Field{"amount", ASN1Value(std::vector<std::uint8_t>{9})}}},
                    ASN1Field{"amount", ASN1Value(std::vector<std::uint8_t>{1, 2, 3})}}};
    instance.set("procedure", ASN1Value::Sequence{
                                      ASN1Field{"name", ASN1Value("settle")},
                                      ASN1Field{"weight", ASN1Value(100)},
                                      ASN1Field{"clauses", ASN1Value(std::move(clauses))}});

    const std::vector<std::uint8_t> der = instance.getDER();
    std::cout << "  DER (" << der.size() << " bytes): " << hex(der) << "\n";

    const ASN1Instance decoded = ASN1Instance::decode(restored, der);
    check(decoded.get("version").asInteger() == 3, "DEFAULT value is encoded when nothing was set");
    check(decoded.get("origin").asOid().toString() == "1.3.6.1.4.1.99999.1", "OBJECT IDENTIFIER survives");
    check(decoded.get("issuedAt").asTime() ==
                      std::chrono::system_clock::time_point{std::chrono::seconds{1'700'000'000}},
          "GeneralizedTime survives");
    check(decoded.get("flags").asBits().bitCount == 3, "BIT STRING survives");

    const ASN1Value::Sequence &procedure = decoded.get("procedure").asSequence();
    check(procedure[0].value.asString() == "settle", "named field keeps its name");
    const ASN1Value::List &clauseList = procedure[2].value.asList();
    const ASN1Value::Sequence &clause = clauseList[0].asSequence();
    check(clause[0].value.asBoolean(), "nested BOOLEAN survives");
    check(clause[2].value.asOctets().size() == 3, "nested OCTET STRING survives");
    const ASN1Value::Sequence &inner = clause[1].value.asSequence();
    check(inner.size() == 2 && inner[1].name == "amount",
          "the recursive member is decoded again one level deeper");
}

void demoConstraints() {
    std::cout << "\n== constraints and error reporting ==\n";

    ASN1 schema = ASN1::sequence("Constrained");
    schema.field("state", ASN1::enumerated("State", {{"created", 0}, {"settled", 1}, {"failed", 2}}));
    schema.field("count", ASN1::integer().withRange(1, 10));
    schema.field("tags", ASN1::setOf(ASN1::integer()).withSize(1, 3));

    ASN1Instance instance = schema.getInstance();
    instance.set("count", 5);
    instance.set("tags", ASN1Value::List{ASN1Value(3), ASN1Value(1)});
    instance.set("state", 1);

    const std::vector<std::uint8_t> der = instance.getDER();
    std::cout << "  DER: " << hex(der) << "\n";

    const ASN1Instance decoded = ASN1Instance::decode(schema, der);
    const ASN1Value::List &tags = decoded.get("tags").asList();
    check(tags.size() == 2 && tags[0].asInteger() == 1 && tags[1].asInteger() == 3,
          "SET OF is sorted by its encoding");

    checkThrows([&] { instance.set("count", 99); }, "value range constraint is enforced");
    checkThrows([&] { instance.set("state", 7); }, "named numbers are enforced");
    checkThrows([&] {
        ASN1Instance tooMany = schema.getInstance();
        tooMany.set("count", 1);
        tooMany.set("state", 0);
        tooMany.set("tags", ASN1Value::List{ASN1Value(1), ASN1Value(2), ASN1Value(3), ASN1Value(4)});
        tooMany.getDER();
    },
                 "SIZE constraint is enforced");

    // A SET OF that is not sorted is not canonical DER.
    std::vector<std::uint8_t> unsorted = {0x31, 0x09, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    checkThrows([&] { (void)ASN1Instance::decode(schema, unsorted); },
                "a SET OF that is not sorted is rejected");

    // Non minimal length encoding: 0x81 0x02 instead of 0x02.
    std::vector<std::uint8_t> nonMinimal = {0x30, 0x81, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    checkThrows([&] { (void)ASN1Instance::decode(schema, nonMinimal); },
                "a non-minimal length is rejected");

    std::vector<std::uint8_t> trailing = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00};
    checkThrows([&] { (void)ASN1Instance::decode(schema, trailing); },
                "trailing data is rejected");

    try {
        (void)ASN1Instance::decode(schema, nonMinimal);
    } catch (const ASN1DecodeError &error) {
        std::cout << "  note: decode error -> offset " << error.offset() << ", path '" << error.path()
                  << "'\n";
    }
}

void demoChoice() {
    std::cout << "\n== CHOICE, SET, DEFAULT and copies ==\n";

    ASN1 schema = ASN1::sequence("Outcome");
    ASN1 choice = ASN1::choice("Result").tagged(ASN1TagClass::context, 0);
    choice.alternative("nothing", ASN1::nullValue());
    choice.alternative("number", ASN1::integer());
    choice.alternative("text", ASN1::printableString());
    schema.field("result", choice);
    ASN1 source = ASN1::set("Source");
    source.field("host", ASN1::utf8String());
    source.field("port", ASN1::integer());
    schema.field("source", source);
    schema.field("role", ASN1::utf8String().withDefault("reader"));

    std::cout << schema.dump();

    ASN1Instance instance = schema.getInstance();
    instance.set("result", ASN1Choice{{ASN1ChoiceEntry{"text", ASN1Value("done")}}});
    ASN1Value::Sequence sourceFields;
    sourceFields.push_back({"host", ASN1Value("localhost")});
    sourceFields.push_back({"port", ASN1Value(8080)});
    instance.set("source", ASN1Value(std::move(sourceFields)));

    const std::vector<std::uint8_t> der = instance.getDER();
    std::cout << "  DER: " << hex(der) << "\n";

    const ASN1Instance decoded = ASN1Instance::decode(schema, der);
    check(decoded.get("result").choiceTag() == "text", "the chosen alternative is identified");
    check(decoded.get("result").choiceValue().asString() == "done", "the alternative value survives");
    check(decoded.get("role").asString() == "reader", "DEFAULT value is encoded when unset");

    // A SET is encoded with its members sorted by tag, no matter how they were set.
    const ASN1Value::Sequence &setFields = decoded.get("source").asSequence();
    check(setFields.size() == 2 && setFields[0].name == "port",
          "SET members are sorted by tag while decoding");

    // Copy on write: the instance keeps the description it was built from.
    ASN1 extended = schema;
    extended.field("extra", ASN1::integer());
    check(!extended.getInstance().has("extra"), "copies are independent");
    check(instance.get("result").choiceTag() == "text", "the existing instance is unaffected");
    checkThrows([&] { (void)ASN1Instance::decode(extended, der); },
                "decoding with a description that declares more required fields is rejected");
}

// Builds a TLV header for the given universal tag and content length, so that the test can
// assemble encodings that the builder would never produce.
std::vector<std::uint8_t> header(std::uint8_t tag, std::size_t length) {
    std::vector<std::uint8_t> out{tag};
    if (length < 0x80) {
        out.push_back(static_cast<std::uint8_t>(length));
        return out;
    }
    std::vector<std::uint8_t> bytes;
    for (std::size_t rest = length; rest != 0; rest >>= 8) bytes.push_back(static_cast<std::uint8_t>(rest));
    out.push_back(static_cast<std::uint8_t>(0x80u | bytes.size()));
    out.insert(out.end(), bytes.rbegin(), bytes.rend());
    return out;
}

std::vector<std::uint8_t> wrap(std::uint8_t tag, const std::vector<std::uint8_t> &content) {
    std::vector<std::uint8_t> out = header(tag, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// Wraps `content` into one more recursive Chain level: value, then next.
std::vector<std::uint8_t> chainLevel(const std::vector<std::uint8_t> &inner) {
    std::vector<std::uint8_t> content = {0x02, 0x01, 0x01};
    content.insert(content.end(), inner.begin(), inner.end());
    return wrap(0x30, content);
}

void demoWideIntegers() {
    std::cout << "\n== integers of any width ==\n";

    ASN1 transfer = ASN1::sequence("Transfer");
    transfer.field("id", ASN1::integer().withRange(0, 1'000'000));
    transfer.field("amount", ASN1::integer());
    transfer.field("fee", ASN1::integer());

    ASN1Instance instance = transfer.getInstance();
    instance.set("id", 4711);
    // A hundred digit amount, far outside what 64 bits can hold.
    const std::string amount = "123456789012345678901234567890123456789012345678901234567890"
                               "1234567890123456789012345678901234567890";
    const std::string fee = "-99999999999999999999";
    instance.set("amount", ASN1BigInt::fromDecimal(amount));
    instance.set("fee", ASN1BigInt::fromDecimal(fee));

    const std::vector<std::uint8_t> der = instance.getDER();
    const ASN1Instance back = ASN1Instance::decode(transfer, der);
    check(back.get("amount").type() == ASN1Value::Type::bigInteger,
          "a value wider than 64 bits is carried as ASN1BigInt");
    check(back.get("amount").asBigInt().toDecimal() == amount, "a hundred digit amount survives");
    check(back.get("fee").asBigInt().toDecimal() == fee, "a negative amount survives");
    check(back.getDER() == der, "re-encoding a wide integer reproduces the same octets");
    check(back.get("id").asInteger() == 4711, "a narrow value stays narrow");

    // The textual form is stable in both directions.
    check(ASN1BigInt::fromDecimal("-0").isZero(), "'-0' is zero, there is no negative zero");
    check(ASN1BigInt::fromDecimal("+42").toDecimal() == "42", "a leading plus is accepted");
    checkThrows([] { (void)ASN1BigInt::fromDecimal("12a"); }, "a stray letter is rejected");
    checkThrows([] { (void)ASN1BigInt::fromDecimal(""); }, "an empty integer is rejected");
    checkThrows([] { (void)ASN1BigInt::fromDecimal("-"); }, "a sign without digits is rejected");
    checkThrows([] { (void)ASN1BigInt::fromDecimal(std::string(5000, '9')); },
                "an absurdly long integer is rejected");

    // Comparison and narrowing.
    check(ASN1BigInt::fromDecimal("-1") < ASN1BigInt::fromDecimal("0"), "a negative is below zero");
    check(ASN1BigInt::fromDecimal("-5") < ASN1BigInt::fromDecimal("-4"),
          "negative values compare by magnitude");
    check(ASN1BigInt::fromDecimal("1") < ASN1BigInt::fromDecimal("100000000000000000000"),
          "a wider positive is larger");
    check(ASN1BigInt::fromDecimal("9223372036854775807").fitsInInt64(), "the largest int64 fits");
    check(!ASN1BigInt::fromDecimal("9223372036854775808").fitsInInt64(),
          "one past the largest int64 does not");
    checkThrows([] { (void)ASN1BigInt::fromDecimal("9223372036854775808").toInt64(); },
                "narrowing a wide value out of range is refused");

    // The canonical form is the shortest two's complement, which is what the decoder demands.
    check(ASN1BigInt::fromDecimal("127").octetCount() == 1, "127 needs one octet");
    check(ASN1BigInt::fromDecimal("128").octetCount() == 2, "128 needs two octets");
    check(ASN1BigInt::fromDecimal("-128").octetCount() == 1, "-128 needs one octet");
    check(ASN1BigInt::fromDecimal("-129").octetCount() == 2, "-129 needs two octets");
    check(ASN1BigInt::fromDecimal("-32768").octetCount() == 2, "-2^15 needs two octets");
    check(ASN1BigInt::fromDecimal("-65536").octetCount() == 3, "-2^16 needs three octets");

    // The 512 octet ceiling, applied on both sides so that a round trip cannot disagree.
    std::string wide = "1";
    for (int bit = 0; bit < 4090; ++bit) {
        std::string next;
        int carry = 0;
        for (std::size_t i = wide.size(); i-- > 0;) {
            const int digit = (wide[i] - '0') * 2 + carry;
            next.push_back(static_cast<char>('0' + digit % 10));
            carry = digit / 10;
        }
        if (carry) next.push_back(static_cast<char>('0' + carry));
        std::reverse(next.begin(), next.end());
        wide = next;
    }
    ASN1Instance wideInstance = transfer.getInstance();
    wideInstance.set("id", 1);
    wideInstance.set("fee", 0);
    wideInstance.set("amount", ASN1BigInt::fromDecimal(wide));
    check(ASN1Instance::decode(transfer, wideInstance.getDER())
                          .get("amount")
                          .asBigInt()
                          .toDecimal() == wide,
          "a 4091 bit value survives a round trip");

    checkThrows(
            [&] {
                ASN1Instance over = transfer.getInstance();
                over.set("id", 1);
                over.set("fee", 0);
                over.set("amount", ASN1BigInt::fromDecimal(wide + "00"));
            },
            "a value past the 512 octet ceiling is refused");

    // A description with a 64 bit range cannot hold a wider value.
    ASN1 bounded = ASN1::sequence("Bounded").field("n", ASN1::integer().withRange(0, 100));
    ASN1Instance boundedInstance = bounded.getInstance();
    boundedInstance.set("n", ASN1BigInt::fromDecimal("50"));
    check(!boundedInstance.getDER().empty(), "a wide value inside the range encodes");
    checkThrows([&] { boundedInstance.set("n", ASN1BigInt::fromDecimal("200")); },
                "a wide value outside the range is refused");
}

void demoNanosecondTime() {
    std::cout << "\n== timestamps with a fraction of a second ==\n";

    ASN1 event = ASN1::sequence("Event");
    event.field("issuedAt", ASN1::generalizedTime());
    event.field("archivedAt", ASN1::utcTime());

    ASN1Instance instance = event.getInstance();
    instance.set("issuedAt",
                 std::chrono::system_clock::time_point(std::chrono::nanoseconds(1765432212123456789LL)));
    instance.set("archivedAt",
                 std::chrono::system_clock::time_point(std::chrono::seconds(1700000000)));

    const std::vector<std::uint8_t> der = instance.getDER();
    const std::string text(der.begin(), der.end());
    check(text.find("20251211055012.123456789Z") != std::string::npos,
          "a nanosecond timestamp is written with all nine digits");
    check(text.find("231114221320Z") != std::string::npos, "a UTCTime stays whole seconds");

    const ASN1Instance back = ASN1Instance::decode(event, der);
    check(back.get("issuedAt").asTime() ==
                  std::chrono::system_clock::time_point(
                          std::chrono::nanoseconds(1765432212123456789LL)),
          "the nanosecond part survives the round trip");

    // The fraction is written with as few digits as it needs, per X.690 11.7.4.
    struct {
        std::int64_t nanoseconds;
        const char *expected;
    } const cases[] = {
            {0, "19700101000000Z"},
            {100000000, "19700101000000.1Z"},
            {500000000, "19700101000000.5Z"},
            {123456789, "19700101000000.123456789Z"},
            {1500000000, "19700101000001.5Z"},
            {1, "19700101000000.000000001Z"},
    };
    bool allAsExpected = true;
    for (const auto &entry : cases) {
        ASN1 single = ASN1::sequence("S").field("t", ASN1::generalizedTime());
        ASN1Instance one = single.getInstance();
        one.set("t", std::chrono::system_clock::time_point(
                             std::chrono::nanoseconds(entry.nanoseconds)));
        const std::vector<std::uint8_t> encoded = one.getDER();
        const std::size_t length = std::strlen(entry.expected);
        if (std::string(encoded.end() - static_cast<long>(length), encoded.end()) != entry.expected)
            allAsExpected = false;
    }
    check(allAsExpected, "the fraction carries no trailing zeros and is omitted when zero");

    // Before the epoch the fraction stays positive and the date goes below 1970.
    ASN1Instance before = event.getInstance();
    before.set("issuedAt", std::chrono::system_clock::time_point(std::chrono::nanoseconds(-1)));
    before.set("archivedAt", std::chrono::system_clock::time_point(std::chrono::seconds(0)));
    const std::vector<std::uint8_t> early = before.getDER();
    check(std::string(early.begin() + 4, early.begin() + 29) == "19691231235959.999999999Z",
          "one nanosecond before the epoch");
}

void demoFixedSizeMaterial() {
    std::cout << "\n== digests, signatures and keys ==\n";

    ASN1 envelope = ASN1::sequence("Envelope");
    envelope.field("digest", ASN1::octetString().withExactSize(32));
    envelope.field("signature", ASN1::octetString().withExactSize(64));

    std::vector<std::uint8_t> digestBytes(32), signatureBytes(64);
    for (std::size_t i = 0; i < digestBytes.size(); ++i)
        digestBytes[i] = static_cast<std::uint8_t>(i * 7 + 1);
    for (std::size_t i = 0; i < signatureBytes.size(); ++i)
        signatureBytes[i] = static_cast<std::uint8_t>(i * 3 + 5);

    ASN1Instance instance = envelope.getInstance();
    instance.set("digest", ASN1Digest(digestBytes));
    instance.set("signature", ASN1Signature(signatureBytes));

    const std::vector<std::uint8_t> der = instance.getDER();
    const ASN1Instance back = ASN1Instance::decode(envelope, der);
    check(back.get("digest").asOctets() == digestBytes, "a digest round trips");
    check(back.get("signature").asOctets() == signatureBytes, "a signature round trips");
    check(der.size() == 2 + 34 + 66, "fixed size material costs only its own length");

    // The type carries the width, so a mistake is caught before it reaches the wire.
    checkThrows([&] { (void)ASN1Digest(std::vector<std::uint8_t>(31, 0)); },
                "a digest of the wrong width is refused at construction");
    checkThrows([&] { (void)ASN1Signature(std::vector<std::uint8_t>(48, 0)); },
                "a signature of the wrong width is refused at construction");

    // The description enforces it on the wire as well.
    checkThrows(
            [&] {
                ASN1Instance wrong = envelope.getInstance();
                wrong.set("digest", ASN1Value(std::vector<std::uint8_t>(31, 0)));
                wrong.set("signature", ASN1Signature(signatureBytes));
            },
            "a digest that does not match withExactSize(32) is refused when encoding");

    // A value that is too narrow is rejected while decoding, before anything is used.
    std::vector<std::uint8_t> body;
    body.push_back(0x04);
    body.push_back(31);
    body.insert(body.end(), 31, 0xAB);
    body.push_back(0x04);
    body.push_back(64);
    body.insert(body.end(), signatureBytes.begin(), signatureBytes.end());
    std::vector<std::uint8_t> wrapped{0x30, static_cast<std::uint8_t>(body.size())};
    wrapped.insert(wrapped.end(), body.begin(), body.end());
    checkThrows([&] { (void)ASN1Instance::decode(envelope, wrapped); },
                "a decoded digest of the wrong width is rejected");

    std::cout << envelope.dump();
}

void demoNonCanonicalTime() {
    std::cout << "\n== times that DER does not allow ==\n";

    ASN1 schema = ASN1::sequence("S").field("t", ASN1::generalizedTime());

    // A fraction with trailing zeros, a comma, ten digits, a missing Z, an offset, an impossible
    // date: all of these are BER that DER forbids.
    const char *rejected[] = {
            "19700101000000.50Z", "19700101000000,5Z", "19700101000000.1234567891Z",
            "19700101000000.Z",   "19700101000000",     "19700101000000+0100",
            "19701301000000Z",    "19700230000000Z",    "19700229000000Z",
            "19700101246000Z",    "1970010100000aZ",
    };
    int slipped = 0;
    for (const char *text : rejected) {
        const std::string content(text);
        std::vector<std::uint8_t> inner{0x18, static_cast<std::uint8_t>(content.size())};
        inner.insert(inner.end(), content.begin(), content.end());
        std::vector<std::uint8_t> der{0x30, static_cast<std::uint8_t>(inner.size())};
        der.insert(der.end(), inner.begin(), inner.end());
        try {
            (void)ASN1Instance::decode(schema, der);
            ++slipped;
        } catch (const ASN1Exception &) {
        }
    }
    check(slipped == 0, "non canonical or impossible times are rejected (" +
                                 std::to_string(slipped) + " slipped through)");

    // UTCTime covers 1950..2049 and carries no fraction.
    ASN1 utc = ASN1::sequence("S").field("t", ASN1::utcTime());
    ASN1Instance tooEarly = utc.getInstance();
    checkThrows([&] { tooEarly.set("t", std::chrono::system_clock::time_point(
                                            std::chrono::seconds(7258118400))); },
                "UTCTime outside 1950..2049 is refused");

    const std::string text = "231114221320.5Z";
    std::vector<std::uint8_t> withFraction{0x17, static_cast<std::uint8_t>(text.size())};
    withFraction.insert(withFraction.end(), text.begin(), text.end());
    std::vector<std::uint8_t> wrapped{0x30, static_cast<std::uint8_t>(withFraction.size())};
    wrapped.insert(wrapped.end(), withFraction.begin(), withFraction.end());
    checkThrows([&] { (void)ASN1Instance::decode(utc, wrapped); },
                "a fraction in UTCTime is rejected");
}
void demoHardening() {
    std::cout << "\n== long forms, depth limits and malformed input ==\n";

    ASN1 schema = ASN1::sequence("Big");
    schema.field("blob", ASN1::octetString());
    schema.field("items", ASN1::sequenceOf(ASN1::integer()));

    ASN1Instance instance = schema.getInstance();
    instance.set("blob", ASN1Value(std::vector<std::uint8_t>(700, 0xAB)));
    ASN1Value::List items;
    for (std::int64_t i = 0; i < 40; ++i) items.push_back(ASN1Value(i * 1000));
    instance.set("items", ASN1Value(std::move(items)));

    const std::vector<std::uint8_t> der = instance.getDER();
    check(der[1] == 0x82, "lengths above 127 use the long form");
    const ASN1Instance decoded = ASN1Instance::decode(schema, der);
    check(decoded.get("blob").asOctets().size() == 700, "a 700 byte OCTET STRING survives");
    check(decoded.get("items").asList().size() == 40, "a 40 element SEQUENCE OF survives");
    check(decoded.getDER() == der, "re-encoding a decoded value reproduces the same bytes");

    // A description of a self referencing type: the encoder and the decoder both have to stop.
    ASN1 link = ASN1::sequence("Chain");
    link.field("value", ASN1::integer());
    link.field("next", ASN1::reference("Chain").optional());
    ASN1 chainSchema = ASN1::sequence("Root");
    chainSchema.named("Chain", link);
    chainSchema.field("head", ASN1::reference("Chain"));

    // The innermost Chain carries only "value"; every further level wraps it into "next", and the
    // whole thing is wrapped once more into the outer Root.
    std::vector<std::uint8_t> deep = wrap(0x30, {0x02, 0x01, 0x01});
    for (int level = 0; level < 500; ++level) deep = chainLevel(deep);
    deep = wrap(0x30, deep);  // the outer Root SEQUENCE
    checkThrows([&] { (void)ASN1Instance::decode(chainSchema, deep); },
                "deeply nested input is rejected instead of exhausting the stack");

    std::vector<std::uint8_t> shallow = wrap(0x30, {0x02, 0x01, 0x01});
    for (int level = 0; level < 3; ++level) shallow = chainLevel(shallow);
    shallow = wrap(0x30, shallow);  // the outer Root SEQUENCE
    const ASN1Instance chain = ASN1Instance::decode(chainSchema, shallow);
    const ASN1Value::Sequence &c1 = chain.get("head").asSequence();
    const ASN1Value::Sequence &c2 = c1.at(1).value.asSequence();
    const ASN1Value::Sequence &c3 = c2.at(1).value.asSequence();
    const ASN1Value::Sequence &c4 = c3.at(1).value.asSequence();
    check(c1.at(0).value.asInteger() == 1 && c2.at(0).value.asInteger() == 1 &&
                  c3.at(0).value.asInteger() == 1 && c4.at(0).value.asInteger() == 1 && c4.size() == 1,
          "a shallow recursive value decodes level by level");

    // Malformed encodings, each of which must be rejected with a decode error.
    ASN1 simple = ASN1::sequence("Simple");
    simple.field("flag", ASN1::boolean());
    simple.field("text", ASN1::utf8String());

    const auto bytes = [](std::initializer_list<int> values) {
        std::vector<std::uint8_t> out;
        out.reserve(values.size());
        for (const int value : values) out.push_back(static_cast<std::uint8_t>(value));
        return out;
    };
    const std::vector<std::vector<std::uint8_t>> rejected = {
            bytes({0x30, 0x80, 0x01, 0x01, 0xff, 0x0c, 0x00}),             // indefinite length
            bytes({0x30, 0x81, 0x00}),                                     // non-minimal long form
            bytes({0x30, 0x06, 0x01, 0x01, 0x01, 0x0c, 0x00}),             // BOOLEAN that is not 0x00/0xFF
            bytes({0x30, 0x07, 0x0c, 0x02, 0xc3, 0x28, 0x01, 0x01, 0xff}), // invalid UTF-8
            bytes({0x30, 0x05, 0x0c, 0x01, 0x41, 0x01, 0x01, 0xff}),       // text where a BOOLEAN belongs
            bytes({0x30, 0x03, 0x01, 0x01, 0xff}),                         // a member is missing
            bytes({0x30, 0x07, 0x01, 0x01, 0xff, 0x0c, 0x01, 0x41, 0x00}), // one octet too much
    };
    for (const auto &bad : rejected) {
        checkThrows([&] { (void)ASN1Instance::decode(simple, bad); },
                    "malformed input is rejected");
    }

    // Every truncation of a valid encoding must be rejected, never crash.
    ASN1Instance sample = simple.getInstance();
    sample.set("flag", true);
    sample.set("text", "hello");
    const std::vector<std::uint8_t> valid = sample.getDER();
    int accepted = 0;
    for (std::size_t cut = 0; cut < valid.size(); ++cut) {
        const std::span<const std::uint8_t> truncated(valid.data(), cut);
        try {
            (void)ASN1Instance::decode(simple, truncated);
            ++accepted;
        } catch (const ASN1Exception &) {
        }
    }
    check(accepted == 0, "every truncated encoding is rejected (" + std::to_string(accepted) +
                             " slipped through)");

    // std::any carriers, for callers that keep their values in one.
    ASN1Instance any = schema.getInstance();
    checkThrows([&] { any.setAny("items", std::any(std::vector<std::int64_t>{})); },
                "a std::any without ASN.1 counterpart is rejected");
    checkThrows([&] { any.setAny("blob", std::any(3.5)); }, "a std::any without ASN.1 type is rejected");
    checkThrows([&] { any.setAny("blob", std::any(std::string("text"))); },
                "a std::any of the wrong type is rejected");
    any.setAny("blob", std::any(std::vector<std::uint8_t>{1, 2, 3}));
    check(any.get("blob").asOctets().size() == 3, "setAny() accepts a supported std::any");
}

}  // namespace

int main() {
    try {
        demoBasics();
        demoNotation();
        demoConstraints();
        demoChoice();
        demoWideIntegers();
        demoNanosecondTime();
        demoFixedSizeMaterial();
        demoNonCanonicalTime();
        demoHardening();
    } catch (const ASN1Exception &error) {
        std::cout << "\nunexpected ASN.1 error: " << error.what() << "\n";
        return 1;
    }

    std::cout << "\n" << (failures == 0 ? "all checks passed" : "FAILURES: " + std::to_string(failures))
              << "\n";
    return failures == 0 ? 0 : 1;
}