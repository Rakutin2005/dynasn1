// What the choices cost in the domain that matters: financial amounts, sub-second timestamps,
// and the tag that carries the alias. DER against JSON and XML on the same records.
#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

using namespace std::chrono;

namespace {

// ---------------------------------------------------------------------------------------------
// The records under test
// ---------------------------------------------------------------------------------------------

// A plain record, no aliases: the cost baseline.
ASN1 plainRecord() {
    ASN1 r = ASN1::sequence("Plain");
    r.field("id", ASN1::integer());
    r.field("amount", ASN1::integer());
    r.field("fee", ASN1::integer());
    r.field("issuedAt", ASN1::generalizedTime());
    r.field("contact", ASN1::utf8String());
    r.field("signature", ASN1::octetString().withExactSize(64));
    return r;
}

// The same record with every field carrying an alias tag, which is what a policy dispatches on.
ASN1 taggedRecord() {
    ASN1 r = ASN1::sequence("Tagged");
    r.field("id", ASN1::integer());
    r.field("amount", ASN1::integer());
    r.field("fee", ASN1::integer());
    r.field("issuedAt", ASN1::generalizedTime());
    r.field("contact", ASN1::utf8String().tagged(ASN1TagClass::application, 1));
    r.field("signature", ASN1::octetString().withExactSize(64));
    return r;
}

void fill(ASN1Instance &i, bool wide) {
    i.set("id", 4711);
    if (wide)
        i.set("amount", ASN1BigInt::fromDecimal(
                             "123456789012345678901234567890123456789012345678901234567890"));
    else
        i.set("amount", 987654321LL);
    i.set("fee", -19999LL);
    i.set("issuedAt", system_clock::time_point(nanoseconds(1765432212123456789LL)));
    i.set("contact", std::string("ivanov@bank.ru"));
    std::vector<std::uint8_t> sig(64, 0xA5);
    i.set("signature", ASN1Signature(sig));
}

// The same records as JSON and as XML, written the way a typical integration would.
std::string asJson(bool wide, bool fractional) {
    std::string amount = wide ? "\"123456789012345678901234567890123456789012345678901234567890\""
                              : "987654321";
    std::string stamp = fractional ? "\"2025-12-12T03:03:32.123456789Z\"" : "\"2025-12-12T03:03:32Z\"";
    return "{\"id\":4711,\"amount\":" + amount +
           ",\"fee\":-19999,\"issuedAt\":" + stamp +
           ",\"contact\":\"ivanov@bank.ru\",\"signature\":\"" +
           std::string(64 * 4 / 3 + 8, 'A') + "\"}";
}

std::string asXml(bool fractional) {
    return std::string("<r><id>4711</id><amount>987654321</amount><fee>-19999</fee><issuedAt>") +
           (fractional ? "2025-12-12T03:03:32.123456789Z" : "2025-12-12T03:03:32Z") +
           "</issuedAt><contact>ivanov@bank.ru</contact><signature>" + std::string(88, 'A') +
           "</signature></r>";
}

std::size_t encoded(const ASN1 &schema) {
    ASN1Instance i = schema.getInstance();
    fill(i, false);
    return i.getDER().size();
}

std::size_t encodedWide(const ASN1 &schema) {
    ASN1Instance i = schema.getInstance();
    fill(i, true);
    return i.getDER().size();
}

// Encode/decode of the same value, averaged.
template <class F> long timeIt(F &&f, int rounds = 200000) {
    const auto start = steady_clock::now();
    for (int i = 0; i < rounds; ++i) f();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(steady_clock::now() - start)
                   .count() /
           rounds;
}

}  // namespace

int main() {
    const ASN1 plain = plainRecord();
    const ASN1 tagged = taggedRecord();

    std::printf("== size of one record, bytes ==\n");
    std::printf("%-46s %5s %5s %5s\n", "record", "DER", "JSON", "XML");

    const std::size_t derPlain = encoded(plain);
    const std::size_t derTagged = encoded(tagged);
    std::printf("%-46s %5zu %5zu %5zu\n", "64 bit amount, whole seconds, plain string",
                derPlain, asJson(false, false).size(), asXml(false).size());
    std::printf("%-46s %5zu %5zu %5zu\n", "64 bit amount, nanoseconds, plain string",
                derPlain, asJson(false, true).size(), asXml(true).size());
    std::printf("%-46s %5zu %5zu %5zu\n", "100 digit amount, nanoseconds, plain string",
                encodedWide(plain), asJson(true, true).size(), asXml(true).size());
    std::printf("%-46s %5zu %5zu %5zu\n", "the same, contact carries an alias tag",
                derTagged, asJson(false, true).size(), asXml(true).size());

    std::printf("\n== what the alias tag costs ==\n");
    std::printf("plain UTF8String field            %3zu octets\n", derPlain);
    std::printf("same field with [APPLICATION 1]   %3zu octets\n", derTagged);
    std::printf("difference                        %3td octets  (the tag replaces the universal one)\n",
                static_cast<long>(derTagged) - static_cast<long>(derPlain));

    std::printf("\n== the two integers alone ==\n");
    for (const char *amount : {"0", "1", "127", "128", "-1", "32768", "987654321", "-19999",
                               "9223372036854775807", "99999999999999999999",
                               "123456789012345678901234567890123456789012345678901234567890"}) {
        const ASN1BigInt value = ASN1BigInt::fromDecimal(amount);
        const std::string decimal = value.toDecimal();
        std::printf("%-64s DER %3zu  JSON %3zu\n", decimal.c_str(), value.octetCount() + 2,
                    decimal.size() + 2);
    }

    std::printf("\n== timestamps ==\n");
    for (const char *label : {"whole second", "milliseconds", "microseconds", "nanoseconds"}) {
        long long ns = 1765432212000000000LL;
        if (std::string(label) == "milliseconds") ns += 123000000LL;
        if (std::string(label) == "microseconds") ns += 123456000LL;
        if (std::string(label) == "nanoseconds") ns += 123456789LL;

        ASN1 one = ASN1::sequence("S").field("t", ASN1::generalizedTime());
        ASN1Instance i = one.getInstance();
        i.set("t", system_clock::time_point(nanoseconds(ns)));
        const std::vector<std::uint8_t> der = i.getDER();

        // the same instant as RFC 3339, which is what a JSON API would carry
        int hour = static_cast<int>((ns / 3600000000000LL) % 24);
        int minute = static_cast<int>((ns / 60000000000LL) % 60);
        int second = static_cast<int>((ns / 1000000000LL) % 60);
        long fraction = (ns % 1000000000LL) + 1000000000LL;
        char buf[80];
        std::snprintf(buf, sizeof buf, "\"2025-12-12T%02d:%02d:%02d.%09ldZ\"", hour, minute,
                      second, fraction);
        std::printf("%-14s DER %3zu octets   RFC3339 %3zu octets   text: %s\n", label, der.size(),
                    std::string(buf).size(), buf + 1);
    }

    std::printf("\n== speed of one record, nanoseconds ==\n");
    ASN1Instance plainInstance = plain.getInstance();
    fill(plainInstance, false);
    const std::vector<std::uint8_t> plainDer = plainInstance.getDER();

    ASN1Instance taggedInstance = tagged.getInstance();
    fill(taggedInstance, false);
    const std::vector<std::uint8_t> taggedDer = taggedInstance.getDER();

    std::printf("encode, plain fields            %5ld\n",
                timeIt([&] { plainInstance.set("id", 4711); (void)plainInstance.getDER(); }));
    std::printf("encode, alias tagged fields     %5ld\n",
                timeIt([&] { taggedInstance.set("id", 4711); (void)taggedInstance.getDER(); }));
    std::printf("decode, plain fields            %5ld\n",
                timeIt([&] { (void)ASN1Instance::decode(plain, plainDer); }));
    std::printf("decode, alias tagged fields     %5ld\n",
                timeIt([&] { (void)ASN1Instance::decode(tagged, taggedDer); }));

    std::printf("\n== a wide amount in the same record ==\n");
    ASN1Instance wideInstance = plain.getInstance();
    fill(wideInstance, true);
    const std::vector<std::uint8_t> wideDer = wideInstance.getDER();
    std::printf("100 digit amount, encode        %5ld\n", timeIt([&] {
                    wideInstance.set("id", 4711);
                    (void)wideInstance.getDER();
                }));
    std::printf("100 digit amount, decode        %5ld\n",
                timeIt([&] { (void)ASN1Instance::decode(plain, wideDer); }));
    std::printf("record is %zu octets\n", wideDer.size());

    return 0;
}