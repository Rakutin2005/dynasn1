// Checks the GeneralizedTime / UTCTime encoding against the exact octets X.690 11.7 prescribes,
// and the canonicality rules the decoder must enforce.
#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

void report(const std::string &what, const std::string &detail) {
    std::printf("  FAIL %s: %s\n", what.c_str(), detail.c_str());
    ++failures;
}

// The content octets of the single field, i.e. the last octets of the encoding.
std::string fieldContent(const std::vector<std::uint8_t> &der, std::size_t size) {
    return std::string(der.end() - static_cast<long>(size), der.end());
}

// SEQUENCE { <primitive TLV> }, which is what the one field description decodes.
std::vector<std::uint8_t> wrap(std::uint8_t tag, const std::string &content) {
    std::vector<std::uint8_t> inner{tag};
    inner.push_back(static_cast<std::uint8_t>(content.size()));
    inner.insert(inner.end(), content.begin(), content.end());

    std::vector<std::uint8_t> out{0x30};
    if (inner.size() < 128) {
        out.push_back(static_cast<std::uint8_t>(inner.size()));
    } else {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(inner.size()));
    }
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

void expectEncoded(const ASN1 &schema, std::chrono::system_clock::time_point value,
                   const std::string &expected) {
    ASN1Instance instance = schema.getInstance();
    instance.set("t", value);
    const std::vector<std::uint8_t> der = instance.getDER();
    const std::string got = fieldContent(der, expected.size());
    if (got != expected) report("encoding", "got " + got + " expected " + expected);
}

void expectRejected(const ASN1 &schema, const std::vector<std::uint8_t> &der,
                    const std::string &what) {
    try {
        (void)ASN1Instance::decode(schema, der);
        report(what, "was accepted");
    } catch (const ASN1DecodeError &) {
    } catch (const ASN1Exception &error) {
        report(what, std::string("wrong exception: ") + error.what());
    }
}

void expectAccepted(const ASN1 &schema, std::uint8_t tag, const std::string &content,
                    std::chrono::system_clock::time_point expected, const std::string &what) {
    try {
        const ASN1Instance decoded = ASN1Instance::decode(schema, wrap(tag, content));
        if (decoded.get("t").asTime() != expected) {
            report(what, "decoded to " +
                                 std::to_string(decoded.get("t").asTime().time_since_epoch().count()) +
                                 " expected " + std::to_string(expected.time_since_epoch().count()));
        }
    } catch (const ASN1Exception &error) {
        report(what, std::string("threw: ") + error.what());
    }
}

}  // namespace

int main() {
    using namespace std::chrono;
    using ns = nanoseconds;
    using TP = system_clock::time_point;

    const ASN1 genTime = ASN1::sequence("S").field("t", ASN1::generalizedTime("t"));
    const ASN1 utcTime = ASN1::sequence("S").field("t", ASN1::utcTime("t"));

    // ---- formatting ---------------------------------------------------------------------------
    expectEncoded(genTime, TP(ns(0)), "19700101000000Z");
    expectEncoded(genTime, TP(seconds(1700000000)), "20231114221320Z");
    expectEncoded(genTime, TP(ns(1500000000)), "19700101000001.5Z");
    expectEncoded(genTime, TP(ns(1765432212123456789LL)), "20251211055012.123456789Z");
    expectEncoded(genTime, TP(ns(1765432212000000000LL)), "20251211055012Z");
    expectEncoded(genTime, TP(ns(1765432212123000000LL)), "20251211055012.123Z");
    expectEncoded(genTime, TP(ns(1)), "19700101000000.000000001Z");
    expectEncoded(genTime, TP(ns(100000000)), "19700101000000.1Z");
    expectEncoded(genTime, TP(ns(100000001)), "19700101000000.100000001Z");
    expectEncoded(genTime, TP(seconds(1709164800)), "20240229000000Z");
    // before the epoch the fraction stays positive and the date goes below 1970
    expectEncoded(genTime, TP(ns(-1500000000LL)), "19691231235958.5Z");
    expectEncoded(genTime, TP(ns(-1)), "19691231235959.999999999Z");
    expectEncoded(genTime, TP(ns(-31536000000000000LL)), "19690101000000Z");

    expectEncoded(utcTime, TP(seconds(1700000000)), "231114221320Z");
    expectEncoded(utcTime, TP(seconds(0)), "700101000000Z");
    expectEncoded(utcTime, TP(seconds(-86400)), "691231000000Z");
    expectEncoded(utcTime, TP(seconds(-63115200)), "680101120000Z");

    // ---- canonical forms the decoder must accept ----------------------------------------------
    expectAccepted(genTime, 0x18, "19700101000000Z", TP(ns(0)), "whole seconds");
    expectAccepted(genTime, 0x18, "19700101000000.5Z", TP(ns(500000000)), "one fraction digit");
    expectAccepted(genTime, 0x18, "19700101000000.000000001Z", TP(ns(1)), "nine fraction digits");
    expectAccepted(genTime, 0x18, "19691231235959.999999999Z", TP(ns(-1)), "before the epoch");
    expectAccepted(genTime, 0x18, "20000229000000Z", TP(seconds(951782400)), "leap day 2000");
    expectAccepted(genTime, 0x18, "19700101000000.1Z", TP(ns(100000000)), "tenth of a second");
    expectAccepted(genTime, 0x18, "19700101000000.100000001Z", TP(ns(100000001)), "mixed fraction");
    expectAccepted(utcTime, 0x17, "231114221320Z", TP(seconds(1700000000)), "utc time");
    expectAccepted(utcTime, 0x17, "700101000000Z", TP(seconds(0)), "utc time at the epoch");

    // ---- what DER does not allow ---------------------------------------------------------------
    expectRejected(genTime, wrap(0x18, "19700101000000.50Z"), "trailing zero in the fraction");
    expectRejected(genTime, wrap(0x18, "19700101000000.000Z"), "trailing zeros in the fraction");
    expectRejected(genTime, wrap(0x18, "19700101000000,5Z"), "comma as the decimal mark");
    expectRejected(genTime, wrap(0x18, "19700101000000.1234567891Z"), "ten fraction digits");
    expectRejected(genTime, wrap(0x18, "19700101000000.Z"), "empty fraction");
    expectRejected(genTime, wrap(0x18, "1970010100000Z"), "truncated year");
    expectRejected(genTime, wrap(0x18, "19700101000000"), "missing the Z");
    expectRejected(genTime, wrap(0x18, "19700101000000+0100"), "time zone offset");
    expectRejected(genTime, wrap(0x18, "19701301000000Z"), "month 13");
    expectRejected(genTime, wrap(0x18, "19700230000000Z"), "30 February");
    expectRejected(genTime, wrap(0x18, "19700229000000Z"), "29 February in a common year");
    expectRejected(genTime, wrap(0x18, "19700101246000Z"), "minute 60");
    expectRejected(genTime, wrap(0x18, "1970010124006 0Z"), "space instead of a digit");
    expectRejected(genTime, wrap(0x18, "1970010100000aZ"), "letter instead of a digit");
    expectRejected(utcTime, wrap(0x17, "231114221320.5Z"), "fraction in UTCTime");
    expectRejected(utcTime, wrap(0x17, "2311142213200Z"), "UTCTime that is too long");
    expectRejected(utcTime, wrap(0x17, "23111422132Z"), "UTCTime that is too short");

    // ---- encoding side refuses what cannot be represented ---------------------------------------
    try {
        ASN1Instance out = utcTime.getInstance();
        out.set("t", TP(seconds(7258118400)));  // the year 2200
        report("UTCTime outside its years", "was accepted");
    } catch (const ASN1ValueError &) {
    }
    // a nanosecond part cannot be written in UTCTime, and must be dropped rather than rounded
    {
        ASN1Instance out = utcTime.getInstance();
        out.set("t", TP(ns(1700000000123456789LL)));
        const std::vector<std::uint8_t> der = out.getDER();
        if (fieldContent(der, 13) != "231114221320Z")
            report("UTCTime drops the fraction", "got " + fieldContent(der, 13));
    }

    std::printf("timestamps: %s (%d failures)\n", failures ? "FAILED" : "ok", failures);
    return failures ? 1 : 0;
}