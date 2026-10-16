// The three types X.680 added after the original set: DATE, TIME-OF-DAY and DATE-TIME.
//
// DATE is the only one of the three that needed a carrier of its own; the other two hold a time
// of day and reuse the timestamp carrier.
#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

using namespace std::chrono;

namespace {

int failures = 0;

void check(bool ok, const std::string &what) {
    if (!ok) ++failures;
    std::printf("  %-4s %s\n", ok ? "ok" : "FAIL", what.c_str());
}

// The encoding is SEQUENCE { <one field> }. The field's identifier is not always one octet: the
// universal tags 31, 32 and 33 do not fit into five bits, so they travel in the long form.
std::string encodeField(ASN1 type, ASN1Value value) {
    const ASN1 one = ASN1::sequence("S").field("t", type);
    ASN1Instance i = one.getInstance();
    i.set("t", value);
    const std::vector<std::uint8_t> der = i.getDER();

    std::size_t pos = 2;  // past the SEQUENCE header, short form

    if ((der[pos] & 0x1Fu) == 0x1Fu) {  // the tag number does not fit in five bits
        ++pos;                          // past the identifier byte itself
        while (der[pos] & 0x80u) ++pos;  // tag number octets, all but the last carry on
        ++pos;
    }
    if (der[pos] & 0x80u)  // long form length
        pos += der[pos] & 0x7Fu;
    ++pos;                 // the length octet itself
    return std::string(der.begin() + static_cast<long>(pos), der.end());
}

bool rejects(ASN1 type, const std::string &content, std::uint8_t tag) {
    std::vector<std::uint8_t> inner{tag, static_cast<std::uint8_t>(content.size())};
    inner.insert(inner.end(), content.begin(), content.end());
    std::vector<std::uint8_t> der{0x30, static_cast<std::uint8_t>(inner.size())};
    der.insert(der.end(), inner.begin(), inner.end());
    const ASN1 one = ASN1::sequence("S").field("t", type);
    try {
        (void)ASN1Instance::decode(one, der);
        return false;
    } catch (const ASN1Exception &) {
        return true;
    }
}

}  // namespace

int main() {
    // ---- DATE --------------------------------------------------------------------------------
    const ASN1 dateType = ASN1::date();
    check(encodeField(dateType, ASN1Date{2025, 12, 12}) == "20251212", "DATE writes YYYYMMDD");
    check(encodeField(dateType, ASN1Date{1970, 1, 1}) == "19700101", "DATE at the epoch");
    check(encodeField(dateType, ASN1Date{2000, 2, 29}) == "20000229", "DATE on a leap day");
    check(encodeField(dateType, ASN1Date{1899, 12, 31}) == "18991231", "DATE before the epoch");

    {
        const ASN1 one = ASN1::sequence("S").field("t", ASN1::date());
        ASN1Instance i = one.getInstance();
        i.set("t", ASN1Date{2025, 12, 12});
        const auto der = i.getDER();
        const ASN1Instance back = ASN1Instance::decode(one, der);
        const ASN1Date got = back.get("t").asDate();
        check(got.year == 2025 && got.month == 12 && got.day == 12, "DATE survives a round trip");
        check(back.get("t").type() == ASN1Value::Type::date, "DATE has its own value type");
        check(back.getDER() == der, "re-encoding a DATE reproduces the same octets");
    }

    // A time point must not be accepted where a DATE is declared: silently dropping the time of
    // day is exactly what the separate carrier is there to prevent.
    {
        const ASN1 one = ASN1::sequence("S").field("t", ASN1::date());
        ASN1Instance i = one.getInstance();
        bool threw = false;
        try {
            i.set("t", system_clock::time_point(seconds(1000)));
            (void)i.getDER();
        } catch (const ASN1ValueError &) {
            threw = true;
        }
        check(threw, "a time point is refused where a DATE is declared");
    }

    check(rejects(ASN1::date(), "2025121", 0x1F), "DATE of seven digits is rejected");
    check(rejects(ASN1::date(), "202512122", 0x1F), "DATE of nine digits is rejected");
    check(rejects(ASN1::date(), "20251212Z", 0x1F), "DATE with a trailing Z is rejected");
    check(rejects(ASN1::date(), "2025-12-12", 0x1F), "DATE with separators is rejected");
    check(rejects(ASN1::date(), "20251312", 0x1F), "DATE with month 13 is rejected");
    check(rejects(ASN1::date(), "20250229", 0x1F), "29 February of a common year is rejected");
    check(rejects(ASN1::date(), "19000229", 0x1F), "29 February 1900 is rejected, it was not a leap year");
    check(rejects(ASN1::date(), "20250012", 0x1F), "DATE with month 00 is rejected");
    check(rejects(ASN1::date(), "2025010a", 0x1F), "DATE with a letter is rejected");
    check(rejects(ASN1::date(), "202501000", 0x1F), "DATE with a zero day is rejected");

    // An impossible date is also refused on the way out, not only on the way in.
    {
        const ASN1 one = ASN1::sequence("S").field("t", ASN1::date());
        ASN1Instance i = one.getInstance();
        bool threw = false;
        try {
            i.set("t", ASN1Date{2025, 2, 30});
            (void)i.getDER();
        } catch (const ASN1ValueError &) {
            threw = true;
        }
        check(threw, "an impossible date is refused when encoding");
    }

    // ---- TIME-OF-DAY -------------------------------------------------------------------------
    check(encodeField(ASN1::timeOfDay(), system_clock::time_point(seconds(0))) == "000000Z",
          "TIME-OF-DAY writes HHMMSSZ");
    check(encodeField(ASN1::timeOfDay(), system_clock::time_point(seconds(45336))) == "123536Z",
          "TIME-OF-DAY at 12:35:36");
    check(encodeField(ASN1::timeOfDay(), system_clock::time_point(nanoseconds(45296500000000LL))) ==
                  "123456.5Z",
          "TIME-OF-DAY with a fraction");

    {
        const ASN1 one = ASN1::sequence("S").field("t", ASN1::timeOfDay());
        ASN1Instance i = one.getInstance();
        i.set("t", system_clock::time_point(nanoseconds(45296500000000LL)));
        const auto der = i.getDER();
        const ASN1Instance back = ASN1Instance::decode(one, der);
        check(back.get("t").asTime() == system_clock::time_point(nanoseconds(45296500000000LL)),
              "TIME-OF-DAY survives a round trip");
    }

    check(rejects(ASN1::timeOfDay(), "1200Z", 0x20), "TIME-OF-DAY without seconds is rejected");
    check(rejects(ASN1::timeOfDay(), "120000", 0x20), "TIME-OF-DAY without the Z is rejected");
    check(rejects(ASN1::timeOfDay(), "120000.50Z", 0x20), "a trailing zero in the fraction is rejected");
    check(rejects(ASN1::timeOfDay(), "120000,5Z", 0x20), "a comma as the decimal mark is rejected");
    check(rejects(ASN1::timeOfDay(), "120000.1234567891Z", 0x20), "ten fraction digits are rejected");
    check(rejects(ASN1::timeOfDay(), "240000Z", 0x20), "hour 24 is rejected");
    check(rejects(ASN1::timeOfDay(), "126000Z", 0x20), "minute 60 is rejected");
    check(rejects(ASN1::timeOfDay(), "1200Z ", 0x20), "a space is rejected");

    // ---- DATE-TIME ----------------------------------------------------------------------------
    const ASN1 dateTimeType = ASN1::dateTime();
    check(encodeField(dateTimeType, system_clock::time_point(seconds(1765432212))) == "20251211055012Z",
          "DATE-TIME writes YYYYMMDDHHMMSSZ");
    check(encodeField(dateTimeType, system_clock::time_point(nanoseconds(1765432212123456789LL))) ==
                  "20251211055012.123456789Z",
          "DATE-TIME with a fraction");

    {
        const ASN1 one = ASN1::sequence("S").field("t", ASN1::dateTime());
        ASN1Instance i = one.getInstance();
        i.set("t", system_clock::time_point(nanoseconds(1765432212123456789LL)));
        const auto der = i.getDER();
        const ASN1Instance back = ASN1Instance::decode(one, der);
        check(back.get("t").asTime() ==
                      system_clock::time_point(nanoseconds(1765432212123456789LL)),
              "DATE-TIME survives a round trip");
        check(back.getDER() == der, "re-encoding a DATE-TIME reproduces the same octets");
    }

    check(rejects(ASN1::dateTime(), "2025121105501Z", 0x21), "DATE-TIME without seconds is rejected");
    check(rejects(ASN1::dateTime(), "20251211055012", 0x21), "DATE-TIME without the Z is rejected");
    check(rejects(ASN1::dateTime(), "20251211055012.0Z", 0x21), "a zero fraction is rejected");
    check(rejects(ASN1::dateTime(), "20251311055012Z", 0x21), "DATE-TIME with month 13 is rejected");

    // ---- the description keeps them -----------------------------------------------------------
    {
        ASN1 schema = ASN1::sequence("S");
        schema.field("d", ASN1::date());
        schema.field("t", ASN1::timeOfDay());
        schema.field("dt", ASN1::dateTime());
        schema.named("BusinessDate", ASN1::date());
        schema.field("ref", ASN1::reference("BusinessDate"));

        const std::vector<std::uint8_t> notation = schema.notation();
        const ASN1 restored = ASN1::fromNotation(notation);
        check(restored.notation() == notation, "the three types survive a description round trip");

        ASN1Instance i = restored.getInstance();
        i.set("d", ASN1Date{2025, 12, 12});
        i.set("t", system_clock::time_point(seconds(3600)));
        i.set("dt", system_clock::time_point(seconds(1765432212)));
        i.set("ref", ASN1Date{2026, 1, 1});
        const ASN1Instance back = ASN1Instance::decode(restored, i.getDER());
        check(back.get("ref").asDate().year == 2026, "a named DATE type resolves and decodes");
        check(back.getDER() == i.getDER(), "re-encoding reproduces the same octets");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "ok", failures);
    return failures ? 1 : 0;
}