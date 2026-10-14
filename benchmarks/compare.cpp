//
// Comparative page: the same data in DER, JSON and XML, across different shapes of payload.
// Shows where DER wins, where it loses, and what compression does to the result.
//

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#ifndef DYNASN1_NO_ZLIB
#include <zlib.h>
#endif

#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

namespace {

using nlohmann::json;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------- helpers
std::string base64(const std::vector<std::uint8_t> &data) {
    static const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < data.size(); i += 3) {
        const unsigned v = (static_cast<unsigned>(data[i]) << 16) |
                           (i + 1 < data.size() ? static_cast<unsigned>(data[i + 1]) << 8 : 0) |
                           (i + 2 < data.size() ? static_cast<unsigned>(data[i + 2]) : 0);
        out += table[(v >> 18) & 63];
        out += table[(v >> 12) & 63];
        out += i + 1 < data.size() ? table[(v >> 6) & 63] : '=';
        out += i + 2 < data.size() ? table[v & 63] : '=';
    }
    return out;
}

#ifdef DYNASN1_NO_ZLIB

// Built without zlib: the compressed columns report the uncompressed size so the table stays
// readable, and the rest of the comparison is unaffected.
std::string gzipped(const std::string &data) { return data; }

#else

std::string gzipped(const std::string &data) {
    uLongf bound = compressBound(static_cast<uLong>(data.size()));
    std::vector<Bytef> buffer(bound);
    if (compress2(buffer.data(), &bound, reinterpret_cast<const Bytef *>(data.data()),
                  static_cast<uLong>(data.size()), 6) != Z_OK)
        return {};
    return std::string(reinterpret_cast<char *>(buffer.data()), bound);
}

#endif

json toJson(const ASN1Value &value) {
    switch (value.type()) {
        case ASN1Value::Type::boolean: return json(value.asBoolean());
        case ASN1Value::Type::integer: return json(value.asInteger());
        case ASN1Value::Type::string: return json(value.asString());
        case ASN1Value::Type::time: {
            const std::time_t seconds = std::chrono::system_clock::to_time_t(value.asTime());
            char buffer[32];
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&seconds));
            return json(std::string(buffer));
        }
        case ASN1Value::Type::octetString: return json(base64(value.asOctets()));
        case ASN1Value::Type::sequence: {
            json out = json::object();
            for (const ASN1Field &field : value.asSequence()) out[field.name] = toJson(field.value);
            return out;
        }
        case ASN1Value::Type::list: {
            json list = json::array();
            for (const ASN1Value &item : value.asList()) list.push_back(toJson(item));
            return list;
        }
        default: return json();
    }
}

std::string toXml(const ASN1Value &value, const std::string &tag) {
    std::string body = "<" + tag + ">";
    switch (value.type()) {
        case ASN1Value::Type::sequence:
            for (const ASN1Field &field : value.asSequence()) body += toXml(field.value, field.name);
            break;
        case ASN1Value::Type::list: {
            std::size_t n = 0;
            for (const ASN1Value &item : value.asList())
                body += toXml(item, tag + "_" + std::to_string(n++));
            break;
        }
        case ASN1Value::Type::octetString: body += base64(value.asOctets()); break;
        case ASN1Value::Type::boolean: body += value.asBoolean() ? "true" : "false"; break;
        case ASN1Value::Type::string: body += value.asString(); break;
        case ASN1Value::Type::integer: body += std::to_string(value.asInteger()); break;
        case ASN1Value::Type::time: {
            const std::time_t seconds = std::chrono::system_clock::to_time_t(value.asTime());
            char buffer[32];
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&seconds));
            body += buffer;
            break;
        }
        default: break;
    }
    return body + "</" + tag + ">";
}

template <class Body> double nsPerOp(int repeats, Body &&body) {
    const auto start = Clock::now();
    for (int n = 0; n < repeats; ++n) body();
    return std::chrono::duration<double, std::nano>(Clock::now() - start).count() / repeats;
}

struct Row {
    const char *name;
    const char *shape;
    std::size_t der;
    std::size_t json;
    std::size_t xml;
    std::size_t derGz;
    std::size_t jsonGz;
    std::size_t xmlGz;
    double derEncodeNs;
    double derDecodeNs;
    double jsonWriteNs;
    double jsonParseNs;
    std::string note;
};

Row row;
std::vector<Row> rows;

void emit(const char *shape, const char *note, const ASN1 &schema, const ASN1Instance &instance,
          const std::string &, bool measureSpeed = true) {
    const std::vector<std::uint8_t> der = instance.getDER();
    const json document = toJson(instance.value());
    const std::string jsonText = document.dump();
    const std::string xml = toXml(instance.value(), schema.name());

    Row r{};
    r.name = "";
    r.shape = shape;
    r.der = der.size();
    r.json = jsonText.size();
    r.xml = xml.size();
    r.derGz = gzipped(std::string(reinterpret_cast<const char *>(der.data()), der.size())).size();
    r.jsonGz = gzipped(jsonText).size();
    r.xmlGz = gzipped(xml).size();
    if (measureSpeed) {
        std::vector<std::uint8_t> sink(der.size() + 64);
        r.derEncodeNs = nsPerOp(20000, [&] { instance.encodeTo(sink); });
        r.derDecodeNs = nsPerOp(10000, [&] { (void)ASN1Instance::decode(schema, der); });
        r.jsonWriteNs = nsPerOp(20000, [&] { (void)toJson(instance.value()).dump(); });
        r.jsonParseNs = nsPerOp(10000, [&] { (void)json::parse(jsonText).size(); });
    }
    static std::vector<std::string> names;
    names.push_back(note);
    r.note = note;
    rows.push_back(r);
}

}  // namespace

int main() {
    // ---------------------------------------------------------------- 1. tiny integers
    {
        ASN1 s = ASN1::sequence("T");
        s.field("a", ASN1::integer());
        s.field("b", ASN1::integer());
        s.field("c", ASN1::integer());
        ASN1Instance i = s.getInstance();
        i.set("a", 1);
        i.set("b", 2);
        i.set("c", 3);
        emit("три мелких целых", "выигрыш за счёт отсутствия имён", s, i,
             R"(<t><a>1</a><b>2</b><c>3</c></t>)");
    }

    // ---------------------------------------------------------------- 2. booleans
    {
        ASN1 s = ASN1::sequence("B");
        for (int n = 0; n < 6; ++n) s.field("flag" + std::to_string(n), ASN1::boolean());
        ASN1Instance i = s.getInstance();
        for (int n = 0; n < 6; ++n) i.set("flag" + std::to_string(n), n % 2 == 0);
        emit("шесть булевых", "DER 3 байта против JSON \"false\"", s, i,
             R"(<b><flag0>true</flag0><flag1>false</flag1><flag2>true</flag2>)"
             R"(<flag3>false</flag3><flag4>true</flag4><flag5>false</flag5></b>)");
    }

    // ---------------------------------------------------------------- 3. short strings
    {
        ASN1 s = ASN1::sequence("S");
        s.field("name", ASN1::utf8String());
        s.field("city", ASN1::utf8String());
        ASN1Instance i = s.getInstance();
        i.set("name", "Ivan");
        i.set("city", "Moscow");
        emit("два коротких текста", "выигрыш небольшой: текст не сжимается строкой", s, i,
             R"(<s><name>Ivan</name><city>Moscow</city></s>)");
    }

    // ---------------------------------------------------------------- 4. long text
    {
        ASN1 s = ASN1::sequence("D");
        s.field("body", ASN1::utf8String());
        ASN1Instance i = s.getInstance();
        i.set("body", std::string(4000, 'a'));
        emit("один длинный текст 4 КБ", "одинаковая добавка: текст доминирует", s, i,
             "<d><body>" + std::string(4000, 'a') + "</body></d>");
    }

    // ---------------------------------------------------------------- 5. binary blob
    {
        ASN1 s = ASN1::sequence("Bin");
        s.field("blob", ASN1::octetString());
        ASN1Instance i = s.getInstance();
        i.set("blob", ASN1Value(std::vector<std::uint8_t>(2048, 0xAB)));
        emit("двоичный блоб 2 КБ", "JSON несёт base64, +33%", s, i, "", false);
    }

    // ---------------------------------------------------------------- 6. timestamps
    {
        ASN1 s = ASN1::sequence("T2");
        s.field("issuedAt", ASN1::generalizedTime());
        s.field("expiresAt", ASN1::generalizedTime());
        ASN1Instance i = s.getInstance();
        const auto moment = std::chrono::system_clock::time_point{std::chrono::seconds{1'700'000'000}};
        i.set("issuedAt", moment);
        i.set("expiresAt", std::chrono::system_clock::time_point{std::chrono::seconds{1'700'086'400}});
        emit("две временные метки", "DER 15 байт против 20 символов", s, i,
             R"(<t><issuedAt>2023-11-14T22:13:20Z</issuedAt>)"
             R"(<expiresAt>2023-11-15T22:13:20Z</expiresAt></t>)");
    }

    // ---------------------------------------------------------------- 7. array of small ints
    {
        ASN1 s = ASN1::sequence("A");
        s.field("ids", ASN1::sequenceOf(ASN1::integer()));
        ASN1Instance i = s.getInstance();
        ASN1Value::List list;
        for (int n = 0; n < 50; ++n) list.push_back(ASN1Value(n));
        i.set("ids", ASN1Value(std::move(list)));
        emit("массив из 50 целых", "JSON повторяет имя ключа один раз, DER 2 байта на элемент", s, i,
             "", false);
    }

    // ------------------------------------------------- 7b. where does the integer array flip?
    {
        ASN1 s = ASN1::sequence("A4");
        s.field("ids", ASN1::sequenceOf(ASN1::integer()));
        ASN1Instance i = s.getInstance();
        ASN1Value::List list;
        for (int n = 0; n < 50; ++n) list.push_back(ASN1Value(1000 + n * 97));
        i.set("ids", ASN1Value(std::move(list)));
        emit("массив из 50 четырёхзначных", "точка перелома по разрядности", s, i, "", false);
    }

    // ---------------------------------------------------------------- 8. array of objects
    {
        ASN1 s = ASN1::sequence("L");
        ASN1 item = ASN1::sequence("Item");
        item.field("id", ASN1::integer());
        item.field("ok", ASN1::boolean());
        s.field("items", ASN1::sequenceOf(item));
        ASN1Instance i = s.getInstance();
        ASN1Value::List list;
        for (int n = 0; n < 20; ++n)
            list.push_back(ASN1Value(ASN1Value::Sequence{
                    ASN1Field{"id", ASN1Value(n)},
                    ASN1Field{"ok", ASN1Value(n % 2 == 0)}}));
        i.set("items", ASN1Value(std::move(list)));
        emit("20 объектов в массиве", "тип элемента описан один раз", s, i,
             "", false);
    }

    // ---------------------------------------------------------------- 9. sparse: 2 из 20
    {
        ASN1 s = ASN1::sequence("Sp");
        for (int n = 0; n < 20; ++n) s.field("field" + std::to_string(n), ASN1::integer().optional());
        ASN1Instance i = s.getInstance();
        i.set("field3", 7);
        i.set("field17", 9);
        emit("2 поля из 20 объявленных", "OPTIONAL отсутствующие не пишутся вообще", s, i,
             "", false);
    }

    // ---------------------------------------------------------------- 10. deep nesting
    {
        ASN1 link = ASN1::sequence("Node");
        link.field("v", ASN1::integer());
        link.field("next", ASN1::reference("Node").optional());
        ASN1 s = ASN1::sequence("Tree");
        s.named("Node", link);
        s.field("root", ASN1::reference("Node"));

        ASN1Value current = ASN1Value(ASN1Value::Sequence{ASN1Field{"v", ASN1Value(1)}});
        for (int n = 0; n < 12; ++n) {
            ASN1Value::Sequence node;
            node.push_back({"v", ASN1Value(n)});
            node.push_back({"next", std::move(current)});
            current = ASN1Value(std::move(node));
        }
        ASN1Instance i = s.getInstance();
        i.set("root", std::move(current));
        emit("вложенность 12 уровней", "на уровень 2 байта против скобок и кавычек", s, i, "", false);
    }

    // ---------------------------------------------------------------- 11. 64-bit amounts
    {
        ASN1 s = ASN1::sequence("M");
        s.field("amount", ASN1::integer());
        s.field("fee", ASN1::integer());
        ASN1Instance i = s.getInstance();
        i.set("amount", std::int64_t(9'223'372'036'854'775'807LL));
        i.set("fee", std::int64_t(1'000'000'000));
        emit("64-битные суммы", "8 байт против 19 символов", s, i,
             R"(<m><amount>9223372036854775807</amount><fee>1000000000</fee></m>)");
    }

    // ---------------------------------------------------------------- 12. protocol envelope
    {
        ASN1 s = ASN1::sequence("Envelope");
        s.field("id", ASN1::octetString().withSize(0, 64));
        s.field("procedure", ASN1::utf8String().withSize(1, 32));
        s.field("deadline", ASN1::generalizedTime());
        s.field("traceId", ASN1::octetString().withSize(0, 32));
        s.field("payload", ASN1::octetString().optional());
        ASN1Instance i = s.getInstance();
        std::vector<std::uint8_t> id(32, 0x11);
        std::vector<std::uint8_t> trace(16, 0x22);
        std::vector<std::uint8_t> payload(256, 0x33);
        i.set("id", ASN1Value(id));
        i.set("procedure", "Transfer");
        i.set("deadline", std::chrono::system_clock::time_point{std::chrono::seconds{1'700'000'000}});
        i.set("traceId", ASN1Value(trace));
        i.set("payload", ASN1Value(payload));
        emit("конверт: id, имя, дедлайн, трейс, блоб", "смешанная нагрузка, типичный случай", s, i,
             "", false);
    }

    // ---------------------------------------------------------------- report
    std::printf(
            "%-38s %6s %6s %6s | %6s %6s | %8s %8s\n", "нагрузка", "DER", "JSON", "XML", "DERgz",
            "JSONgz", "JSON/DER", "XML/DER");
    std::printf(
            "-------------------------------------------------------------------------------------------------------------------\n");
    const char *shapes[] = {
            "три мелких целых", "шесть булевых", "два коротких текста", "один длинный текст 4 КБ",
            "двоичный блоб 2 КБ", "две временные метки", "массив из 50 целых", "массив из 50 четырёхзначных", "20 объектов в массиве", "2 поля из 20 объявленных", "вложенность 12 уровней",
            "64-битные суммы", "конверт: id, имя, дедлайн, трейс, блоб"};
    for (std::size_t n = 0; n < rows.size(); ++n) {
        const Row &r = rows[n];
        const double vsJson = r.json ? static_cast<double>(r.json) / static_cast<double>(r.der) : 0.0;
        const double vsXml = r.xml ? static_cast<double>(r.xml) / static_cast<double>(r.der) : 0.0;
        const std::string verdict = vsJson < 1.0
                                       ? "<- проигрываем"
                                       : (vsJson >= 1.5
                                                  ? "выигрываем x" +
                                                            std::to_string(static_cast<int>(vsJson * 10) / 10)
                                                  : "паритет");
        char line[220];
        std::snprintf(line, sizeof(line), "%-38s %6zu %6zu %6zu | %6zu %6zu | %8.2f %8.2f  %s",
                      shapes[n], r.der, r.json, r.xml, r.derGz, r.jsonGz, vsJson, vsXml,
                      verdict.c_str());
        std::printf("%s\n", line);
    }

    std::printf("\n%-38s %7s %7s %7s\n", "скорость, нс на сообщение", "DER enc", "DER dec", "JSON par");
    std::printf(
            "-------------------------------------------------------------------------------------------------------------------\n");
    for (std::size_t n = 0; n < rows.size(); ++n) {
        const Row &r = rows[n];
        if (r.derEncodeNs == 0) continue;
        char line[160];
        std::snprintf(line, sizeof(line), "%-34s %7.0f %7.0f %7.0f", shapes[n], r.derEncodeNs,
                      r.derDecodeNs, r.jsonParseNs);
        std::printf("%s\n", line);
    }
    return 0;
}