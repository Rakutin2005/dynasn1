//
// Size comparison: DER schema description vs ASN.1 text vs JSON vs XML,
// and DER data vs JSON data vs XML data.
//

#include <chrono>
#include <functional>
#include <cstdio>
#include <string>
#include <vector>

#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

namespace {

void row(const std::string &label, std::size_t der, std::size_t text, std::size_t json,
         std::size_t xml) {
    char buffer[256];
    std::snprintf(buffer, sizeof(buffer), "  %-34s %8zu %8zu %8zu %8zu   %5.1fx vs JSON", label.c_str(),
                  der, text, json, xml, json ? static_cast<double>(der) / static_cast<double>(json) : 0.0);
    std::printf("%s\n", buffer);
}

// A minimal, hand packed description of the same schema: a name pool plus one fixed size record
// per type. This is the "purpose built binary schema" reference point, without the self
// describing meta schema overhead.
std::vector<std::uint8_t> packSchema(const std::vector<std::string> &names) {
    std::vector<std::uint8_t> out;
    const auto put16 = [&](std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v));
    };
    put16(static_cast<std::uint16_t>(names.size()));  // name pool size
    for (const std::string &name : names) {
        put16(static_cast<std::uint16_t>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
    }
    put16(static_cast<std::uint16_t>(names.size() * 7));  // one record per type, 7 bytes each
    for (std::size_t i = 0; i < names.size(); ++i) {
        out.insert(out.end(), {0x0e, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00});
    }
    return out;
}

}  // namespace

int main() {
    // ------------------------------------------------------------------ schema
    ASN1 request = ASN1::sequence("TransferRequest");
    request.field("id", ASN1::integer().withRange(0, 1'000'000));
    request.field("memo", ASN1::utf8String().optional().withSize(0, 64));
    request.field("urgent", ASN1::boolean());
    request.field("amount", ASN1::integer());
    request.field("payload", ASN1::octetString().optional());
    request.field("tags", ASN1::sequenceOf(ASN1::utf8String()).withSize(0, 8));

    const std::string asn1Text = request.dump();
    const std::vector<std::uint8_t> derSchema = request.notation();
    const std::vector<std::uint8_t> packedSchema =
            packSchema({"TransferRequest", "id", "memo", "urgent", "amount", "payload", "tags"});

    const std::string jsonSchema =
            R"({"name":"TransferRequest","types":{"TransferRequest":{"kind":"SEQUENCE","fields":[)"
            R"({"name":"id","type":"INTEGER","min":0,"max":1000000},)"
            R"({"name":"memo","type":"UTF8String","optional":true,"maxLen":64},)"
            R"({"name":"urgent","type":"BOOLEAN"},)"
            R"({"name":"amount","type":"INTEGER"},)"
            R"({"name":"payload","type":"OCTET STRING","optional":true},)"
            R"({"name":"tags","type":"SEQUENCE OF","of":"UTF8String","maxItems":8}]}}})";

    const std::string xmlSchema =
            R"(<?xml version="1.0"?>)"
            R"(<schema name="TransferRequest"><sequence>)"
            R"(<field name="id" type="INTEGER" min="0" max="1000000"/>)"
            R"(<field name="memo" type="UTF8String" optional="true" maxLen="64"/>)"
            R"(<field name="urgent" type="BOOLEAN"/>)"
            R"(<field name="amount" type="INTEGER"/>)"
            R"(<field name="payload" type="OCTET STRING" optional="true"/>)"
            R"(<field name="tags" type="SEQUENCE OF" of="UTF8String" maxItems="8"/>)"
            R"(</sequence></schema>)";

    std::printf("== schema description, one 7 field SEQUENCE ==\n");
    row("DER (meta schema)", derSchema.size(), asn1Text.size(), jsonSchema.size(), xmlSchema.size());
    row("DER (hand packed reference)", packedSchema.size(), asn1Text.size(), jsonSchema.size(),
        xmlSchema.size());

    // A recursive schema, the kind a procedure/contract definition really needs.
    ASN1 clause = ASN1::sequence("Clause");
    clause.field("guard", ASN1::boolean());
    clause.field("target", ASN1::reference("Clause").optional());
    clause.field("amount", ASN1::octetString().withSize(0, 64));
    ASN1 procedure = ASN1::sequence("Procedure");
    procedure.field("name", ASN1::utf8String().withSize(1, 32));
    procedure.field("weight", ASN1::integer().withRange(0, 1'000'000));
    procedure.field("clauses", ASN1::sequenceOf(ASN1::reference("Clause")));
    ASN1 plan = ASN1::sequence("ExecutionPlan");
    plan.named("Clause", clause);
    plan.named("Procedure", procedure);
    plan.field("procedure", ASN1::reference("Procedure"));
    plan.field("version", ASN1::integer().withDefault(1));

    std::printf("\n== schema description, recursive 4 named types / 13 nodes ==\n");
    row("DER (meta schema)", plan.notation().size(), plan.dump().size(), 0, 0);

    // ------------------------------------------------------------------ data
    std::printf("\n== data, same schema, four payloads ==\n");
    std::printf("  %-34s %8s %8s %8s %8s\n", "", "DER", "ASN.1", "JSON", "XML");

    struct Case {
        std::string name;
        std::function<ASN1Instance(const ASN1 &)> build;
        std::string json;
        std::string xml;
    };

    const std::vector<Case> cases = {
            {"minimum (no text, no payload)",
             [](const ASN1 &s) {
                 ASN1Instance i = s.getInstance();
                 i.set("id", 1);
                 i.set("urgent", false);
                 i.set("amount", 0);
                 i.set("tags", ASN1Value::List{});
                 return i;
             },
             R"({"id":1,"urgent":false,"amount":0,"tags":[]})",
             R"(<request><id>1</id><urgent>false</urgent><amount>0</amount><tags/></request>)"},

            {"typical (text + 2 tags)",
             [](const ASN1 &s) {
                 ASN1Instance i = s.getInstance();
                 i.set("id", 4711);
                 i.set("memo", "invoice #7");
                 i.set("urgent", true);
                 i.set("amount", -1234567890123LL);
                 i.set("tags", ASN1Value::List{ASN1Value("alpha"), ASN1Value("beta")});
                 return i;
             },
             R"({"id":4711,"memo":"invoice #7","urgent":true,"amount":-1234567890123,)"
             R"("tags":["alpha","beta"]})",
             R"(<request><id>4711</id><memo>invoice #7</memo><urgent>true</urgent>)"
             R"(<amount>-1234567890123</amount><tags><tag>alpha</tag><tag>beta</tag></tags></request>)"},

            {"1 KiB binary payload",
             [](const ASN1 &s) {
                 ASN1Instance i = s.getInstance();
                 i.set("id", 4711);
                 i.set("urgent", false);
                 i.set("amount", 7);
                 i.set("payload", ASN1Value(std::vector<std::uint8_t>(1024, 0xAB)));
                 i.set("tags", ASN1Value::List{});
                 return i;
             },
             "", R"()"},

            {"32 KiB binary payload",
             [](const ASN1 &s) {
                 ASN1Instance i = s.getInstance();
                 i.set("id", 4711);
                 i.set("urgent", false);
                 i.set("amount", 7);
                 i.set("payload", ASN1Value(std::vector<std::uint8_t>(32 * 1024, 0xAB)));
                 i.set("tags", ASN1Value::List{});
                 return i;
             },
             "", R"()"},

            {"",
             [](const ASN1 &s) {
                 (void)s;
                 return ASN1Instance();
             },
             "", R"()"}};

    // base64 of 1 KiB and 32 KiB of binary, as JSON/XML would carry it
    const auto base64 = [](std::size_t bytes) {
        static const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve((bytes + 2) / 3 * 4);
        for (std::size_t i = 0; i < bytes; i += 3) {
            const unsigned v = (0xAB << 16) | (i + 1 < bytes ? 0xAB << 8 : 0) | (i + 2 < bytes ? 0xAB : 0);
            out.push_back(table[(v >> 18) & 63]);
            out.push_back(table[(v >> 12) & 63]);
            out.push_back(i + 1 < bytes ? table[(v >> 6) & 63] : '=');
            out.push_back(i + 2 < bytes ? table[v & 63] : '=');
        }
        return out;
    };

    for (std::size_t i = 0; i < cases.size(); ++i) {
        if (cases[i].name.empty()) continue;
        const ASN1Instance instance = cases[i].build(request);
        const std::vector<std::uint8_t> der = instance.getDER();

        std::string json = cases[i].json;
        std::string xml = cases[i].xml;
        if (json.empty()) {  // binary payload cases
            json = R"({"id":4711,"urgent":false,"amount":7,"payload":")" + base64(1024) +
                   R"(","tags":[]})";
            xml = R"(<request><id>4711</id><urgent>false</urgent><amount>7</amount><payload>)" +
                  base64(1024) + R"(</payload><tags/></request>)";
            if (i == 3) {  // 32 KiB
                json = R"({"id":4711,"urgent":false,"amount":7,"payload":")" + base64(32 * 1024) +
                       R"(","tags":[]})";
                xml = R"(<request><id>4711</id><urgent>false</urgent><amount>7</amount><payload>)" +
                      base64(32 * 1024) + R"(</payload><tags/></request>)";
            }
            if (i == 4) break;  // handled separately below
        }

        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "  %-34s %8zu %8s %8zu %8zu", cases[i].name.c_str(),
                      der.size(), "-", json.size(), xml.size());
        std::printf("%s\n", buffer);
    }

    // The tag list case needs its own, unbounded, list type.
    {
        ASN1 listSchema = ASN1::sequence("TagSet");
        listSchema.field("id", ASN1::integer());
        listSchema.field("urgent", ASN1::boolean());
        listSchema.field("amount", ASN1::integer());
        listSchema.field("tags", ASN1::sequenceOf(ASN1::utf8String()));

        ASN1Instance instance = listSchema.getInstance();
        instance.set("id", 1);
        instance.set("urgent", true);
        instance.set("amount", 2);
        ASN1Value::List tags;
        for (int n = 0; n < 40; ++n) tags.push_back(ASN1Value("tag-" + std::to_string(n)));
        instance.set("tags", ASN1Value(std::move(tags)));

        std::string json = R"({"id":1,"urgent":true,"amount":2,"tags":[)";
        std::string xml = R"(<tagset><id>1</id><urgent>true</urgent><amount>2</amount><tags>)";
        for (int n = 0; n < 40; ++n) {
            if (n) { json += ","; xml += "<tag>"; }
            json += R"("tag-)" + std::to_string(n) + R"(")";
            xml += "tag-" + std::to_string(n) + "</tag>";
        }
        json += "]}";
        xml += "</tags></tagset>";

        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "  %-34s %8zu %8s %8zu %8zu",
                      "40 element list (unbounded tag list)", instance.getDER().size(), "-",
                      json.size(), xml.size());
        std::printf("%s\n", buffer);
    }

    // ------------------------------------------------------------------ scaling
    std::printf("\n== scaling, one SEQUENCE with N INTEGER fields ==\n");
    std::printf("  %-34s %8s %8s %8s %8s\n", "N", "DER", "ASN.1", "JSON", "XML");
    for (const int fields : {1, 5, 10, 20, 40}) {
        ASN1 wide = ASN1::sequence("Wide");
        for (int n = 0; n < fields; ++n) wide.field("field" + std::to_string(n), ASN1::integer());
        std::string json = R"({"name":"Wide","kind":"SEQUENCE","fields":[)";
        std::string xml = R"(<schema name="Wide"><sequence>)";
        for (int n = 0; n < fields; ++n) {
            if (n) { json += ","; xml += ""; }
            json += R"({"name":"field)" + std::to_string(n) + R"(","type":"INTEGER"})";
            xml += R"(<field name="field)" + std::to_string(n) + R"(" type="INTEGER"/>)";
        }
        json += "]}";
        xml += "</sequence></schema>";
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "  %-34d %8zu %8zu %8zu %8zu", fields,
                      wide.notation().size(), wide.dump().size(), json.size(), xml.size());
        std::printf("%s\n", buffer);
    }

    // ------------------------------------------------------------------ speed
    std::printf("\n== throughput, 20k round trips of the typical payload ==\n");
    const ASN1Instance sample = cases[1].build(request);
    const std::vector<std::uint8_t> der = sample.getDER();
    const auto start = std::chrono::steady_clock::now();
    std::size_t sink = 0;
    for (int n = 0; n < 20000; ++n) {
        const ASN1Instance back = ASN1Instance::decode(request, der);
        sink += back.get("id").asInteger() > 0 ? 1 : 0;
    }
    const auto end = std::chrono::steady_clock::now();
    const double ms = std::chrono::duration<double, std::milli>(end - start).count();
    std::printf("  decode: %6.2f us/value  (%.0f MB/s), checksum %zu\n", ms * 1000.0 / 20000.0,
                static_cast<double>(der.size()) * 20000.0 / ms / 1024.0, sink);
    return 0;
}