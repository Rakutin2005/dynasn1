//
// Speed and navigation cost: the DER codec vs nlohmann/json, and where navigation inside the
// ASN.1 module is cheap and where it is not.
//

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "dynasn1/ASN1.h"
#include "dynasn1/ASN1Instance.h"

// ---------------------------------------------------------------- global allocation counter
namespace {
std::size_t g_allocations = 0;
std::size_t g_bytes = 0;
bool g_counting = false;
}  // namespace

void *operator new(std::size_t size) {
    if (g_counting) {
        ++g_allocations;
        g_bytes += size;
    }
    void *p = std::malloc(size ? size : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void *operator new[](std::size_t size) { return operator new(size); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
// Replacing the global allocator is the only portable way to count allocations. Allocation and
// release do match up, but the compiler cannot see it across the boundary and complains anyway.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
#pragma GCC diagnostic pop

namespace {

using Clock = std::chrono::steady_clock;

template <class Body> double measureNs(int repeats, Body &&body) {
    const auto start = Clock::now();
    for (int n = 0; n < repeats; ++n) body();
    const auto end = Clock::now();
    return std::chrono::duration<double, std::nano>(end - start).count() / repeats;
}

template <class Body> void timed(const char *what, std::size_t size, int repeats, Body &&body) {
    const double ns = measureNs(repeats, body);
    std::printf("  %-44s %8.0f ns  %8.1f MB/s\n", what, ns,
                ns > 0 ? static_cast<double>(size) / ns : 0.0);
}

template <class Body> void alloc(const char *what, Body &&body) {
    g_allocations = 0;
    g_bytes = 0;
    g_counting = true;
    body();
    g_counting = false;
    std::printf("  %-44s %6zu allocs  %8zu bytes\n", what, g_allocations, g_bytes);
}

using nlohmann::json;

json toJson(const ASN1Value &value) {
    switch (value.type()) {
        case ASN1Value::Type::boolean: return json(value.asBoolean());
        case ASN1Value::Type::integer: return json(value.asInteger());
        case ASN1Value::Type::string: return json(value.asString());
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

json toJson(const ASN1Instance &instance) {
    json out = json::object();
    for (const ASN1Field &field : instance.value().asSequence()) out[field.name] = toJson(field.value);
    return out;
}

}  // namespace

int main() {
    ASN1 clause = ASN1::sequence("Clause");
    clause.field("guard", ASN1::boolean());
    clause.field("target", ASN1::reference("Clause").optional());
    clause.field("amount", ASN1::octetString().withSize(0, 64));

    ASN1 procedure = ASN1::sequence("Procedure");
    procedure.field("name", ASN1::utf8String().withSize(1, 32));
    procedure.field("weight", ASN1::integer().withRange(0, 1'000'000));
    procedure.field("clauses", ASN1::sequenceOf(ASN1::reference("Clause")));

    ASN1 plan = ASN1::sequence("Plan");
    plan.named("Clause", clause);
    plan.named("Procedure", procedure);
    plan.field("procedure", ASN1::reference("Procedure"));
    plan.field("version", ASN1::integer().withDefault(1));

    ASN1Instance instance = plan.getInstance();
    ASN1Value::Sequence procedureFields;
    procedureFields.push_back({"name", ASN1Value("settle")});
    procedureFields.push_back({"weight", ASN1Value(100)});
    ASN1Value::List clauses;
    for (int n = 0; n < 4; ++n) {
        ASN1Value::Sequence one;
        one.push_back({"guard", ASN1Value(n % 2 == 0)});
        one.push_back({"amount", ASN1Value(std::vector<std::uint8_t>{1, 2, 3})});
        clauses.push_back(ASN1Value(std::move(one)));
    }
    procedureFields.push_back({"clauses", ASN1Value(std::move(clauses))});
    instance.set("procedure", ASN1Value(std::move(procedureFields)));

    const std::vector<std::uint8_t> der = instance.getDER();
    const std::string jsonText = toJson(instance).dump();

    std::printf("payload: DER %zu bytes, JSON %zu bytes, description has %zu nodes\n\n", der.size(),
                jsonText.size(), plan.size());

    // ------------------------------------------------------------------ throughput
    std::printf("== throughput ==\n");
    std::vector<std::uint8_t> sinkBuffer(der.size() + 64);
    timed("DER encode into a reusable buffer", der.size(), 100000,
          [&] { instance.encodeTo(sinkBuffer); });
    timed("DER decode into an instance", der.size(), 50000,
          [&] { (void)ASN1Instance::decode(plan, der); });
    timed("JSON parse into a DOM", jsonText.size(), 50000,
          [&] { (void)json::parse(jsonText).size(); });
    timed("JSON build a DOM from the value tree", jsonText.size(), 50000,
          [&] { (void)toJson(instance).dump().size(); });

    // ------------------------------------------------------------------ allocations
    std::printf("\n== allocations per operation ==\n");
    alloc("DER encode into a reusable buffer", [&] { instance.encodeTo(sinkBuffer); });
    alloc("DER decode into an instance", [&] { (void)ASN1Instance::decode(plan, der); });
    alloc("JSON parse into a DOM", [&] { (void)json::parse(jsonText).size(); });
    alloc("JSON build a DOM from the value tree", [&] { (void)toJson(instance).dump(); });

    // ------------------------------------------------------------------ navigation
    std::printf("\n== navigation, 1e6 operations ==\n");
    const ASN1Instance decoded = ASN1Instance::decode(plan, der);
    const json document = json::parse(jsonText);
    volatile std::size_t sink = 0;

    timed("DER: get(\"procedure\") by name", 0, 1000000, [&] { sink += decoded.get("procedure").index(); });
    timed("DER: value().asSequence()[0] by index", 0, 1000000,
          [&] { sink += decoded.value().asSequence()[0].value.index(); });
    timed("DER: full tree walk by index", 0, 200000, [&] {
        std::size_t total = 0;
        for (const ASN1Field &field : decoded.value().asSequence()) {
            total += field.name.size();
            if (field.value.is<ASN1Value::List>())
                for (const ASN1Value &item : field.value.asList()) total += item.asSequence().size();
        }
        sink += total;
    });
    timed("JSON: document[\"procedure\"] by key", 0, 1000000,
          [&] { sink += document["procedure"].size(); });
    timed("JSON: full tree walk by key", 0, 200000, [&] {
        std::size_t total = 0;
        for (auto it = document.begin(); it != document.end(); ++it) {
            total += it.key().size();
            if (it->is_array()) total += it->size();
        }
        sink += total;
    });

    // ------------------------------------------------------------------ one time vs per call
    std::printf("\n== one time vs per call ==\n");
    timed("getInstance() on a description already validated", 0, 200000,
          [&] { (void)plan.getInstance(); });
    timed("fromNotation(), rebuild from the binary description", 0, 5000,
          [&] { (void)ASN1::fromNotation(plan.notation()); });
    timed("notation(), already serialised", 0, 200000, [&] {
        ASN1 copy = plan;
        (void)copy.notation().size();
    });
    timed("notation(), after a change (re-serialises)", 0, 2000, [&] {
        ASN1 copy = plan;
        copy.field("extra", ASN1::integer());
        (void)copy.notation().size();
    });
    {
        ASN1Instance cached = plan.getInstance();
        cached.set("procedure", decoded.value().asSequence()[0].value);
        (void)cached.getDER();
        timed("getDER() from the warm cache", 0, 200000, [&] { (void)cached.getDER(); });
    }
    return 0;
}