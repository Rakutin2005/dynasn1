// Proves the timestamp carrier does not depend on the platform clock already counting
// nanoseconds: the stored type is spelled out, and a coarser point still converts in.
#include "dynasn1/ASN1Value.h"

#include <chrono>
#include <cstdio>
#include <type_traits>

using Point = ASN1Value::Timestamp;

static_assert(std::is_same_v<Point, std::chrono::time_point<std::chrono::system_clock,
                                                             std::chrono::nanoseconds>>,
              "the carrier must be a nanosecond time point whatever the platform clock uses");

int main() {
    // The library's own precision reaches full nanoseconds.
    const ASN1Value exact(Point(std::chrono::nanoseconds(1765432212123456789LL)));
    if (exact.asTime().time_since_epoch().count() != 1765432212123456789LL) {
        std::printf("FAIL: nanosecond precision lost\n");
        return 1;
    }
    // A point from a coarser clock converts without losing anything it had.
    const std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds> coarse{
            std::chrono::microseconds(1765432212LL * 1000000LL + 123456LL)};
    const ASN1Value converted(coarse);
    if (converted.asTime().time_since_epoch().count() != 1765432212123456000LL) {
        std::printf("FAIL: microsecond point did not convert\n");
        return 1;
    }
    // A plain system_clock point converts too.
    const ASN1Value direct(std::chrono::system_clock::time_point(
            std::chrono::nanoseconds(1765432212123456789LL)));
    if (direct.asTime().time_since_epoch().count() != 1765432212123456789LL) {
        std::printf("FAIL: system_clock point did not convert\n");
        return 1;
    }
    std::printf("ok: the carrier is nanoseconds on any clock, conversions keep precision\n");
    return 0;
}