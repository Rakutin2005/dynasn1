# Benchmarks are not tests: they print numbers and are meant to be run and read, not asserted on.
# They land in <build>/benchmarks so a plain `ctest` run never picks them up.

function(dynasn1_benchmark name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE dynasn1::dynasn1)
    target_compile_features(${name} PRIVATE cxx_std_20)
    set_target_properties(${name} PROPERTIES
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# Byte counts against JSON and XML, including the cost of the description itself. No dependencies.
dynasn1_benchmark(size)

# The shapes this library is actually pointed at: wide amounts, sub second timestamps, alias tags.
dynasn1_benchmark(domain)

# The two benchmarks below compare against a third party JSON parser, so they only build when one
# is installed. The library itself has no such dependency and never will.
find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
    dynasn1_benchmark(speed)

    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        add_executable(compare compare.cpp)
        target_link_libraries(compare PRIVATE dynasn1::dynasn1 nlohmann_json::nlohmann_json
                                             ZLIB::ZLIB)
        target_compile_features(compare PRIVATE cxx_std_20)
        set_target_properties(compare PROPERTIES
                CXX_STANDARD 20
                CXX_STANDARD_REQUIRED ON
                CXX_EXTENSIONS OFF
                RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(compare PRIVATE -Wall -Wextra)
        endif()
    else()
        message(STATUS "dynasn1: zlib not found, the compare benchmark is skipped")
    endif()
else()
    message(STATUS "dynasn1: nlohmann/json not found, the speed and compare benchmarks are skipped")
endif()