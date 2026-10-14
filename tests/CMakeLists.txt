# Every test links the library and nothing else: the suite is also the consumer documentation.

function(dynasn1_test name)
    cmake_parse_arguments(ARG "" "" "SOURCES;LIBRARIES" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_link_libraries(${name} PRIVATE dynasn1::dynasn1 ${ARG_LIBRARIES})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    set_target_properties(${name} PROPERTIES
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# The worked example: builds a description, encodes, decodes, compares. A hundred assertions over
# the whole type set, the builder, the constraints and the hardening. Prints what it checks.
dynasn1_test(demo SOURCES demo.cpp)

# Arbitrary precision integers against vectors computed by Python, see tools/ref_bigint.py.
# Regenerate the vectors with:  python3 tools/ref_bigint.py
add_executable(test_bigint test_bigint.cpp)
target_link_libraries(test_bigint PRIVATE dynasn1::dynasn1)
target_compile_features(test_bigint PRIVATE cxx_std_20)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_bigint PRIVATE -Wall -Wextra)
endif()
add_test(NAME bigint
         COMMAND test_bigint ${CMAKE_CURRENT_SOURCE_DIR}/data/bigint_vectors.txt)

# Timestamps: the exact octets X.690 11.7 prescribes, and everything DER forbids.
dynasn1_test(time SOURCES test_time.cpp)

# The timestamp carrier must not depend on the platform clock already counting nanoseconds.
dynasn1_test(portability SOURCES test_portability.cpp)