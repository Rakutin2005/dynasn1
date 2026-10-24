cmake_minimum_required(VERSION 3.20)

project(dynasn1
        VERSION 1.0.0
        DESCRIPTION "A description driven encoder and decoder for ASN.1 DER"
        LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(DYNASN1_BUILD_TESTS "Build the test suite" ON)
option(DYNASN1_BUILD_BENCHMARKS "Build the benchmarks" ON)
option(DYNASN1_INSTALL "Generate the install rules" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# -------------------------------------------------------------------------------------------------
# The library
# -------------------------------------------------------------------------------------------------

add_library(dynasn1
        src/ASN1.cpp
        src/ASN1BigInt.cpp
        src/ASN1Codec.cpp
        src/ASN1Instance.cpp
        src/ASN1Schema.cpp
        src/ASN1Value.cpp
        include/dynasn1/ASN1.h
        include/dynasn1/ASN1BigInt.h
        include/dynasn1/ASN1Codec.h
        include/dynasn1/ASN1Exception.h
        include/dynasn1/ASN1Instance.h
        include/dynasn1/ASN1Schema.h
        include/dynasn1/ASN1Value.h)

add_library(dynasn1::dynasn1 ALIAS dynasn1)

target_include_directories(dynasn1
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(dynasn1 PUBLIC cxx_std_20)

# A module is its own shared object and links this library, so the objects have to be position
# independent even when the library itself is static.
set_target_properties(dynasn1 PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        EXPORT_NAME dynasn1)

# The library is warning clean; keep it that way for anyone who builds it in tree.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dynasn1 PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()

# -------------------------------------------------------------------------------------------------
# Tests and benchmarks
# -------------------------------------------------------------------------------------------------

if(DYNASN1_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(DYNASN1_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# -------------------------------------------------------------------------------------------------
# Install, so that the project can be consumed with find_package(dynasn1)
# -------------------------------------------------------------------------------------------------

if(DYNASN1_INSTALL)
    install(TARGETS dynasn1
            EXPORT dynasn1Targets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(DIRECTORY include/dynasn1
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            FILES_MATCHING PATTERN "*.h")

    install(EXPORT dynasn1Targets
            FILE dynasn1Targets.cmake
            NAMESPACE dynasn1::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dynasn1)

    configure_package_config_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/dynasn1Config.cmake.in
            ${CMAKE_CURRENT_BINARY_DIR}/dynasn1Config.cmake
            INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dynasn1)

    write_basic_package_version_file(
            ${CMAKE_CURRENT_BINARY_DIR}/dynasn1ConfigVersion.cmake
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion)

    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/dynasn1Config.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/dynasn1ConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dynasn1)
endif()