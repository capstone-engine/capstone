cmake_minimum_required(VERSION 3.15)

# Enable DOWNLOAD_EXTRACT_TIMESTAMP
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

include(ExternalProject)
find_library(libyaml
    NAMES libyaml yaml
    REQUIRED)
set(CMOCKA_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/extern/src/cmocka_ext-build/src/libcmocka.a")

ExternalProject_Add(cmocka_ext
    PREFIX extern
    URL "https://cmocka.org/files/1.1/cmocka-1.1.7.tar.xz"
    URL_HASH SHA256=810570eb0b8d64804331f82b29ff47c790ce9cd6b163e98d47a4807047ecad82
    CONFIGURE_COMMAND cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} ../cmocka_ext/
    BUILD_COMMAND cmake --build . --config Release
    BUILD_BYPRODUCTS "${CMOCKA_LIB_FILE}"
    INSTALL_COMMAND ""
)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(LIBCYAML_VARIANT "debug")
else()
    set(LIBCYAML_VARIANT "release")
endif()

set(LIBCYAML_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext/build/${LIBCYAML_VARIANT}/libcyaml.a")
ExternalProject_Add(libcyaml_ext
    PREFIX extern
    URL "https://github.com/tlsa/libcyaml/archive/refs/tags/v1.4.2.tar.gz"
    URL_HASH SHA256=3211b2a0589ebfe02c563c96adce9246c0787be2af30353becbbd362998d16dc
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make VARIANT=${LIBCYAML_VARIANT} PKG_CONFIG=pkg-config
    BUILD_BYPRODUCTS "${LIBCYAML_LIB_FILE}"
    BUILD_IN_SOURCE true
    INSTALL_COMMAND ""
)
set(CMOCKA_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/extern/src/cmocka_ext/include)
set(LIBCYAML_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext/include)
add_library(cmocka STATIC IMPORTED)
add_library(libcyaml STATIC IMPORTED)
set_target_properties(cmocka PROPERTIES IMPORTED_LOCATION "${CMOCKA_LIB_FILE}")
set_target_properties(libcyaml PROPERTIES IMPORTED_LOCATION "${LIBCYAML_LIB_FILE}")

set(CSTEST_INCLUDE_DIR ${CSTEST_DIR}/include)
file(GLOB CSTEST_SRC ${CSTEST_DIR}/src/*.c)
add_executable(cstest ${CSTEST_SRC})
add_library(libcstest STATIC ${CSTEST_SRC})
add_dependencies(cstest cmocka_ext)
add_dependencies(cstest libcyaml_ext)
target_link_libraries(cstest PUBLIC capstone cmocka libcyaml ${libyaml})
target_link_libraries(libcstest PUBLIC capstone cmocka libcyaml ${libyaml})
target_include_directories(cstest PRIVATE
        ${PROJECT_SOURCE_DIR}/include>
        ${CSTEST_INCLUDE_DIR}
        ${CMOCKA_INCLUDE_DIR}
        ${LIBCYAML_INCLUDE_DIR}
        )
target_include_directories(libcstest PRIVATE
        ${PROJECT_SOURCE_DIR}/include>
        ${CSTEST_INCLUDE_DIR}
        ${CMOCKA_INCLUDE_DIR}
        ${LIBCYAML_INCLUDE_DIR}
        )

# Unit tests for cstest
set(CSTEST_TEST_DIR ${CSTEST_DIR}/test/)
add_subdirectory(${CSTEST_TEST_DIR})

# Test targets
add_test(MCTests
    cstest ${PROJECT_SOURCE_DIR}/tests/MC
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(DetailTests
    cstest ${PROJECT_SOURCE_DIR}/tests/details
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(IssueTests
    cstest ${PROJECT_SOURCE_DIR}/tests/issues
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(FeaturesTests
    cstest ${PROJECT_SOURCE_DIR}/tests/features
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

# These tests must be run independently. Otherwise we won't detect when one succeeds.
# Because cstest will always return not 0 from the first failing test onwards.
# But we need to ensure all of them fail always.
add_test(NegativeTests1
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_I.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests1 PROPERTY WILL_FAIL TRUE)
add_test(NegativeTests2
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_II.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests2 PROPERTY WILL_FAIL TRUE)
add_test(NegativeTests3
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_III.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests3 PROPERTY WILL_FAIL TRUE)
add_test(NegativeTests4
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_IV.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests4 PROPERTY WILL_FAIL TRUE)
add_test(NegativeTests5
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_V.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests5 PROPERTY WILL_FAIL TRUE)
add_test(NegativeTests6
    cstest ${PROJECT_SOURCE_DIR}/tests/negative/should_fail_VI.yaml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
set_property(TEST NegativeTests6 PROPERTY WILL_FAIL TRUE)


if(CAPSTONE_INSTALL)
    install(TARGETS cstest EXPORT capstone-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
