cmake_minimum_required(VERSION 3.15)

# Enable DOWNLOAD_EXTRACT_TIMESTAMP
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

include(ExternalProject)
set(CMOCKA_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/extern/src/cmocka_ext-build/src/libcmocka.a")

# CMocka is the unit testing library we use.
ExternalProject_Add(cmocka_ext
    PREFIX extern
    URL "https://cmocka.org/files/1.1/cmocka-1.1.7.tar.xz"
    URL_HASH SHA256=810570eb0b8d64804331f82b29ff47c790ce9cd6b163e98d47a4807047ecad82
    CMAKE_ARGS
        -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DANDROID_NDK=${ANDROID_NDK}
        -DANDROID_PLATFORM=${ANDROID_PLATFORM}
        -DANDROID_ABI=${ANDROID_ABI}
    BUILD_BYPRODUCTS "${CMOCKA_LIB_FILE}"
    INSTALL_COMMAND ""
)
set(CMOCKA_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/extern/src/cmocka_ext/include)
add_library(cmocka STATIC IMPORTED)
set_target_properties(cmocka PROPERTIES IMPORTED_LOCATION "${CMOCKA_LIB_FILE}")

# libyaml is used to parse the test files.
# Normally it can be installed via the package managers,
# but Windows and cross-compile targets might not have it.
# So it builds it optionally as well.
set(USE_BUILT_LIBYAML false)
find_library(libyaml NAMES libyaml yaml)
if (NOT libyaml)
    # Build libyaml
    set(USE_BUILT_LIBYAML true)
    message("System libyaml: NO - Building it.")
    set(LIBYAML_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libyaml_ext-build/libyaml.a")
    set(LIBYAML_LIBRARY_DIRS "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libyaml_ext-build/")
    set(LIBYAML_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libyaml_ext/include")
    ExternalProject_Add(libyaml_ext
        PREFIX extern
        URL "https://github.com/yaml/libyaml/archive/refs/tags/0.2.5.tar.gz"
        URL_HASH SHA256=fa240dbf262be053f3898006d502d514936c818e422afdcf33921c63bed9bf2e
        # URL "https://github.com/yaml/libyaml/archive/refs/tags/0.1.7.tar.gz"
        # URL_HASH SHA256=e1884d0fa1eec8cf869ac6bebbf25391e81956aa2970267f974a9fa5e0b968e2
        CMAKE_ARGS
            -DCMAKE_POLICY_VERSION_MINIMUM=3.5
            -DBUILD_TESTING=OFF
            -DBUILD_SHARED_LIBS=OFF
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DANDROID_NDK=${ANDROID_NDK}
            -DANDROID_PLATFORM=${ANDROID_PLATFORM}
            -DANDROID_ABI=${ANDROID_ABI}
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        BUILD_BYPRODUCTS "${LIBYAML_LIB_FILE}"
        INSTALL_COMMAND ""
    )
    add_library(libyaml_built STATIC IMPORTED)
    set_target_properties(libyaml_built PROPERTIES IMPORTED_LOCATION "${LIBYAML_LIB_FILE}")
    set_target_properties(libyaml_built PROPERTIES INCLUDE_DIRECTORIES "${LIBYAML_INCLUDE_DIRS}")
    set_target_properties(libyaml_built PROPERTIES LIBRARY_DIRECTORIES "${LIBYAML_LIB_DIR}")
else()
    message("System libyaml: YES")
endif()

# Libcyaml is a wrapper library around libyaml.
# It parses the yaml files so we don't have to.
# Sadly it has no CMakeLists.txt. So we patch it into.
set(LIBCYAML_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext/include")

set(LIBCYAML_LIB_FILE "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext-build/lib/libcyaml_static.a")
set(LIBCYAML_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext-build/lib/")
set(LIBCYAML_SRC_DIR "${CMAKE_CURRENT_BINARY_DIR}/extern/src/libcyaml_ext/")
ExternalProject_Add(libcyaml_ext
    PREFIX extern
    URL "https://github.com/tlsa/libcyaml/archive/refs/tags/v1.4.2.tar.gz"
    URL_HASH SHA256=3211b2a0589ebfe02c563c96adce9246c0787be2af30353becbbd362998d16dc
    PATCH_COMMAND cmake -E copy_if_different ${EXTERNAL_PROJ_PATCH_DIR}/libcyaml/CMakeLists.txt ${LIBCYAML_SRC_DIR}
    CMAKE_ARGS
        -DUSE_BUILT_LIBYAML=${USE_BUILT_LIBYAML}
        -DLIBYAML_INCLUDE_DIRS=${LIBYAML_INCLUDE_DIRS}
        -DLIBYAML_LIBRARY_DIRS=${LIBYAML_LIBRARY_DIRS}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DANDROID_NDK=${ANDROID_NDK}
        -DANDROID_PLATFORM=${ANDROID_PLATFORM}
        -DANDROID_ABI=${ANDROID_ABI}
    BUILD_BYPRODUCTS "${LIBCYAML_LIB_FILE}"
    INSTALL_COMMAND ""
)

add_library(libcyaml STATIC IMPORTED)
set_target_properties(libcyaml PROPERTIES IMPORTED_LOCATION "${LIBCYAML_LIB_FILE}")
set_target_properties(libcyaml PROPERTIES INCLUDE_DIRECTORIES "${LIBCYAML_INCLUDE_DIR}")
set_target_properties(libcyaml PROPERTIES LIBRARY_DIRECTORIES "${LIBCYAML_LIBRARY_DIR}")
if (USE_BUILT_LIBYAML)
    add_dependencies(libcyaml libyaml_ext)
    add_dependencies(libcyaml libyaml_built)
    target_link_libraries(libcyaml INTERFACE libyaml_built)
else()
    add_dependencies(libcyaml ${libyaml})
    target_link_libraries(libcyaml INTERFACE ${libyaml})
endif()

# The final cstest binary and library.
set(CSTEST_INCLUDE_DIR ${CSTEST_DIR}/include)
file(GLOB CSTEST_SRC ${CSTEST_DIR}/src/*.c)
add_executable(cstest ${CSTEST_SRC})
add_library(libcstest STATIC ${CSTEST_SRC})
set_property(TARGET libcstest PROPERTY OUTPUT_NAME cstest)

add_dependencies(cstest cmocka_ext)
add_dependencies(cstest libcyaml_ext)
add_dependencies(libcstest cmocka_ext)
add_dependencies(libcstest libcyaml_ext)

if (USE_BUILT_LIBYAML)
    target_link_libraries(cstest PUBLIC capstone cmocka libcyaml libyaml_built)
    target_link_libraries(libcstest PUBLIC capstone cmocka libcyaml libyaml_built)
else()
    target_link_libraries(cstest PUBLIC capstone cmocka libcyaml ${libyaml})
    target_link_libraries(libcstest PUBLIC capstone cmocka libcyaml ${libyaml})
endif()

target_include_directories(cstest PRIVATE
        ${PROJECT_SOURCE_DIR}/include>
        ${CSTEST_INCLUDE_DIR}
        ${CMOCKA_INCLUDE_DIR}
        ${LIBCYAML_INCLUDE_DIR}
        ${LIBYAML_INCLUDE_DIRS}
        )
target_include_directories(libcstest PRIVATE
        ${PROJECT_SOURCE_DIR}/include>
        ${CSTEST_INCLUDE_DIR}
        ${CMOCKA_INCLUDE_DIR}
        ${LIBCYAML_INCLUDE_DIR}
        ${LIBYAML_INCLUDE_DIRS}
        )

# Unit tests for cstest
set(CSTEST_TEST_DIR ${CSTEST_DIR}/test/)
add_subdirectory(${CSTEST_TEST_DIR})

# Test targets
add_test(NAME MCTests
    COMMAND cstest ${PROJECT_SOURCE_DIR}/tests/MC
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(NAME DetailTests
    COMMAND cstest ${PROJECT_SOURCE_DIR}/tests/details
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(NAME IssueTests
    COMMAND cstest ${PROJECT_SOURCE_DIR}/tests/issues
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
add_test(NAME FeaturesTests
    COMMAND cstest ${PROJECT_SOURCE_DIR}/tests/features
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
