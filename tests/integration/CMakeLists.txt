cmake_minimum_required(VERSION 3.15)

# Old integration tests.
if (CAPSTONE_BUILD_LEGACY_TESTS)
  enable_testing()
  set(TEST_SOURCES test_skipdata.c test_iter.c)
  if(CAPSTONE_X86_SUPPORT)
    set(TEST_SOURCES ${TEST_SOURCES} test_customized_mnem.c)
  endif()

  foreach(TSRC ${TEST_SOURCES})
      string(REGEX REPLACE ".c$" "" TBIN ${TSRC})
      add_executable(${TBIN} "${TESTS_INTEGRATION_DIR}/${TSRC}")
      target_link_libraries(${TBIN} PRIVATE capstone)
      add_test(NAME "legacy_${TBIN}" COMMAND ${TBIN})
  endforeach()
endif()

# Compatibility header test
set(COMPAT_C_TEST_DIR ${TESTS_INTEGRATION_DIR}/compat_header)
set(COMPAT_C_TEST_SRC_DIR ${COMPAT_C_TEST_DIR}/src)
set(COMPAT_C_TEST_INC_DIR ${COMPAT_C_TEST_DIR}/include)

include_directories(${COMPAT_C_TEST_INC_DIR} ${PROJECT_SOURCE_DIR}/include)

file(GLOB COMPAT_C_SRC ${COMPAT_C_TEST_SRC_DIR}/*.c)
add_executable(compat_header_build_test ${COMPAT_C_SRC})
add_dependencies(compat_header_build_test capstone)
target_link_libraries(compat_header_build_test PUBLIC capstone)

add_test(NAME integration_compat_headers
  COMMAND compat_header_build_test
  WORKING_DIRECTORY ${COMPAT_C_TEST_DIR}
)

set(INTEGRATION_TEST_SRC test_litbase.c)
foreach(TSRC ${INTEGRATION_TEST_SRC})
      string(REGEX REPLACE ".c$" "" TBIN ${TSRC})
      add_executable(${TBIN} "${TESTS_INTEGRATION_DIR}/${TSRC}")
      target_link_libraries(${TBIN} PRIVATE capstone)
      add_test(NAME "integration_${TBIN}" COMMAND ${TBIN})
  endforeach()
