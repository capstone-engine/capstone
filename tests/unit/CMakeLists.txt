cmake_minimum_required(VERSION 3.15)

# Old integration tests.
if (CAPSTONE_BUILD_LEGACY_TESTS)
  enable_testing()
  set(UNIT_TEST_SOURCES sstream.c)

  foreach(TSRC ${UNIT_TEST_SOURCES})
      string(REGEX REPLACE ".c$" "" TBIN ${TSRC})
      add_executable(${TBIN} "${TESTS_UNIT_DIR}/${TSRC}")
      target_link_libraries(${TBIN} PRIVATE capstone)
      add_test(NAME "unit_${TBIN}" COMMAND ${TBIN})
  endforeach()
endif()
