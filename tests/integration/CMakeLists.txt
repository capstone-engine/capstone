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
