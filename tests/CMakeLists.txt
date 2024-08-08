cmake_minimum_required(VERSION 3.15)

# Old integration tests.
if (CAPSTONE_BUILD_LEGACY_TESTS)
  enable_testing()
  set(TEST_SOURCES test_basic.c test_skipdata.c test_iter.c)
  if(CAPSTONE_X86_SUPPORT)
    set(TEST_SOURCES ${TEST_SOURCES} test_customized_mnem.c)
  endif()

  foreach(TSRC ${TEST_SOURCES})
      string(REGEX REPLACE ".c$" "" TBIN ${TSRC})
      add_executable(${TBIN} "${TESTS_DIR}/${TSRC}")
      target_link_libraries(${TBIN} PRIVATE capstone)
      add_test(NAME "legacy_${TBIN}" COMMAND ${TBIN})
  endforeach()
  # fuzz target built with the tests
  add_executable(fuzz_disasm ${PROJECT_SOURCE_DIR}/suite/fuzz/onefile.c ${PROJECT_SOURCE_DIR}/suite/fuzz/fuzz_disasm.c ${PROJECT_SOURCE_DIR}/suite/fuzz/platform.c)
  target_link_libraries(fuzz_disasm PRIVATE capstone)
endif()
