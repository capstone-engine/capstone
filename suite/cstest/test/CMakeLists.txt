cmake_minimum_required(VERSION 3.15)

set(CSTEST_TEST_SRC_DIR ${CSTEST_TEST_DIR}/src)
set(CSTEST_TEST_INC_DIR ${CSTEST_TEST_DIR}/include)

include_directories(${CSTEST_TEST_INC_DIR}
  ${CSTEST_INCLUDE_DIR}
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/include)

file(GLOB CSTEST_TEST_SRC ${CSTEST_TEST_SRC_DIR}/*.c)
add_executable(unit_test ${CSTEST_TEST_SRC})
add_dependencies(unit_test libcstest)
target_link_libraries(unit_test PUBLIC libcstest)

add_test(NAME unit_cstest
  COMMAND unit_test
  WORKING_DIRECTORY ${CSTEST_TEST_DIR}
)
add_test(NAME integration_cstest
  COMMAND python3 ${CSTEST_TEST_DIR}/integration_tests.py cstest
  WORKING_DIRECTORY ${CSTEST_TEST_DIR}
)
