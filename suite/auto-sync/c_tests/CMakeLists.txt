cmake_minimum_required(VERSION 3.15)

set(AUTO_SYNC_C_TEST_SRC_DIR ${AUTO_SYNC_C_TEST_DIR}/src)
set(AUTO_SYNC_C_TEST_INC_DIR ${AUTO_SYNC_C_TEST_DIR}/include)

include_directories(${AUTO_SYNC_C_TEST_INC_DIR} ${PROJECT_SOURCE_DIR}/include)

file(GLOB AUTO_SYNC_C_SRC ${AUTO_SYNC_C_TEST_SRC_DIR}/*.c)
add_executable(compat_header_build_test ${AUTO_SYNC_C_SRC})
add_dependencies(compat_header_build_test capstone)
target_link_libraries(compat_header_build_test PUBLIC capstone)

add_test(NAME ASCompatibilityHeaderTest
  COMMAND compat_header_build_test
  WORKING_DIRECTORY ${AUTO_SYNC_C_TEST_DIR}
)
