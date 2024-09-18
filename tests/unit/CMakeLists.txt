cmake_minimum_required(VERSION 3.15)

enable_testing()
set(UNIT_TEST_SOURCES sstream.c utils.c)
include_directories(include)

foreach(TSRC ${UNIT_TEST_SOURCES})
    string(REGEX REPLACE ".c$" "" TBIN ${TSRC})
    add_executable(${TBIN} "${TESTS_UNIT_DIR}/${TSRC}")
    target_link_libraries(${TBIN} PRIVATE capstone)
    add_test(NAME "unit_${TBIN}" COMMAND ${TBIN})
endforeach()
