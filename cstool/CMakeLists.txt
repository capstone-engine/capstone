# Cstool for Capstone disassembler engine.
# By Nguyen Anh Quynh, 2016

cmake_minimum_required(VERSION 2.8)

project(cstool)

include_directories("../include")

add_executable(cstool cstool.c)

target_link_libraries(cstool capstone)

install(TARGETS cstool DESTINATION bin)
