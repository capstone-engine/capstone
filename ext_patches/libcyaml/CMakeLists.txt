cmake_minimum_required(VERSION 3.15)
project(libcyaml VERSION 1.4.2 LANGUAGES C)

# Version defines
add_compile_definitions(
  VERSION_MAJOR=1
  VERSION_MINOR=4
  VERSION_PATCH=2
)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Source files
set(LIBCYAML_SRC
  ${CMAKE_SOURCE_DIR}/src/mem.c
  ${CMAKE_SOURCE_DIR}/src/free.c
  ${CMAKE_SOURCE_DIR}/src/load.c
  ${CMAKE_SOURCE_DIR}/src/save.c
  ${CMAKE_SOURCE_DIR}/src/util.c
  ${CMAKE_SOURCE_DIR}/src/utf8.c
)

# Include directories
include_directories(include)

# Find libyaml
if (NOT USE_BUILT_LIBYAML)
  find_library(libyaml NAMES libyaml yaml REQUIRED)
endif()
include_directories(${LIBYAML_INCLUDE_DIRS})
link_directories(${LIBYAML_LIBRARY_DIRS})

add_library(cyaml_static STATIC ${LIBCYAML_SRC})
