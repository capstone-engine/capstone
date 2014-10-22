cmake_minimum_required(VERSION 2.6)
project(capstone)

set(VERSION_MAJOR 2)
set(VERSION_MINOR 2)
set(VERSION_PATCH 0)

# to configure the options specify them in in the command line or change them in the cmake UI.
# Don't edit the makefile!
option(CAPSTONE_BUILD_STATIC "Build static library" ON)
option(CAPSTONE_BUILD_SHARED "Build shared library" ON)
option(CAPSTONE_BUILD_DIET "Build diet library" OFF)
option(CAPSTONE_BUILD_TESTS "Build tests" ON)
option(CAPSTONE_USE_DEFAULT_ALLOC "Use default memory allocation functions" ON)

option(CAPSTONE_ARM_SUPPORT "ARM support" ON)
option(CAPSTONE_ARM64_SUPPORT "ARM64 support" ON)
option(CAPSTONE_MIPS_SUPPORT "MIPS support" ON)
option(CAPSTONE_PPC_SUPPORT "PowerPC support" ON)
option(CAPSTONE_SPARC_SUPPORT "Sparc support" ON)
option(CAPSTONE_SYSZ_SUPPORT "SystemZ support" ON)
option(CAPSTONE_XCORE_SUPPORT "XCore support" ON)
option(CAPSTONE_X86_SUPPORT "x86 support" ON)
option(CAPSTONE_X86_REDUCE "x86 with reduce instruction sets to minimize library" OFF)
option(CAPSTONE_X86_ATT_DISABLE "Disable x86 AT&T syntax" OFF)

if (CAPSTONE_BUILD_DIET)
    add_definitions(-DCAPSTONE_DIET)
endif ()

if (CAPSTONE_USE_DEFAULT_ALLOC)
    add_definitions(-DCAPSTONE_USE_SYS_DYN_MEM)
endif ()

if (CAPSTONE_X86_REDUCE)
    add_definitions(-DCAPSTONE_X86_REDUCE)
endif ()

if (CAPSTONE_X86_ATT_DISABLE)
    add_definitions(-DCAPSTONE_X86_ATT_DISABLE)
endif ()

## sources
set(SOURCES
    cs.c
    MCInst.c
    MCInstrDesc.c
    MCRegisterInfo.c
    SStream.c
    utils.c
    )

set(TEST_SOURCES test.c test_detail.c test_skipdata.c test_iter.c)

## architecture support
if (CAPSTONE_ARM_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_ARM)
    set(SOURCES
        ${SOURCES}
        arch/ARM/ARMDisassembler.c
        arch/ARM/ARMInstPrinter.c
        arch/ARM/ARMMapping.c
        arch/ARM/ARMModule.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_arm.c)
endif ()

if (CAPSTONE_ARM64_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_ARM64)
    set(SOURCES
        ${SOURCES}
        arch/AArch64/AArch64BaseInfo.c
        arch/AArch64/AArch64Disassembler.c
        arch/AArch64/AArch64InstPrinter.c
        arch/AArch64/AArch64Mapping.c
        arch/AArch64/AArch64Module.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_arm64.c)
endif ()

if (CAPSTONE_MIPS_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_MIPS)
    set(SOURCES
        ${SOURCES}
        arch/Mips/MipsDisassembler.c
        arch/Mips/MipsInstPrinter.c
        arch/Mips/MipsMapping.c
        arch/Mips/MipsModule.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_mips.c)
endif ()

if (CAPSTONE_PPC_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_POWERPC)
    set(SOURCES
        ${SOURCES}
        arch/PowerPC/PPCDisassembler.c
        arch/PowerPC/PPCInstPrinter.c
        arch/PowerPC/PPCMapping.c
        arch/PowerPC/PPCModule.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_ppc.c)
endif ()

if (CAPSTONE_X86_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_X86)
    set(SOURCES
        ${SOURCES}
        arch/X86/X86Disassembler.c
        arch/X86/X86DisassemblerDecoder.c
        arch/X86/X86IntelInstPrinter.c
        arch/X86/X86Mapping.c
        arch/X86/X86Module.c
        )
    if (NOT CAPSTONE_BUILD_DIET)
        set(SOURCES ${SOURCES} arch/X86/X86ATTInstPrinter.c)
    endif ()
    set(TEST_SOURCES ${TEST_SOURCES} test_x86.c)
endif ()

if (CAPSTONE_SPARC_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_SPARC)
    set(SOURCES
        ${SOURCES}
	arch/Sparc/SparcDisassembler.c
	arch/Sparc/SparcInstPrinter.c
	arch/Sparc/SparcMapping.c
	arch/Sparc/SparcModule.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_sparc.c)
endif ()

if (CAPSTONE_SYSZ_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_SYSZ)
    set(SOURCES
        ${SOURCES}
	arch/SystemZ/SystemZDisassembler.c
	arch/SystemZ/SystemZInstPrinter.c
	arch/SystemZ/SystemZMapping.c
	arch/SystemZ/SystemZModule.c
	arch/SystemZ/SystemZMCTargetDesc.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_systemz.c)
endif ()

if (CAPSTONE_XCORE_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_XCORE)
    set(SOURCES
        ${SOURCES}
	arch/XCore/XCoreDisassembler.c
	arch/XCore/XCoreInstPrinter.c
	arch/XCore/XCoreMapping.c
	arch/XCore/XCoreModule.c
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_xcore.c)
endif ()

include_directories("${PROJECT_SOURCE_DIR}/include")

## properties
# version info
set_property(GLOBAL PROPERTY VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})
set_property(GLOBAL PROPERTY SOVERSION SOVERSION ${VERSION_MAJOR})

## targets
if (CAPSTONE_BUILD_STATIC)
    add_library(capstone-static STATIC ${SOURCES})
    set_property(TARGET capstone-static PROPERTY OUTPUT_NAME capstone)
    set(default-target capstone-static)
endif ()

if (CAPSTONE_BUILD_SHARED)
    add_library(capstone-shared SHARED ${SOURCES})
    set_property(TARGET capstone-shared PROPERTY OUTPUT_NAME capstone)
    set_property(TARGET capstone-shared PROPERTY COMPILE_FLAGS -DCAPSTONE_SHARED)

    if(NOT DEFINED default-target)      # honor `capstone-static` for tests first.
	set(default-target capstone-shared)
	add_definitions(-DCAPSTONE_SHARED)
    endif ()
endif ()

if (CAPSTONE_BUILD_TESTS)
    foreach (TSRC ${TEST_SOURCES})
        STRING(REGEX REPLACE ".c$" "" TBIN ${TSRC})
        add_executable(${TBIN} "tests/${TSRC}")
        target_link_libraries(${TBIN} ${default-target})
    endforeach ()
    if (CAPSTONE_ARM_SUPPORT)
        set(ARM_REGRESS_TEST test_arm_regression.c)
        STRING(REGEX REPLACE ".c$" "" ARM_REGRESS_BIN ${ARM_REGRESS_TEST})
        add_executable(${ARM_REGRESS_BIN} "suite/arm/${ARM_REGRESS_TEST}")
        target_link_libraries(${ARM_REGRESS_BIN} ${default-target})
    endif()
endif ()

## installation
set(INCLUDES arm64.h  arm.h  capstone.h  mips.h  ppc.h  x86.h sparc.h systemz.h xcore.h platform.h)
foreach (INC ${INCLUDES})
    install(FILES "include/${INC}" DESTINATION include/capstone)
endforeach ()

if (CAPSTONE_BUILD_STATIC)
    install(TARGETS capstone-static
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)
endif ()

if (CAPSTONE_BUILD_SHARED)
    install(TARGETS capstone-shared
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)
endif ()
