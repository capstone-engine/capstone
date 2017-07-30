cmake_minimum_required(VERSION 2.6)
project(capstone)

set(VERSION_MAJOR 3)
set(VERSION_MINOR 0)
set(VERSION_PATCH 5)

# to configure the options specify them in in the command line or change them in the cmake UI.
# Don't edit the makefile!
option(CAPSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" OFF)
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
option(CAPSTONE_OSXKERNEL_SUPPORT "Support to embed Capstone into OS X Kernel extensions" OFF)

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
set(SOURCES_ENGINE
    cs.c
    MCInst.c
    MCInstrDesc.c
    MCRegisterInfo.c
    SStream.c
    utils.c
    )

set(HEADERS_ENGINE
    include/capstone.h
    utils.h
    MCRegisterInfo.h
    MCInst.h
    MCInstrDesc.h
    SStream.h
    cs_priv.h
    include/platform.h
    )

set(HEADERS_COMMON
    include/arm64.h
    include/arm.h
    include/capstone.h
    include/mips.h
    include/ppc.h
    include/x86.h
    include/sparc.h
    include/systemz.h
    include/xcore.h
    include/platform.h
    )


set(TEST_SOURCES test_basic.c test_detail.c test_skipdata.c test_iter.c)

## architecture support
if (CAPSTONE_ARM_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_ARM)
    set(SOURCES_ARM
        arch/ARM/ARMDisassembler.c
        arch/ARM/ARMInstPrinter.c
        arch/ARM/ARMMapping.c
        arch/ARM/ARMModule.c
        )
    set(HEADERS_ARM
        arch/ARM/ARMAddressingModes.h
        arch/ARM/ARMBaseInfo.h
        arch/ARM/ARMDisassembler.h
        arch/ARM/ARMGenAsmWriter.inc
        arch/ARM/ARMGenDisassemblerTables.inc
        arch/ARM/ARMGenInstrInfo.inc
        arch/ARM/ARMGenRegisterInfo.inc
        arch/ARM/ARMGenSubtargetInfo.inc
        arch/ARM/ARMInstPrinter.h
        arch/ARM/ARMMapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_arm.c)
endif ()

if (CAPSTONE_ARM64_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_ARM64)
    set(SOURCES_ARM64
        arch/AArch64/AArch64BaseInfo.c
        arch/AArch64/AArch64Disassembler.c
        arch/AArch64/AArch64InstPrinter.c
        arch/AArch64/AArch64Mapping.c
        arch/AArch64/AArch64Module.c
        )
    set(HEADERS_ARM64
        arch/AArch64/AArch64AddressingModes.h
        arch/AArch64/AArch64BaseInfo.h
        arch/AArch64/AArch64Disassembler.h
        arch/AArch64/AArch64GenAsmWriter.inc
        arch/AArch64/AArch64GenDisassemblerTables.inc
        arch/AArch64/AArch64GenInstrInfo.inc
        arch/AArch64/AArch64GenRegisterInfo.inc
        arch/AArch64/AArch64GenSubtargetInfo.inc
        arch/AArch64/AArch64InstPrinter.h
        arch/AArch64/AArch64Mapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_arm64.c)
endif ()

if (CAPSTONE_MIPS_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_MIPS)
    set(SOURCES_MIPS
        arch/Mips/MipsDisassembler.c
        arch/Mips/MipsInstPrinter.c
        arch/Mips/MipsMapping.c
        arch/Mips/MipsModule.c
        )
    set(HEADERS_MIPS
        arch/Mips/MipsDisassembler.h
        arch/Mips/MipsGenAsmWriter.inc
        arch/Mips/MipsGenDisassemblerTables.inc
        arch/Mips/MipsGenInstrInfo.inc
        arch/Mips/MipsGenRegisterInfo.inc
        arch/Mips/MipsGenSubtargetInfo.inc
        arch/Mips/MipsInstPrinter.h
        arch/Mips/MipsMapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_mips.c)
endif ()

if (CAPSTONE_PPC_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_POWERPC)
    set(SOURCES_PPC
        arch/PowerPC/PPCDisassembler.c
        arch/PowerPC/PPCInstPrinter.c
        arch/PowerPC/PPCMapping.c
        arch/PowerPC/PPCModule.c
        )
    set(HEADERS_PPC
        arch/PowerPC/PPCDisassembler.h
        arch/PowerPC/PPCGenAsmWriter.inc
        arch/PowerPC/PPCGenDisassemblerTables.inc
        arch/PowerPC/PPCGenInstrInfo.inc
        arch/PowerPC/PPCGenRegisterInfo.inc
        arch/PowerPC/PPCGenSubtargetInfo.inc
        arch/PowerPC/PPCInstPrinter.h
        arch/PowerPC/PPCMapping.h
        arch/PowerPC/PPCPredicates.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_ppc.c)
endif ()

if (CAPSTONE_X86_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_X86)
    set(SOURCES_X86
        arch/X86/X86Disassembler.c
        arch/X86/X86DisassemblerDecoder.c
        arch/X86/X86IntelInstPrinter.c
        arch/X86/X86Mapping.c
        arch/X86/X86Module.c
        )
    set(HEADERS_X86
        arch/X86/X86BaseInfo.h
        arch/X86/X86Disassembler.h
        arch/X86/X86DisassemblerDecoder.h
        arch/X86/X86DisassemblerDecoderCommon.h
        arch/X86/X86GenAsmWriter.inc
        arch/X86/X86GenAsmWriter1.inc
        arch/X86/X86GenAsmWriter1_reduce.inc
        arch/X86/X86GenAsmWriter_reduce.inc
        arch/X86/X86GenDisassemblerTables.inc
        arch/X86/X86GenDisassemblerTables_reduce.inc
        arch/X86/X86GenInstrInfo.inc
        arch/X86/X86GenInstrInfo_reduce.inc
        arch/X86/X86GenRegisterInfo.inc
        arch/X86/X86InstPrinter.h
        arch/X86/X86Mapping.h
        )
    if (NOT CAPSTONE_BUILD_DIET)
        set(SOURCES_X86 ${SOURCES_X86} arch/X86/X86ATTInstPrinter.c)
    endif ()
    set(TEST_SOURCES ${TEST_SOURCES} test_x86.c)
endif ()

if (CAPSTONE_SPARC_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_SPARC)
    set(SOURCES_SPARC
        arch/Sparc/SparcDisassembler.c
        arch/Sparc/SparcInstPrinter.c
        arch/Sparc/SparcMapping.c
        arch/Sparc/SparcModule.c
        )
    set(HEADERS_SPARC
        arch/Sparc/Sparc.h
        arch/Sparc/SparcDisassembler.h
        arch/Sparc/SparcGenAsmWriter.inc
        arch/Sparc/SparcGenDisassemblerTables.inc
        arch/Sparc/SparcGenInstrInfo.inc
        arch/Sparc/SparcGenRegisterInfo.inc
        arch/Sparc/SparcGenSubtargetInfo.inc
        arch/Sparc/SparcInstPrinter.h
        arch/Sparc/SparcMapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_sparc.c)
endif ()

if (CAPSTONE_SYSZ_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_SYSZ)
    set(SOURCES_SYSZ
        arch/SystemZ/SystemZDisassembler.c
        arch/SystemZ/SystemZInstPrinter.c
        arch/SystemZ/SystemZMapping.c
        arch/SystemZ/SystemZModule.c
        arch/SystemZ/SystemZMCTargetDesc.c
        )
    set(HEADERS_SYSZ
        arch/SystemZ/SystemZDisassembler.h
        arch/SystemZ/SystemZGenAsmWriter.inc
        arch/SystemZ/SystemZGenDisassemblerTables.inc
        arch/SystemZ/SystemZGenInstrInfo.inc
        arch/SystemZ/SystemZGenRegisterInfo.inc
        arch/SystemZ/SystemZGenSubtargetInfo.inc
        arch/SystemZ/SystemZInstPrinter.h
        arch/SystemZ/SystemZMCTargetDesc.h
        arch/SystemZ/SystemZMapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_systemz.c)
endif ()

if (CAPSTONE_XCORE_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_XCORE)
    set(SOURCES_XCORE
        arch/XCore/XCoreDisassembler.c
        arch/XCore/XCoreInstPrinter.c
        arch/XCore/XCoreMapping.c
        arch/XCore/XCoreModule.c
        )
    set(HEADERS_XCORE
        arch/XCore/XCoreDisassembler.h
        arch/XCore/XCoreGenAsmWriter.inc
        arch/XCore/XCoreGenDisassemblerTables.inc
        arch/XCore/XCoreGenInstrInfo.inc
        arch/XCore/XCoreGenRegisterInfo.inc
        arch/XCore/XCoreInstPrinter.h
        arch/XCore/XCoreMapping.h
        )
    set(TEST_SOURCES ${TEST_SOURCES} test_xcore.c)
endif ()

if (CAPSTONE_OSXKERNEL_SUPPORT)
    add_definitions(-DCAPSTONE_HAS_OSXKERNEL)
endif ()

set(ALL_SOURCES
    ${SOURCES_ENGINE}
    ${SOURCES_ARM}
    ${SOURCES_ARM64}
    ${SOURCES_MIPS}
    ${SOURCES_PPC}
    ${SOURCES_X86}
    ${SOURCES_SPARC}
    ${SOURCES_SYSZ}
    ${SOURCES_XCORE}
    )

set(ALL_HEADERS
    ${HEADERS_COMMON}
    ${HEADERS_ENGINE}
    ${HEADERS_ARM}
    ${HEADERS_ARM64}
    ${HEADERS_MIPS}
    ${HEADERS_PPC}
    ${HEADERS_X86}
    ${HEADERS_SPARC}
    ${HEADERS_SYSZ}
    ${HEADERS_XCORE}
    )

include_directories("${PROJECT_SOURCE_DIR}/include")

## properties
# version info
set_property(GLOBAL PROPERTY VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

## targets
if (CAPSTONE_BUILD_STATIC)
    add_library(capstone-static STATIC ${ALL_SOURCES} ${ALL_HEADERS})
    set_property(TARGET capstone-static PROPERTY OUTPUT_NAME capstone)
    set(default-target capstone-static)
endif ()

# Force static runtime libraries
if (CAPSTONE_BUILD_STATIC_RUNTIME)
    FOREACH(flag
        CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_DEBUG_INIT
        CMAKE_CXX_FLAGS_RELEASE  CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_DEBUG  CMAKE_CXX_FLAGS_DEBUG_INIT)
        if (MSVC)
            STRING(REPLACE "/MD"  "/MT" "${flag}" "${${flag}}")
            SET("${flag}" "${${flag}} /EHsc")
        endif (MSVC)
    ENDFOREACH()
endif ()

if (CAPSTONE_BUILD_SHARED)
    add_library(capstone-shared SHARED ${ALL_SOURCES} ${ALL_HEADERS})
    set_property(TARGET capstone-shared PROPERTY OUTPUT_NAME capstone)
    set_property(TARGET capstone-shared PROPERTY COMPILE_FLAGS -DCAPSTONE_SHARED)

    if (MSVC)
        set_target_properties(capstone-shared PROPERTIES IMPORT_SUFFIX _dll.lib)
    else()
        set_target_properties(capstone-shared PROPERTIES
	    VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
	    SOVERSION ${VERSION_MAJOR})
    endif ()

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

source_group("Source\\Engine" FILES ${SOURCES_ENGINE})
source_group("Source\\ARM" FILES ${SOURCES_ARM})
source_group("Source\\ARM64" FILES ${SOURCES_ARM64})
source_group("Source\\Mips" FILES ${SOURCES_MIPS})
source_group("Source\\PowerPC" FILES ${SOURCES_PPC})
source_group("Source\\Sparc" FILES ${SOURCES_SPARC})
source_group("Source\\SystemZ" FILES ${SOURCES_SYSZ})
source_group("Source\\X86" FILES ${SOURCES_X86})
source_group("Source\\XCore" FILES ${SOURCES_XCORE})

source_group("Include\\Common" FILES ${HEADERS_COMMON})
source_group("Include\\Engine" FILES ${HEADERS_ENGINE})
source_group("Include\\ARM" FILES ${HEADERS_ARM})
source_group("Include\\ARM64" FILES ${HEADERS_ARM64})
source_group("Include\\Mips" FILES ${HEADERS_MIPS})
source_group("Include\\PowerPC" FILES ${HEADERS_PPC})
source_group("Include\\Sparc" FILES ${HEADERS_SPARC})
source_group("Include\\SystemZ" FILES ${HEADERS_SYSZ})
source_group("Include\\X86" FILES ${HEADERS_X86})
source_group("Include\\XCore" FILES ${HEADERS_XCORE})

### test library 64bit routine:
get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)

if (NOT APPLE AND "${LIB64}" STREQUAL "TRUE")
    set(LIBSUFFIX 64)
else()
    set(LIBSUFFIX "")
endif()

set(INSTALL_LIB_DIR     lib${LIBSUFFIX} CACHE PATH "Installation directory for libraries")
mark_as_advanced(INSTALL_LIB_DIR)

## installation
install(FILES ${HEADERS_COMMON} DESTINATION include/capstone)
configure_file(capstone.pc.in capstone.pc)

if (CAPSTONE_BUILD_STATIC)
    install(TARGETS capstone-static
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION ${INSTALL_LIB_DIR}
            ARCHIVE DESTINATION ${INSTALL_LIB_DIR})
endif ()

if (CAPSTONE_BUILD_SHARED)
    install(TARGETS capstone-shared
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION ${INSTALL_LIB_DIR}
            ARCHIVE DESTINATION ${INSTALL_LIB_DIR})
endif ()

if (CAPSTONE_BUILD_SHARED)
FILE(GLOB CSTOOL_SRC cstool/*.c)
add_executable(cstool ${CSTOOL_SRC})
target_link_libraries(cstool ${default-target})

install(TARGETS cstool DESTINATION bin)
install(FILES ${CMAKE_BINARY_DIR}/capstone.pc DESTINATION lib/pkgconfig)
endif ()
