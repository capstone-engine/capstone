ACLOCAL_AMFLAGS = -I m4

pcfiles = \
	capstone.pc

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

lib_LTLIBRARIES = libcapstone.la

capstoneincludedir = $(includedir)/capstone
capstoneinclude_HEADERS = \
	include/arm.h \
	include/arm64.h \
	include/capstone.h \
	include/mips.h \
	include/ppc.h \
	include/x86.h

arm_sources =
if ENABLE_ARM
arm_sources += \
	arch/ARM/ARMAddressingModes.h \
	arch/ARM/ARMBaseInfo.h \
	arch/ARM/ARMDisassembler.c \
	arch/ARM/ARMDisassembler.h \
	arch/ARM/ARMInstPrinter.c \
	arch/ARM/ARMInstPrinter.h \
	arch/ARM/ARMMapping.c \
	arch/ARM/ARMMapping.h \
	arch/ARM/ARMModule.c \
	arch/ARM/ARMGenAsmWriter.inc \
	arch/ARM/ARMGenDisassemblerTables.inc \
	arch/ARM/ARMGenInstrInfo.inc \
	arch/ARM/ARMGenRegisterInfo.inc \
	arch/ARM/ARMGenSubtargetInfo.inc
endif

arm64_sources =
if ENABLE_ARM64
arm64_sources += \
	arch/AArch64/AArch64BaseInfo.c \
	arch/AArch64/AArch64BaseInfo.h \
	arch/AArch64/AArch64Disassembler.c \
	arch/AArch64/AArch64Disassembler.h \
	arch/AArch64/AArch64InstPrinter.c \
	arch/AArch64/AArch64InstPrinter.h \
	arch/AArch64/AArch64Mapping.c \
	arch/AArch64/AArch64Mapping.h \
	arch/AArch64/AArch64Module.c \
	arch/AArch64/AArch64GenAsmWriter.inc \
	arch/AArch64/AArch64GenDisassemblerTables.inc \
	arch/AArch64/AArch64GenInstrInfo.inc \
	arch/AArch64/AArch64GenRegisterInfo.inc \
	arch/AArch64/AArch64GenSubtargetInfo.inc
endif

mips_sources =
if ENABLE_MIPS
mips_sources += \
	arch/Mips/MipsDisassembler.c \
	arch/Mips/MipsDisassembler.h \
	arch/Mips/MipsInstPrinter.c \
	arch/Mips/MipsInstPrinter.h \
	arch/Mips/MipsMapping.c \
	arch/Mips/MipsMapping.h \
	arch/Mips/MipsModule.c \
	arch/Mips/MipsGenAsmWriter.inc \
	arch/Mips/MipsGenDisassemblerTables.inc \
	arch/Mips/MipsGenInstrInfo.inc \
	arch/Mips/MipsGenRegisterInfo.inc \
	arch/Mips/MipsGenSubtargetInfo.inc
endif

ppc_sources =
if ENABLE_PPC
ppc_sources += \
	arch/PowerPC/PPCDisassembler.c \
	arch/PowerPC/PPCDisassembler.h \
	arch/PowerPC/PPCInstPrinter.c \
	arch/PowerPC/PPCInstPrinter.h \
	arch/PowerPC/PPCMapping.c \
	arch/PowerPC/PPCMapping.h \
	arch/PowerPC/PPCModule.c \
	arch/PowerPC/PPCPredicates.h \
	arch/PowerPC/PPCGenAsmWriter.inc \
	arch/PowerPC/PPCGenDisassemblerTables.inc \
	arch/PowerPC/PPCGenInstrInfo.inc \
	arch/PowerPC/PPCGenRegisterInfo.inc \
	arch/PowerPC/PPCGenSubtargetInfo.inc
endif

sparc_sources =
if ENABLE_SPARC
sparc_sources += \
	arch/Sparc/Sparc.h \
	arch/Sparc/SparcDisassembler.c \
	arch/Sparc/SparcDisassembler.h \
	arch/Sparc/SparcInstPrinter.c \
	arch/Sparc/SparcInstPrinter.h \
	arch/Sparc/SparcMapping.c \
	arch/Sparc/SparcMapping.h \
	arch/Sparc/SparcModule.c \
	arch/Sparc/SparcGenAsmWriter.inc \
	arch/Sparc/SparcGenDisassemblerTables.inc \
	arch/Sparc/SparcGenInstrInfo.inc \
	arch/Sparc/SparcGenRegisterInfo.inc \
	arch/Sparc/SparcGenSubtargetInfo.inc
endif

sysz_sources =
if ENABLE_SYSZ
sysz_sources += \
	arch/SystemZ/SystemZDisassembler.c \
	arch/SystemZ/SystemZDisassembler.h \
	arch/SystemZ/SystemZInstPrinter.c \
	arch/SystemZ/SystemZInstPrinter.h \
	arch/SystemZ/SystemZMCTargetDesc.c \
	arch/SystemZ/SystemZMCTargetDesc.h \
	arch/SystemZ/SystemZMapping.c \
	arch/SystemZ/SystemZMapping.h \
	arch/SystemZ/SystemZModule.c \
	arch/SystemZ/SystemZGenAsmWriter.inc \
	arch/SystemZ/SystemZGenDisassemblerTables.inc \
	arch/SystemZ/SystemZGenInstrInfo.inc \
	arch/SystemZ/SystemZGenRegisterInfo.inc \
	arch/SystemZ/SystemZGenSubtargetInfo.inc
endif

x86_sources =
if ENABLE_X86
x86_sources += \
	arch/X86/X86ATTInstPrinter.c \
	arch/X86/X86Disassembler.c \
	arch/X86/X86Disassembler.h \
	arch/X86/X86DisassemblerDecoder.c \
	arch/X86/X86DisassemblerDecoder.h \
	arch/X86/X86DisassemblerDecoderCommon.h \
	arch/X86/X86InstPrinter.h \
	arch/X86/X86IntelInstPrinter.c \
	arch/X86/X86Mapping.c \
	arch/X86/X86Mapping.h \
	arch/X86/X86Module.c \
	arch/X86/X86GenAsmWriter.inc \
	arch/X86/X86GenAsmWriter1.inc \
	arch/X86/X86GenAsmWriter1_reduce.inc \
	arch/X86/X86GenAsmWriter_reduce.inc \
	arch/X86/X86GenDisassemblerTables.inc \
	arch/X86/X86GenDisassemblerTables_reduce.inc \
	arch/X86/X86GenInstrInfo.inc \
	arch/X86/X86GenInstrInfo_reduce.inc \
	arch/X86/X86GenRegisterInfo.inc
endif

libcapstone_la_SOURCES = \
	cs.c \
	cs_priv.h \
	utils.c \
	utils.h \
	SStream.c \
	SStream.h \
	MCInstrDesc.c \
	MCInstrDesc.h \
	MCRegisterInfo.c \
	MCRegisterInfo.h \
	$(arm_sources) \
	$(arm64_sources) \
	$(mips_sources) \
	$(ppc_sources) \
	$(sparc_sources) \
	$(sysz_sources) \
	$(x86_sources) \
	LEB128.h \
	MCInst.c \
	MCInst.h \
	MCDisassembler.h \
	MCFixedLenDisassembler.h \
	MathExtras.h \
	SubtargetFeature.h

libcapstone_la_LDFLAGS = \
	-export-symbols-regex "^cs_.*" \
	-no-undefined \
	-avoid-version

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/include
