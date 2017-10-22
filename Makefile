# Capstone Disassembly Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014

include config.mk
include pkgconfig.mk	# package version
include functions.mk

# Verbose output?
V ?= 0

ifeq ($(PKG_EXTRA),)
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR)
else
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA)
endif

ifeq ($(CROSS),)
CC ?= cc
AR ?= ar
RANLIB ?= ranlib
STRIP ?= strip
else
CC = $(CROSS)gcc
AR = $(CROSS)ar
RANLIB = $(CROSS)ranlib
STRIP = $(CROSS)strip
endif

ifneq (,$(findstring yes,$(CAPSTONE_DIET)))
CFLAGS ?= -Os
CFLAGS += -DCAPSTONE_DIET
else
CFLAGS ?= -O3
endif

ifneq (,$(findstring yes,$(CAPSTONE_X86_ATT_DISABLE)))
CFLAGS += -DCAPSTONE_X86_ATT_DISABLE
endif

CFLAGS += -fPIC -Wall -Wwrite-strings -Iinclude

ifeq ($(CAPSTONE_USE_SYS_DYN_MEM),yes)
CFLAGS += -DCAPSTONE_USE_SYS_DYN_MEM
endif

ifeq ($(CAPSTONE_HAS_OSXKERNEL), yes)
CFLAGS += -DCAPSTONE_HAS_OSXKERNEL
SDKROOT ?= $(shell xcodebuild -version -sdk macosx Path)
CFLAGS += -mmacosx-version-min=10.5 \
		  -isysroot$(SDKROOT) \
		  -I$(SDKROOT)/System/Library/Frameworks/Kernel.framework/Headers \
		  -mkernel \
		  -fno-builtin
endif

PREFIX ?= /usr
DESTDIR ?=
ifndef BUILDDIR
BLDIR = .
OBJDIR = .
else
BLDIR = $(abspath $(BUILDDIR))
OBJDIR = $(BLDIR)/obj
endif
INCDIR = $(DESTDIR)$(PREFIX)/include

UNAME_S := $(shell uname -s)

LIBDIRARCH ?= lib
# Uncomment the below line to installs x86_64 libs to lib64/ directory.
# Or better, pass 'LIBDIRARCH=lib64' to 'make install/uninstall' via 'make.sh'.
#LIBDIRARCH ?= lib64
LIBDIR = $(DESTDIR)$(PREFIX)/$(LIBDIRARCH)
BINDIR = $(DESTDIR)$(PREFIX)/bin

LIBDATADIR = $(LIBDIR)

# Don't redefine $LIBDATADIR when global environment variable
# USE_GENERIC_LIBDATADIR is set. This is used by the pkgsrc framework.

ifndef USE_GENERIC_LIBDATADIR
ifeq ($(UNAME_S), FreeBSD)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
endif
ifeq ($(UNAME_S), DragonFly)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
endif
endif

INSTALL_BIN ?= install
INSTALL_DATA ?= $(INSTALL_BIN) -m0644
INSTALL_LIB ?= $(INSTALL_BIN) -m0755

LIBNAME = capstone


DEP_ARM =
DEP_ARM += arch/ARM/ARMGenAsmWriter.inc
DEP_ARM += arch/ARM/ARMGenDisassemblerTables.inc
DEP_ARM += arch/ARM/ARMGenInstrInfo.inc
DEP_ARM += arch/ARM/ARMGenRegisterInfo.inc
DEP_ARM += arch/ARM/ARMGenSubtargetInfo.inc

LIBOBJ_ARM =
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_ARM
	LIBOBJ_ARM += $(OBJDIR)/arch/ARM/ARMDisassembler.o
	LIBOBJ_ARM += $(OBJDIR)/arch/ARM/ARMInstPrinter.o
	LIBOBJ_ARM += $(OBJDIR)/arch/ARM/ARMMapping.o
	LIBOBJ_ARM += $(OBJDIR)/arch/ARM/ARMModule.o
endif

DEP_ARM64 =
DEP_ARM64 += arch/AArch64/AArch64GenAsmWriter.inc
DEP_ARM64 += arch/AArch64/AArch64GenInstrInfo.inc
DEP_ARM64 += arch/AArch64/AArch64GenSubtargetInfo.inc
DEP_ARM64 += arch/AArch64/AArch64GenDisassemblerTables.inc
DEP_ARM64 += arch/AArch64/AArch64GenRegisterInfo.inc

LIBOBJ_ARM64 =
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_ARM64
	LIBOBJ_ARM64 += $(OBJDIR)/arch/AArch64/AArch64BaseInfo.o
	LIBOBJ_ARM64 += $(OBJDIR)/arch/AArch64/AArch64Disassembler.o
	LIBOBJ_ARM64 += $(OBJDIR)/arch/AArch64/AArch64InstPrinter.o
	LIBOBJ_ARM64 += $(OBJDIR)/arch/AArch64/AArch64Mapping.o
	LIBOBJ_ARM64 += $(OBJDIR)/arch/AArch64/AArch64Module.o
endif


DEP_MIPS =
DEP_MIPS += arch/Mips/MipsGenAsmWriter.inc
DEP_MIPS += arch/Mips/MipsGenDisassemblerTables.inc
DEP_MIPS += arch/Mips/MipsGenInstrInfo.inc
DEP_MIPS += arch/Mips/MipsGenRegisterInfo.inc
DEP_MIPS += arch/Mips/MipsGenSubtargetInfo.inc

LIBOBJ_MIPS =
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_MIPS
	LIBOBJ_MIPS += $(OBJDIR)/arch/Mips/MipsDisassembler.o
	LIBOBJ_MIPS += $(OBJDIR)/arch/Mips/MipsInstPrinter.o
	LIBOBJ_MIPS += $(OBJDIR)/arch/Mips/MipsMapping.o
	LIBOBJ_MIPS += $(OBJDIR)/arch/Mips/MipsModule.o
endif


DEP_PPC =
DEP_PPC += arch/PowerPC/PPCGenAsmWriter.inc
DEP_PPC += arch/PowerPC/PPCGenInstrInfo.inc
DEP_PPC += arch/PowerPC/PPCGenSubtargetInfo.inc
DEP_PPC += arch/PowerPC/PPCGenDisassemblerTables.inc
DEP_PPC += arch/PowerPC/PPCGenRegisterInfo.inc

LIBOBJ_PPC =
ifneq (,$(findstring powerpc,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_POWERPC
	LIBOBJ_PPC += $(OBJDIR)/arch/PowerPC/PPCDisassembler.o
	LIBOBJ_PPC += $(OBJDIR)/arch/PowerPC/PPCInstPrinter.o
	LIBOBJ_PPC += $(OBJDIR)/arch/PowerPC/PPCMapping.o
	LIBOBJ_PPC += $(OBJDIR)/arch/PowerPC/PPCModule.o
endif


DEP_SPARC =
DEP_SPARC += arch/Sparc/SparcGenAsmWriter.inc
DEP_SPARC += arch/Sparc/SparcGenInstrInfo.inc
DEP_SPARC += arch/Sparc/SparcGenSubtargetInfo.inc
DEP_SPARC += arch/Sparc/SparcGenDisassemblerTables.inc
DEP_SPARC += arch/Sparc/SparcGenRegisterInfo.inc

LIBOBJ_SPARC =
ifneq (,$(findstring sparc,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_SPARC
	LIBOBJ_SPARC += $(OBJDIR)/arch/Sparc/SparcDisassembler.o
	LIBOBJ_SPARC += $(OBJDIR)/arch/Sparc/SparcInstPrinter.o
	LIBOBJ_SPARC += $(OBJDIR)/arch/Sparc/SparcMapping.o
	LIBOBJ_SPARC += $(OBJDIR)/arch/Sparc/SparcModule.o
endif


DEP_SYSZ =
DEP_SYSZ += arch/SystemZ/SystemZGenAsmWriter.inc
DEP_SYSZ += arch/SystemZ/SystemZGenInstrInfo.inc
DEP_SYSZ += arch/SystemZ/SystemZGenSubtargetInfo.inc
DEP_SYSZ += arch/SystemZ/SystemZGenDisassemblerTables.inc
DEP_SYSZ += arch/SystemZ/SystemZGenRegisterInfo.inc

LIBOBJ_SYSZ =
ifneq (,$(findstring systemz,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_SYSZ
	LIBOBJ_SYSZ += $(OBJDIR)/arch/SystemZ/SystemZDisassembler.o
	LIBOBJ_SYSZ += $(OBJDIR)/arch/SystemZ/SystemZInstPrinter.o
	LIBOBJ_SYSZ += $(OBJDIR)/arch/SystemZ/SystemZMapping.o
	LIBOBJ_SYSZ += $(OBJDIR)/arch/SystemZ/SystemZModule.o
	LIBOBJ_SYSZ += $(OBJDIR)/arch/SystemZ/SystemZMCTargetDesc.o
endif


# by default, we compile full X86 instruction sets
X86_REDUCE =
ifneq (,$(findstring yes,$(CAPSTONE_X86_REDUCE)))
X86_REDUCE = _reduce
CFLAGS += -DCAPSTONE_X86_REDUCE -Os
endif

DEP_X86 =
DEP_X86 += arch/X86/X86GenAsmWriter$(X86_REDUCE).inc
DEP_X86 += arch/X86/X86GenAsmWriter1$(X86_REDUCE).inc
DEP_X86 += arch/X86/X86GenDisassemblerTables$(X86_REDUCE).inc
DEP_X86 += arch/X86/X86GenInstrInfo$(X86_REDUCE).inc
DEP_X86 += arch/X86/X86GenRegisterInfo.inc

LIBOBJ_X86 =
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_X86
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86DisassemblerDecoder.o
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86Disassembler.o
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86IntelInstPrinter.o
# assembly syntax is irrelevant in Diet mode, when this info is suppressed
ifeq (,$(findstring yes,$(CAPSTONE_DIET)))
ifeq (,$(findstring yes,$(CAPSTONE_X86_ATT_DISABLE)))
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86ATTInstPrinter.o
endif
endif
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86Mapping.o
	LIBOBJ_X86 += $(OBJDIR)/arch/X86/X86Module.o
endif


DEP_XCORE =
DEP_XCORE += arch/XCore/XCoreGenAsmWriter.inc
DEP_XCORE += arch/XCore/XCoreGenInstrInfo.inc
DEP_XCORE += arch/XCore/XCoreGenDisassemblerTables.inc
DEP_XCORE += arch/XCore/XCoreGenRegisterInfo.inc

LIBOBJ_XCORE =
ifneq (,$(findstring xcore,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_XCORE
	LIBOBJ_XCORE += $(OBJDIR)/arch/XCore/XCoreDisassembler.o
	LIBOBJ_XCORE += $(OBJDIR)/arch/XCore/XCoreInstPrinter.o
	LIBOBJ_XCORE += $(OBJDIR)/arch/XCore/XCoreMapping.o
	LIBOBJ_XCORE += $(OBJDIR)/arch/XCore/XCoreModule.o
endif


LIBOBJ =
LIBOBJ += $(OBJDIR)/cs.o $(OBJDIR)/utils.o $(OBJDIR)/SStream.o $(OBJDIR)/MCInstrDesc.o $(OBJDIR)/MCRegisterInfo.o
LIBOBJ += $(LIBOBJ_ARM) $(LIBOBJ_ARM64) $(LIBOBJ_MIPS) $(LIBOBJ_PPC) $(LIBOBJ_SPARC) $(LIBOBJ_SYSZ) $(LIBOBJ_X86) $(LIBOBJ_XCORE)
LIBOBJ += $(OBJDIR)/MCInst.o


PKGCFGDIR ?= $(LIBDATADIR)/pkgconfig
API_MAJOR=$(shell echo `grep -e CS_API_MAJOR include/capstone.h | grep -v = | awk '{print $$3}'` | awk '{print $$1}')
VERSION_EXT =

IS_APPLE := $(shell $(CC) -dM -E - < /dev/null | grep -cm 1 -e __apple_build_version__ -e __APPLE_CC__)
ifeq ($(IS_APPLE),1)
# on MacOS, compile in Universal format by default
MACOS_UNIVERSAL ?= yes
ifeq ($(MACOS_UNIVERSAL),yes)
CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
endif
EXT = dylib
VERSION_EXT = $(API_MAJOR).$(EXT)
$(LIBNAME)_LDFLAGS += -dynamiclib -install_name lib$(LIBNAME).$(VERSION_EXT) -current_version $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA) -compatibility_version $(PKG_MAJOR).$(PKG_MINOR)
AR_EXT = a
# Homebrew wants to make sure its formula does not disable FORTIFY_SOURCE
# However, this is not really necessary because 'CAPSTONE_USE_SYS_DYN_MEM=yes' by default
ifneq ($(HOMEBREW_CAPSTONE),1)
ifneq ($(CAPSTONE_USE_SYS_DYN_MEM),yes)
# remove string check because OSX kernel complains about missing symbols
CFLAGS += -D_FORTIFY_SOURCE=0
endif
endif
else
CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
$(LIBNAME)_LDFLAGS += -shared
# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
EXT = dll
AR_EXT = lib
# Cygwin doesn't like -fPIC
CFLAGS := $(CFLAGS:-fPIC=)
# On Windows we need the shared library to be executable
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
EXT = dll
AR_EXT = lib
# mingw doesn't like -fPIC either
CFLAGS := $(CFLAGS:-fPIC=)
# On Windows we need the shared library to be executable
else
# Linux, *BSD
EXT = so
VERSION_EXT = $(EXT).$(API_MAJOR)
AR_EXT = a
$(LIBNAME)_LDFLAGS += -Wl,-soname,lib$(LIBNAME).$(VERSION_EXT)
endif
endif
endif

ifeq ($(CAPSTONE_SHARED),yes)
ifeq ($(IS_MINGW),1)
LIBRARY = $(BLDIR)/$(LIBNAME).$(EXT)
else ifeq ($(IS_CYGWIN),1)
LIBRARY = $(BLDIR)/$(LIBNAME).$(EXT)
else	# *nix
LIBRARY = $(BLDIR)/lib$(LIBNAME).$(EXT)
CFLAGS += -fvisibility=hidden
endif
endif

ifeq ($(CAPSTONE_STATIC),yes)
ifeq ($(IS_MINGW),1)
ARCHIVE = $(BLDIR)/$(LIBNAME).$(AR_EXT)
else ifeq ($(IS_CYGWIN),1)
ARCHIVE = $(BLDIR)/$(LIBNAME).$(AR_EXT)
else
ARCHIVE = $(BLDIR)/lib$(LIBNAME).$(AR_EXT)
endif
endif

PKGCFGF = $(BLDIR)/$(LIBNAME).pc

.PHONY: all clean install uninstall dist

all: $(LIBRARY) $(ARCHIVE) $(PKGCFGF)
ifeq (,$(findstring yes,$(CAPSTONE_BUILD_CORE_ONLY)))
	@V=$(V) CC=$(CC) $(MAKE) -C cstool
ifndef BUILDDIR
	cd tests && $(MAKE)
else
	cd tests && $(MAKE) BUILDDIR=$(BLDIR)
endif
	$(call install-library,$(BLDIR)/tests/)
endif

ifeq ($(CAPSTONE_SHARED),yes)
$(LIBRARY): $(LIBOBJ)
ifeq ($(V),0)
	$(call log,LINK,$(@:$(BLDIR)/%=%))
	@$(create-library)
else
	$(create-library)
endif
endif

$(LIBOBJ): *.h include/*.h config.mk

$(LIBOBJ_ARM): $(DEP_ARM)
$(LIBOBJ_ARM64): $(DEP_ARM64)
$(LIBOBJ_MIPS): $(DEP_MIPS)
$(LIBOBJ_PPC): $(DEP_PPC)
$(LIBOBJ_SPARC): $(DEP_SPARC)
$(LIBOBJ_SYSZ): $(DEP_SYSZ)
$(LIBOBJ_X86): $(DEP_X86)
$(LIBOBJ_XCORE): $(DEP_XCORE)

ifeq ($(CAPSTONE_STATIC),yes)
$(ARCHIVE): $(LIBOBJ)
	@rm -f $(ARCHIVE)
ifeq ($(V),0)
	$(call log,AR,$(@:$(BLDIR)/%=%))
	@$(create-archive)
else
	$(create-archive)
endif
endif

$(PKGCFGF):
ifeq ($(V),0)
	$(call log,GEN,$(@:$(BLDIR)/%=%))
	@$(generate-pkgcfg)
else
	$(generate-pkgcfg)
endif

install: $(PKGCFGF) $(ARCHIVE) $(LIBRARY)
	mkdir -p $(LIBDIR)
	$(call install-library,$(LIBDIR))
ifeq ($(CAPSTONE_STATIC),yes)
	$(INSTALL_DATA) $(ARCHIVE) $(LIBDIR)
endif
	mkdir -p $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/*.h $(INCDIR)/$(LIBNAME)
	mkdir -p $(PKGCFGDIR)
	$(INSTALL_DATA) $(PKGCFGF) $(PKGCFGDIR)/
	mkdir -p $(BINDIR)
	$(INSTALL_LIB) cstool/cstool $(BINDIR)

uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).*
	rm -f $(PKGCFGDIR)/$(LIBNAME).pc
	rm -f $(BINDIR)/cstool

clean:
	rm -f $(LIBOBJ)
	rm -f $(BLDIR)/lib$(LIBNAME).* $(BLDIR)/$(LIBNAME).pc
	rm -f $(PKGCFGF)
	$(MAKE) -C cstool clean

ifeq (,$(findstring yes,$(CAPSTONE_BUILD_CORE_ONLY)))
	cd tests && $(MAKE) clean
	rm -f $(BLDIR)/tests/lib$(LIBNAME).$(EXT)
endif

ifdef BUILDDIR
	rm -rf $(BUILDDIR)
endif

ifeq (,$(findstring yes,$(CAPSTONE_BUILD_CORE_ONLY)))
	cd bindings/python && $(MAKE) clean
	cd bindings/java && $(MAKE) clean
	cd bindings/ocaml && $(MAKE) clean
endif


TAG ?= HEAD
ifeq ($(TAG), HEAD)
DIST_VERSION = latest
else
DIST_VERSION = $(TAG)
endif

dist:
	git archive --format=tar.gz --prefix=capstone-$(DIST_VERSION)/ $(TAG) > capstone-$(DIST_VERSION).tgz
	git archive --format=zip --prefix=capstone-$(DIST_VERSION)/ $(TAG) > capstone-$(DIST_VERSION).zip


TESTS = test_basic test_detail test_arm test_arm64 test_mips test_ppc test_sparc
TESTS += test_systemz test_x86 test_xcore test_iter
TESTS += test_basic.static test_detail.static test_arm.static test_arm64.static
TESTS += test_mips.static test_ppc.static test_sparc.static
TESTS += test_systemz.static test_x86.static test_xcore.static
TESTS += test_skipdata test_skipdata.static test_iter.static
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		LD_LIBRARY_PATH=./tests ./tests/$$t > /dev/null && echo OK || echo FAILED; \
	done

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:$(OBJDIR)/%=%))
	@$(compile)
else
	$(compile)
endif


ifeq ($(CAPSTONE_SHARED),yes)
define install-library
	$(INSTALL_LIB) $(LIBRARY) $1
	$(if $(VERSION_EXT),
		cd $1 && \
		mv lib$(LIBNAME).$(EXT) lib$(LIBNAME).$(VERSION_EXT) && \
		ln -s lib$(LIBNAME).$(VERSION_EXT) lib$(LIBNAME).$(EXT))
endef
else
define install-library
endef
endif


define create-archive
	$(AR) q $(ARCHIVE) $(LIBOBJ)
	$(RANLIB) $(ARCHIVE)
endef


define create-library
	$(CC) $(LDFLAGS) $($(LIBNAME)_LDFLAGS) $(LIBOBJ) -o $(LIBRARY)
endef


define generate-pkgcfg
	echo 'Name: capstone' > $(PKGCFGF)
	echo 'Description: Capstone disassembly engine' >> $(PKGCFGF)
	echo 'Version: $(PKG_VERSION)' >> $(PKGCFGF)
	echo 'libdir=$(LIBDIR)' >> $(PKGCFGF)
	echo 'includedir=$(INCDIR)/capstone' >> $(PKGCFGF)
	echo 'archive=$${libdir}/libcapstone.a' >> $(PKGCFGF)
	echo 'Libs: -L$${libdir} -lcapstone' >> $(PKGCFGF)
	echo 'Cflags: -I$${includedir}' >> $(PKGCFGF)
endef
