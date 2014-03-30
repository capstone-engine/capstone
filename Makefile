# Capstone Disassembly Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014

include config.mk
include pkgconfig.mk	# package version

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

CFLAGS += -fPIC -O3 -Wall -Iinclude

ifeq ($(USE_SYS_DYN_MEM),yes)
CFLAGS += -DUSE_SYS_DYN_MEM
endif

ifneq (,$(findstring yes,$(CAPSTONE_DIET)))
CFLAGS += -DCAPSTONE_DIET
endif

PREFIX ?= /usr
DESTDIR ?=
INCDIR = $(DESTDIR)$(PREFIX)/include

LIBDIR = $(DESTDIR)$(PREFIX)/lib
# on x86_64, we might have /usr/lib64 directory instead of /usr/lib
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_M), x86_64)
ifeq (,$(wildcard $(LIBDIR)))
ifneq ($(UNAME_S), Darwin)
LIBDIR = $(DESTDIR)$(PREFIX)/lib64
endif
endif
endif

ifneq ($(UNAME_S),Darwin)
LDFLAGS += -shared
endif

LIBDATADIR = $(LIBDIR)
ifeq ($(UNAME_S), FreeBSD)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
endif
ifeq ($(UNAME_S), DragonFly)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
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
	LIBOBJ_ARM += arch/ARM/ARMDisassembler.o
	LIBOBJ_ARM += arch/ARM/ARMInstPrinter.o
	LIBOBJ_ARM += arch/ARM/ARMMapping.o
	LIBOBJ_ARM += arch/ARM/ARMModule.o
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
	LIBOBJ_ARM64 += arch/AArch64/AArch64BaseInfo.o
	LIBOBJ_ARM64 += arch/AArch64/AArch64Disassembler.o
	LIBOBJ_ARM64 += arch/AArch64/AArch64InstPrinter.o
	LIBOBJ_ARM64 += arch/AArch64/AArch64Mapping.o
	LIBOBJ_ARM64 += arch/AArch64/AArch64Module.o
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
	LIBOBJ_MIPS += arch/Mips/MipsDisassembler.o
	LIBOBJ_MIPS += arch/Mips/MipsInstPrinter.o
	LIBOBJ_MIPS += arch/Mips/MipsMapping.o
	LIBOBJ_MIPS += arch/Mips/MipsModule.o
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
	LIBOBJ_PPC += arch/PowerPC/PPCDisassembler.o
	LIBOBJ_PPC += arch/PowerPC/PPCInstPrinter.o
	LIBOBJ_PPC += arch/PowerPC/PPCMapping.o
	LIBOBJ_PPC += arch/PowerPC/PPCModule.o
endif


DEP_X86 =
DEP_X86 += arch/X86/X86GenAsmWriter.inc
DEP_X86 += arch/X86/X86GenAsmWriter1.inc
DEP_X86 += arch/X86/X86GenDisassemblerTables.inc
DEP_X86 += arch/X86/X86GenInstrInfo.inc
DEP_X86 += arch/X86/X86GenRegisterInfo.inc

LIBOBJ_X86 =
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
	CFLAGS += -DCAPSTONE_HAS_X86
	LIBOBJ_X86 += arch/X86/X86DisassemblerDecoder.o
	LIBOBJ_X86 += arch/X86/X86Disassembler.o
	LIBOBJ_X86 += arch/X86/X86IntelInstPrinter.o
	LIBOBJ_X86 += arch/X86/X86ATTInstPrinter.o
	LIBOBJ_X86 += arch/X86/X86Mapping.o
	LIBOBJ_X86 += arch/X86/X86Module.o
endif

LIBOBJ =
LIBOBJ += cs.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o
LIBOBJ += $(LIBOBJ_ARM) $(LIBOBJ_ARM64) $(LIBOBJ_MIPS) $(LIBOBJ_PPC) $(LIBOBJ_X86)
LIBOBJ += MCInst.o


PKGCFCGDIR = $(LIBDATADIR)/pkgconfig
API_MAJOR=$(shell echo `grep -e CS_API_MAJOR include/capstone.h | grep -v = | awk '{print $$3}'` | awk '{print $$1}')
VERSION_EXT =

# OSX?
ifeq ($(UNAME_S),Darwin)
EXT = dylib
VERSION_EXT = $(API_MAJOR).$(EXT)
LDFLAGS += -dynamiclib -install_name lib$(LIBNAME).$(VERSION_EXT) -current_version $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA) -compatibility_version $(PKG_MAJOR).$(PKG_MINOR)
AR_EXT = a
ifneq ($(HOMEBREW_CAPSTONE),1)
ifneq ($(USE_SYS_DYN_MEM),yes)
# remove string check because OSX kernel complains about missing symbols
CFLAGS += -D_FORTIFY_SOURCE=0
endif
# By default, suppose that Brew is installed & use Brew path for pkgconfig file
PKGCFCGDIR = /usr/local/lib/pkgconfig
# is Macport installed instead?
ifneq (,$(wildcard /opt/local/bin/port))
# then correct the path for pkgconfig file
PKGCFCGDIR = /opt/local/lib/pkgconfig
endif
endif
else
# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
EXT = dll
AR_EXT = dll.a
# Cygwin doesn't like -fPIC
CFLAGS := $(CFLAGS:-fPIC=)
# On Windows we need the shared library to be executable
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
EXT = dll
AR_EXT = dll.a
# mingw doesn't like -fPIC either
CFLAGS := $(CFLAGS:-fPIC=)
# On Windows we need the shared library to be executable
else
# Linux, *BSD
EXT = so
VERSION_EXT = $(EXT).$(API_MAJOR)
AR_EXT = a
LDFLAGS += -Wl,-soname,lib$(LIBNAME).$(VERSION_EXT)
endif
endif
endif

LIBRARY = lib$(LIBNAME).$(EXT)
ARCHIVE = lib$(LIBNAME).$(AR_EXT)
PKGCFGF = $(LIBNAME).pc

.PHONY: all clean install uninstall dist

all: $(LIBRARY) $(ARCHIVE) $(PKGCFGF)
	$(MAKE) -C tests
	$(INSTALL_DATA) lib$(LIBNAME).$(EXT) tests

$(LIBRARY): $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o $(LIBRARY)

$(LIBOBJ): config.mk

$(LIBOBJ_ARM): $(DEP_ARM)
$(LIBOBJ_ARM64): $(DEP_ARM64)
$(LIBOBJ_MIPS): $(DEP_MIPS)
$(LIBOBJ_PPC): $(DEP_PPC)
$(LIBOBJ_X86): $(DEP_X86)

$(ARCHIVE): $(LIBOBJ)
	rm -f $(ARCHIVE)
	$(AR) q $(ARCHIVE) $(LIBOBJ)
	$(RANLIB) $(ARCHIVE)

$(PKGCFGF):
	echo 'Name: capstone' > $(PKGCFGF)
	echo 'Description: Capstone disassembly engine' >> $(PKGCFGF)
ifeq ($(PKG_EXTRA),)
	echo 'Version: $(PKG_MAJOR).$(PKG_MINOR)' >> $(PKGCFGF)
else
	echo 'Version: $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA)' >> $(PKGCFGF)
endif
	echo 'libdir=$(LIBDIR)' >> $(PKGCFGF)
	echo 'includedir=$(PREFIX)/include/capstone' >> $(PKGCFGF)
	echo 'archive=$${libdir}/libcapstone.a' >> $(PKGCFGF)
	echo 'Libs: -L$${libdir} -lcapstone' >> $(PKGCFGF)
	echo 'Cflags: -I$${includedir}' >> $(PKGCFGF)

install: $(PKGCFGF) $(ARCHIVE) $(LIBRARY)
	mkdir -p $(LIBDIR)
	# remove potential broken old libs
	rm -f $(LIBDIR)/lib$(LIBNAME).*
	$(INSTALL_LIB) lib$(LIBNAME).$(EXT) $(LIBDIR)
ifneq ($(VERSION_EXT),)
	cd $(LIBDIR) && \
	mv lib$(LIBNAME).$(EXT) lib$(LIBNAME).$(VERSION_EXT) && \
	ln -s lib$(LIBNAME).$(VERSION_EXT) lib$(LIBNAME).$(EXT)
endif
	$(INSTALL_DATA) lib$(LIBNAME).$(AR_EXT) $(LIBDIR)
	mkdir -p $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/*.h $(INCDIR)/$(LIBNAME)
	mkdir -p $(PKGCFCGDIR)
	$(INSTALL_DATA) $(PKGCFGF) $(PKGCFCGDIR)/

uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).*
	rm -f $(PKGCFCGDIR)/$(LIBNAME).pc

clean:
	rm -f $(LIBOBJ) lib$(LIBNAME).*
	rm -f $(PKGCFGF)
	$(MAKE) -C bindings/python clean
	$(MAKE) -C bindings/java clean
	$(MAKE) -C bindings/ocaml clean
	$(MAKE) -C tests clean


TAG ?= HEAD
ifeq ($(TAG), HEAD)
DIST_VERSION = latest
else
DIST_VERSION = $(TAG)
endif

dist:
	git archive --format=tar.gz --prefix=capstone-$(DIST_VERSION)/ $(TAG) > capstone-$(DIST_VERSION).tgz
	git archive --format=zip --prefix=capstone-$(DIST_VERSION)/ $(TAG) > capstone-$(DIST_VERSION).zip

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
