# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

include config.mk

CC = $(CROSS)gcc
AR ?= $(CROSS)ar
RANLIB ?= $(CROSS)ranlib
STRIP ?= $(CROSS)strip

CFLAGS += -fPIC -O3 -Wall -Iinclude
LDFLAGS += -shared

PREFIX ?= /usr
DESTDIR ?=
INCDIR = $(DESTDIR)$(PREFIX)/include

LIBDIR = $(DESTDIR)$(PREFIX)/lib
# on x86_64, we might have /usr/lib64 directory instead of /usr/lib
MACHINE := $(shell uname -m)
ifeq ($(MACHINE), x86_64)
ifeq (,$(wildcard $(LIBDIR)))
LIBDIR = $(DESTDIR)$(PREFIX)/lib64
else
LIBDIR = $(DESTDIR)$(PREFIX)/lib
endif
endif

INSTALL_DATA ?= install -m0644
INSTALL_LIBRARY ?= install -m0755

LIBNAME = capstone

LIBOBJ =
LIBOBJ += cs.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o

ifneq (,$(findstring powerpc,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/PowerPC/PPCDisassembler.o
	LIBOBJ += arch/PowerPC/PPCInstPrinter.o
#	LIBOBJ += arch/PowerPC/mapping.o
	LIBOBJ += arch/PowerPC/module.o
endif
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/ARM/ARMDisassembler.o
	LIBOBJ += arch/ARM/ARMInstPrinter.o
	LIBOBJ += arch/ARM/mapping.o
	LIBOBJ += arch/ARM/module.o
endif
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/X86/X86DisassemblerDecoder.o
	LIBOBJ += arch/X86/X86Disassembler.o
	LIBOBJ += arch/X86/X86IntelInstPrinter.o
	LIBOBJ += arch/X86/X86ATTInstPrinter.o
	LIBOBJ += arch/X86/mapping.o arch/X86/module.o
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/Mips/MipsDisassembler.o
	LIBOBJ += arch/Mips/MipsInstPrinter.o
	LIBOBJ += arch/Mips/mapping.o
	LIBOBJ += arch/Mips/module.o
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/AArch64/AArch64BaseInfo.o
	LIBOBJ += arch/AArch64/AArch64Disassembler.o
	LIBOBJ += arch/AArch64/AArch64InstPrinter.o
	LIBOBJ += arch/AArch64/mapping.o
	LIBOBJ += arch/AArch64/module.o
endif

LIBOBJ += MCInst.o

UNAME_S := $(shell uname -s)
# OSX?
ifeq ($(UNAME_S),Darwin)
EXT = dylib
AR_EXT = a
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
AR_EXT = a
LDFLAGS += -Wl,-soname,$(LIBRARY)
endif
endif
endif

LIBRARY = lib$(LIBNAME).$(EXT)
ARCHIVE = lib$(LIBNAME).$(AR_EXT)
PKGCFGF = $(LIBNAME).pc

VERSION=$(shell echo `grep -e PKG_MAJOR -e PKG_MINOR CONFIG | grep -v = | awk '{print $$3}'` | awk '{print $$1"."$$2}')

.PHONY: all clean install uninstall

all: $(LIBRARY) $(ARCHIVE) $(PKGCFGF)
	$(MAKE) -C tests
	$(INSTALL_DATA) lib$(LIBNAME).$(EXT) tests

$(LIBRARY): $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o $(LIBRARY)

$(ARCHIVE): $(LIBOBJ)
	rm -f $(ARCHIVE)
	$(AR) q $(ARCHIVE) $(LIBOBJ)
	$(RANLIB) $(ARCHIVE)

$(PKGCFGF):
	echo 'Name: capstone' > $(PKGCFGF)
	echo 'Description: Capstone disassembler engine' >> $(PKGCFGF)
	echo 'Version: $(VERSION)' >> $(PKGCFGF)
	echo 'libdir=$(LIBDIR)' >> $(PKGCFGF)
	echo 'includedir=$(PREFIX)/include/capstone' >> $(PKGCFGF)
	echo 'archive=$${libdir}/libcapstone.a' >> $(PKGCFGF)
	echo 'Libs: -L$${libdir} -lcapstone' >> $(PKGCFGF)
	echo 'Cflags: -I$${includedir}' >> $(PKGCFGF)

install: $(PKGCFGF) $(ARCHIVE) $(LIBRARY)
	mkdir -p $(LIBDIR)
	$(INSTALL_LIBRARY) lib$(LIBNAME).$(EXT) $(LIBDIR)
	$(INSTALL_DATA) lib$(LIBNAME).$(AR_EXT) $(LIBDIR)
	mkdir -p $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/capstone.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/x86.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/arm.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/arm64.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/mips.h $(INCDIR)/$(LIBNAME)
	mkdir -p $(LIBDIR)/pkgconfig
	$(INSTALL_DATA) $(PKGCFGF) $(LIBDIR)/pkgconfig/

uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).$(EXT)
	rm -f $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
	rm -f $(LIBDIR)/pkgconfig/$(LIBNAME).pc

clean:
	rm -f $(LIBOBJ) lib$(LIBNAME).*
	#cd bindings/ruby; $(MAKE) clean; rm -rf Makefile
	$(MAKE) -C bindings/python clean
	$(MAKE) -C bindings/csharp clean
	$(MAKE) -C bindings/java clean
	$(MAKE) -C bindings/ocaml clean
	$(MAKE) -C tests clean

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
