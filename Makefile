# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>
#
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
if [ ! -d “$(LIBDIR)" ]; then LIBDIR = $(DESTDIR)$(PREFIX)/lib64;  fi
endif

INSTALL_DATA ?= install -m0644
INSTALL_LIBRARY ?= install -m0755

LIBNAME = capstone

LIBOBJ =
LIBOBJ += cs.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/ARM/ARMDisassembler.o arch/ARM/ARMInstPrinter.o arch/ARM/mapping.o arch/ARM/module.o
	CFLAGS += -DCS_SUPPORT_ARM
endif
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/X86/X86DisassemblerDecoder.o arch/X86/X86Disassembler.o arch/X86/X86IntelInstPrinter.o arch/X86/X86ATTInstPrinter.o arch/X86/mapping.o arch/X86/module.o
	CFLAGS += -DCS_SUPPORT_X86
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/Mips/MipsDisassembler.o arch/Mips/MipsInstPrinter.o arch/Mips/mapping.o arch/Mips/module.o
	CFLAGS += -DCS_SUPPORT_AARCH64
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
	LIBOBJ += arch/AArch64/AArch64BaseInfo.o arch/AArch64/AArch64Disassembler.o arch/AArch64/AArch64InstPrinter.o arch/AArch64/mapping.o arch/AArch64/module.o
	CFLAGS += -DCS_SUPPORT_MIPS
endif
LIBOBJ += MCInst.o

EXT = so
AR_EXT = a

# OSX?
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
EXT = dylib
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
