# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

# NOTE: at the moment this Makefile is for *nix only.

CC = $(CROSS)gcc
AR ?= ar
RANLIB ?= ranlib
STRIP ?= strip

CFLAGS  += -fPIC -O3 -Wall -Iinclude
LDFLAGS += -shared

PREFIX ?= /usr
DESTDIR ?=
INCDIR = $(DESTDIR)$(PREFIX)/include
LIBDIR = $(DESTDIR)$(PREFIX)/lib

INSTALL_DATA ?= install -m0644
INSTALL_LIBRARY ?= install -m0755

LIBNAME = capstone
LIBOBJ =
LIBOBJ += cs.o asprintf.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o
LIBOBJ += arch/Mips/MipsDisassembler.o arch/Mips/MipsInstPrinter.o arch/Mips/mapping.o
LIBOBJ += arch/X86/X86DisassemblerDecoder.o arch/X86/X86Disassembler.o arch/X86/X86IntelInstPrinter.o arch/X86/X86ATTInstPrinter.o arch/X86/mapping.o
LIBOBJ += arch/ARM/ARMDisassembler.o arch/ARM/ARMInstPrinter.o arch/ARM/mapping.o
LIBOBJ += arch/AArch64/AArch64BaseInfo.o arch/AArch64/AArch64Disassembler.o arch/AArch64/AArch64InstPrinter.o arch/AArch64/mapping.o
LIBOBJ += MCInst.o

# OSX is the exception
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
EXT = dylib
else
# by default, lib extension is .so
EXT = so
endif


.PHONY: all clean lib archive windows win_lib install uninstall

all: lib archive
	$(MAKE) -C tests
	$(INSTALL_DATA) lib$(LIBNAME).$(EXT) tests

lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o lib$(LIBNAME).$(EXT)
	# MacOS doesn't like strip
	#strip lib$(LIBNAME).$(EXT)

archive: $(LIBOBJ)
	rm -f lib$(LIBNAME).a
	$(AR) q lib$(LIBNAME).a $(LIBOBJ)
	$(RANLIB) lib$(LIBNAME).a

install: archive lib
	mkdir -p $(LIBDIR)
	$(INSTALL_LIBRARY) lib$(LIBNAME).$(EXT) $(LIBDIR)
	$(INSTALL_DATA) lib$(LIBNAME).a $(LIBDIR)
	mkdir -p $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/capstone.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/x86.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/arm.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/arm64.h $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/mips.h $(INCDIR)/$(LIBNAME)

uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).$(EXT)
	rm -f $(LIBDIR)/lib$(LIBNAME).a

# Mingw32
windows: win_lib
	$(INSTALL_DATA) $(LIBNAME).dll tests
	$(MAKE) -C tests windows

# Mingw32
win_lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o $(LIBNAME).dll
	$(STRIP) $(LIBNAME).dll

clean:
	rm -f $(LIBOBJ) lib$(LIBNAME).* $(LIBNAME).dll
	#cd bindings/ruby; $(MAKE) clean; rm -rf Makefile
	$(MAKE) -C bindings/python clean
	$(MAKE) -C bindings/csharp clean
	$(MAKE) -C bindings/java clean
	$(MAKE) -C bindings/ocaml clean
	$(MAKE) -C tests clean

.c.o:
	${CC} ${CFLAGS} -c $< -o $@
