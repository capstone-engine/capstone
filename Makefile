# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

# NOTE: at the moment this Makefile is for *nix only.

CC = $(CROSS)gcc

CFLAGS  += -fPIC -O3 -Wall -Iinclude
LDFLAGS += -shared

LIBNAME = capstone
LIBOBJ =
LIBOBJ += cs.o asprintf.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o
LIBOBJ += arch/Mips/MipsDisassembler.o arch/Mips/MipsInstPrinter.o arch/Mips/mapping.o
LIBOBJ += arch/X86/X86DisassemblerDecoder.o arch/X86/X86Disassembler.o arch/X86/X86IntelInstPrinter.o arch/X86/X86ATTInstPrinter.o arch/X86/mapping.o
LIBOBJ += arch/ARM/ARMDisassembler.o arch/ARM/ARMInstPrinter.o arch/ARM/mapping.o
LIBOBJ += arch/AArch64/AArch64BaseInfo.o arch/AArch64/AArch64Disassembler.o arch/AArch64/AArch64InstPrinter.o arch/AArch64/mapping.o
LIBOBJ += MCInst.o


# by default, lib extension is .so
EXT = so
PERMS = 0644

# OSX
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
EXT = dylib
endif

# Cygwin
UNAME_S := $(shell uname -s | sed 's|.*\(CYGWIN\).*|CYGWIN|')
ifeq ($(UNAME_S),CYGWIN)
EXT = dll
# Cygwin doesn't like -fPIC
CFLAGS := $(CFLAGS:-fPIC=)
# On Windows we need the shared library to be executable
PERMS = 0755
endif


.PHONY: all clean lib install uninstall

all: lib
	make -C tests
	install -m$(PERMS) lib$(LIBNAME).$(EXT) tests

lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o lib$(LIBNAME).$(EXT)
	# MacOS doesn't like strip
	#strip lib$(LIBNAME).$(EXT)

install: lib
	install -m$(PERMS) lib$(LIBNAME).$(EXT) /usr/lib
	mkdir -p /usr/include/$(LIBNAME)
	install -m0644 include/capstone.h /usr/include/$(LIBNAME)
	install -m0644 include/x86.h /usr/include/$(LIBNAME)
	install -m0644 include/arm.h /usr/include/$(LIBNAME)
	install -m0644 include/arm64.h /usr/include/$(LIBNAME)
	install -m0644 include/mips.h /usr/include/$(LIBNAME)

uninstall:
	rm -rf /usr/include/$(LIBNAME)
	rm -rf /usr/lib/lib$(LIBNAME).$(EXT)

clean:
	rm -f $(LIBOBJ) lib$(LIBNAME).*
	#cd bindings/ruby; make clean; rm -rf Makefile
	cd bindings/python; make clean
	cd bindings/csharp; make clean
	cd bindings/java; make clean
	cd bindings/ocaml; make clean
	make -C tests clean

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

