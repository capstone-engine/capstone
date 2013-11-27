# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

# NOTE: at the moment this Makefile is for *nix only.

CC ?= $(CROSS)gcc

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

# OSX is the exception
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
EXT = dylib
endif


.PHONY: all clean lib windows win_lib install uninstall

all: lib
	make -C tests
	install -m0644 lib$(LIBNAME).$(EXT) tests

lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o lib$(LIBNAME).$(EXT)
	# MacOS doesn't like strip
	#strip lib$(LIBNAME).$(EXT)

install: lib
	install -m0644 lib$(LIBNAME).$(EXT) /usr/lib
	mkdir -p /usr/include/$(LIBNAME)
	install -m0644 include/capstone.h /usr/include/$(LIBNAME)
	install -m0644 include/x86.h /usr/include/$(LIBNAME)
	install -m0644 include/arm.h /usr/include/$(LIBNAME)
	install -m0644 include/arm64.h /usr/include/$(LIBNAME)
	install -m0644 include/mips.h /usr/include/$(LIBNAME)

uninstall:
	rm -rf /usr/include/$(LIBNAME)
	rm -rf /usr/lib/lib$(LIBNAME).$(EXT)

# Mingw32
windows: win_lib
	install -m0644 $(LIBNAME).dll tests
	make -C tests windows

# Mingw32
win_lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o $(LIBNAME).dll
	strip $(LIBNAME).dll

clean:
	rm -f $(LIBOBJ) lib$(LIBNAME).* $(LIBNAME).dll
	#cd bindings/ruby; make clean; rm -rf Makefile
	cd bindings/python; make clean
	cd bindings/csharp; make clean
	cd bindings/java; make clean
	cd bindings/ocaml; make clean
	make -C tests clean

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

