# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

include Makefile.global

CFLAGS += -Iinclude

LIBNAME = capstone
LIBOBJ =
LIBOBJ += cs.o utils.o SStream.o MCInstrDesc.o MCRegisterInfo.o
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
LIBOBJ += arch/ARM/ARMDisassembler.o arch/ARM/ARMInstPrinter.o arch/ARM/mapping.o
endif
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
LIBOBJ += arch/X86/X86DisassemblerDecoder.o arch/X86/X86Disassembler.o arch/X86/X86IntelInstPrinter.o arch/X86/X86ATTInstPrinter.o arch/X86/mapping.o
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
LIBOBJ += arch/Mips/MipsDisassembler.o arch/Mips/MipsInstPrinter.o arch/Mips/mapping.o
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
LIBOBJ += arch/AArch64/AArch64BaseInfo.o arch/AArch64/AArch64Disassembler.o arch/AArch64/AArch64InstPrinter.o arch/AArch64/mapping.o
endif
LIBOBJ += MCInst.o

.PHONY: all clean lib archive install uninstall

all: lib archive
	$(MAKE) -C tests
	$(INSTALL_DATA) lib$(LIBNAME).$(EXT) tests

lib: $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) -o lib$(LIBNAME).$(EXT)
	# MacOS doesn't like strip
	#strip lib$(LIBNAME).$(EXT)

archive: $(LIBOBJ)
	rm -f lib$(LIBNAME).$(AR_EXT)
	$(AR) q lib$(LIBNAME).$(AR_EXT) $(LIBOBJ)
	$(RANLIB) lib$(LIBNAME).$(AR_EXT)

PC=capstone.pc
VERSION=$(shell echo `grep -e PKG_MAJOR -e PKG_MINOR cs.c|grep -v =| awk '{print $$3}'` | awk '{print $$1"."$$2}')

capstone.pc: lib$(LIBNAME).$(AR_EXT)
	echo Name: capstone > $(PC)
	echo Description: Capstone disassembler engine >> $(PC)
	echo Version: $(VERSION) >> $(PC)
	echo Libs: -L$(LIBDIR) -lcapstone >> $(PC)
	echo Cflags: -I$(PREFIX)/include/capstone >> $(PC)

install: capstone.pc archive lib
	mkdir -p $(LIBDIR)
	$(INSTALL_LIBRARY) lib$(LIBNAME).$(EXT) $(LIBDIR)
	$(INSTALL_DATA) lib$(LIBNAME).$(AR_EXT) $(LIBDIR)
	mkdir -p $(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/capstone.h $(INCDIR)/$(LIBNAME)
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
	$(INSTALL_DATA) include/x86.h $(INCDIR)/$(LIBNAME)
endif
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
	$(INSTALL_DATA) include/arm.h $(INCDIR)/$(LIBNAME)
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
	$(INSTALL_DATA) include/arm64.h $(INCDIR)/$(LIBNAME)
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
	$(INSTALL_DATA) include/mips.h $(INCDIR)/$(LIBNAME)
endif
	mkdir -p $(LIBDIR)/pkgconfig
	$(INSTALL_DATA) $(LIBNAME).pc $(LIBDIR)/pkgconfig/

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
	${CC} ${CFLAGS} -c $< -o $@
