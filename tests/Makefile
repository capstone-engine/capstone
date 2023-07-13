# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014

include ../config.mk
include ../functions.mk

# Verbose output?
V ?= 0

INCDIR = ../include
ifndef BUILDDIR
TESTDIR = .
OBJDIR = .
LIBDIR = ..
else
TESTDIR = $(BUILDDIR)/tests
OBJDIR = $(BUILDDIR)/obj/tests
LIBDIR = $(BUILDDIR)
endif

ifeq ($(CROSS),)
CC ?= cc
else
CC = $(CROSS)gcc
endif


CFLAGS += -Wall -I$(INCDIR)
LDFLAGS += -L$(LIBDIR)

CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))

LIBNAME = capstone

BIN_EXT =
AR_EXT = a

# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = lib
else
# mingw?
IS_MINGW := $(shell $(CC) --version 2>/dev/null | grep -i "\(mingw\|MSYS\)" | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = lib
endif
endif

ifeq ($(CAPSTONE_STATIC),yes)
ifeq ($(IS_MINGW),1)
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else ifeq ($(IS_CYGWIN),1)
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
endif
endif

.PHONY: all clean

SOURCES = test_basic.c test_detail.c test_skipdata.c test_iter.c test_customized_mnem.c
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_ARM
SOURCES += test_arm.c
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_ARM64
SOURCES += test_arm64.c
endif
ifneq (,$(findstring m68k,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_M68K
SOURCES += test_m68k.c
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_MIPS
SOURCES += test_mips.c
endif
ifneq (,$(findstring powerpc,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_POWERPC
SOURCES += test_ppc.c
endif
ifneq (,$(findstring sparc,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_SPARC
SOURCES += test_sparc.c
endif
ifneq (,$(findstring systemz,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_SYSZ
SOURCES += test_systemz.c
endif
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_X86
SOURCES += test_x86.c
endif
ifneq (,$(findstring xcore,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_XCORE
SOURCES += test_xcore.c
endif
ifneq (,$(findstring tms320c64x,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_TMS320C64X
SOURCES += test_tms320c64x.c
endif
ifneq (,$(findstring m680x,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_M680X
SOURCES += test_m680x.c
endif
ifneq (,$(findstring evm,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_EVM
SOURCES += test_evm.c
endif
ifneq (,$(findstring riscv,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_RISCV
SOURCES += test_riscv.c
endif
ifneq (,$(findstring wasm,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_WASM
SOURCES += test_wasm.c
endif
ifneq (,$(findstring evm,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_MOS65XX
SOURCES += test_mos65xx.c
endif
ifneq (,$(findstring bpf,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_BPF
SOURCES += test_bpf.c
endif
ifneq (,$(findstring tricore,$(CAPSTONE_ARCHS)))
SOURCES += test_tricore.c
endif
ifneq (,$(findstring sh,$(CAPSTONE_ARCHS)))
CFLAGS += -DCAPSTONE_HAS_SH
SOURCES += test_sh.c
endif

OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
BINARY = $(addprefix $(TESTDIR)/,$(SOURCES:.c=$(BIN_EXT)))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(BINARY) $(TESTDIR)/*.exe $(TESTDIR)/*.static $(OBJDIR)/lib$(LIBNAME).* $(OBJDIR)/$(LIBNAME).*
	rm -f *.d $(TESTDIR)/*.d $(OBJDIR)/*.d
	# remove orphan files due to renaming from test.c to test_basic.c
	rm -rf $(TESTDIR)/test.o $(TESTDIR)/test.exe $(TESTDIR)/test.static $(TESTDIR)/test

$(BINARY): $(OBJS)

$(TESTDIR)/%$(BIN_EXT): $(OBJDIR)/%.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(CAPSTONE_SHARED),yes)
	$(call log,LINK,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(CAPSTONE_STATIC),yes)
	$(call log,LINK,$(notdir $(call staticname,$@)))
	@$(link-static)
endif
else
ifeq ($(CAPSTONE_SHARED),yes)
	$(link-dynamic)
endif
ifeq ($(CAPSTONE_STATIC),yes)
	$(link-static)
endif
endif

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:$(OBJDIR)/%=%))
	@$(compile)
else
	$(compile)
endif


define link-dynamic
	$(CC) $(LDFLAGS) $< -l$(LIBNAME) -o $@
endef


define link-static
	$(CC) $(LDFLAGS) $< $(ARCHIVE) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)
