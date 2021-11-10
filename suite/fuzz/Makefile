# Capstone Disassembler Engine
# By Philippe Antoine <contact@catenacyber.fr>, 2018

include ../../config.mk
include ../../functions.mk

ifneq ($(CAPSTONE_STATIC),yes)
$(error Needs static capstone.)
endif

# Verbose output?
V ?= 0

INCDIR = ../../include
ifndef BUILDDIR
TESTDIR = .
OBJDIR = .
LIBDIR = ../..
else
TESTDIR = $(BUILDDIR)/tests
OBJDIR = $(BUILDDIR)/obj/tests
LIBDIR = $(BUILDDIR)
endif

CFLAGS += -Wall -I$(INCDIR)
LDFLAGS += -L$(LIBDIR)

CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
FUZZLDFLAGS =

LIBNAME = capstone

IS_CYGWIN := $(shell $(CC) -dumpmachine 2>/dev/null | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
EXT = dll
AR_EXT = lib
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else
BIN_EXT =
AR_EXT = a
ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
endif


ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)

.PHONY: all clean

SOURCES = fuzz_disasm.c drivermc.c fuzz_harness.c driverbin.c platform.c
OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
# reproducer using MC file as input
REPRODUCERMC = $(addprefix $(TESTDIR)/,fuzz_disasm$(BIN_EXT))
# reproducer using raw binary file as input (as produced by fuzzer)
REPRODUCERBIN = $(addprefix $(TESTDIR)/,fuzz_bindisasm$(BIN_EXT))
# fuzzer
FUZZERBIN = $(addprefix $(TESTDIR)/,fuzz_bindisasm2$(BIN_EXT))
PLATFORMDECODE = $(addprefix $(TESTDIR)/,fuzz_decode_platform$(BIN_EXT))

all: $(REPRODUCERMC) $(REPRODUCERBIN) $(FUZZERBIN) $(PLATFORMDECODE)

clean:
	rm -rf fuzz_harness $(OBJS) $(PLATFORMDECODE) $(REPRODUCERMC) $(REPRODUCERBIN) $(FUZZERBIN) $(OBJDIR)/lib$(LIBNAME).* $(OBJDIR)/$(LIBNAME).*
	rm -f *.d $(OBJDIR)/*.d

$(REPRODUCERMC): fuzz_disasm.o drivermc.o platform.o
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,LINK,$(notdir $@))
	@$(link-static)
else
	$(link-static)
endif

$(REPRODUCERBIN): fuzz_disasm.o driverbin.o platform.o
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,LINK,$(notdir $@))
	@$(link-static)
else
	$(link-static)
endif

$(FUZZERBIN): FUZZLDFLAGS="-fsanitize=fuzzer"

$(FUZZERBIN): fuzz_disasm.o platform.o
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,LINK,$(notdir $@))
	@$(link-static) || touch $(FUZZERBIN)
else
	$(link-static) || touch $(FUZZERBIN)
endif

$(PLATFORMDECODE): fuzz_decode_platform.o platform.o
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,LINK,$(notdir $@))
	@$(link-static)
else
	$(link-static)
endif

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:$(OBJDIR)/%=%))
	@$(compile)
else
	$(compile)
endif



define link-static
	$(CC) $(LDFLAGS) $(FUZZLDFLAGS) $^ $(ARCHIVE) -o $@
endef

fuzz_harness: fuzz_harness.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@
