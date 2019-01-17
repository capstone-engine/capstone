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

LIBNAME = capstone

BIN_EXT =
AR_EXT = a


ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)

.PHONY: all clean

SOURCES = fuzz_disasm.c drivermc.c fuzz_harness.c driverbin.c
OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
BINARY = $(addprefix $(TESTDIR)/,fuzz_disasm$(BIN_EXT))
BINARYBIN = $(addprefix $(TESTDIR)/,fuzz_bindisasm$(BIN_EXT))

all: $(BINARY) $(BINARYBIN)

clean:
	rm -rf fuzz_harness $(OBJS) $(BINARY) $(BINARYBIN) $(OBJDIR)/lib$(LIBNAME).* $(OBJDIR)/$(LIBNAME).*

$(BINARY): fuzz_disasm.o drivermc.o
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,LINK,$(notdir $@))
	@$(link-static)
else
	$(link-static)
endif

$(BINARYBIN): fuzz_disasm.o driverbin.o
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
	$(CC) $(LDFLAGS) $^ $(ARCHIVE) -o $@
endef

fuzz_harness: fuzz_harness.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@
