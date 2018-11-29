# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2018

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

SOURCES = fuzz_disasm.c drivermc.c
OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
BINARY = $(addprefix $(TESTDIR)/,fuzz_disasm$(BIN_EXT))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(BINARY) $(OBJDIR)/lib$(LIBNAME).* $(OBJDIR)/$(LIBNAME).*

$(BINARY): $(OBJS)
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
