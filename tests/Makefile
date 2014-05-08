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


CFLAGS = -O3 -Wall -I$(INCDIR)
LDFLAGS = -L$(LIBDIR)

LIBNAME = capstone

BIN_EXT =
AR_EXT = a

# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = dll.a
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = dll.a
endif
endif

.PHONY: all clean

SOURCES = test.c test_detail.c test_skipdata.c
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
SOURCES += test_arm.c
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
SOURCES += test_arm64.c
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
SOURCES += test_mips.c
endif
ifneq (,$(findstring powerpc,$(CAPSTONE_ARCHS)))
SOURCES += test_ppc.c
endif
ifneq (,$(findstring sparc,$(CAPSTONE_ARCHS)))
SOURCES += test_sparc.c
endif
ifneq (,$(findstring systemz,$(CAPSTONE_ARCHS)))
SOURCES += test_systemz.c
endif
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
SOURCES += test_x86.c
endif

OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
BINARY = $(addprefix $(TESTDIR)/,$(SOURCES:.c=$(BIN_EXT)))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(BINARY) $(TESTDIR)/*.exe $(TESTDIR)/*.static $(OBJDIR)/lib$(LIBNAME).*

$(BINARY): $(OBJS)

$(TESTDIR)/%$(BIN_EXT): $(OBJDIR)/%.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(CAPSTONE_SHARED),yes)
	$(call log,CCLD,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(CAPSTONE_STATIC),yes)
	$(call log,CCLD,$(notdir $(call staticname,$@)))
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
	${CC} $(CFLAGS) $(LDFLAGS) $< -O3 -Wall -l$(LIBNAME) -o $@
endef


define link-static
	${CC} $(CFLAGS) $(LDFLAGS) $< -O3 -Wall $(LIBDIR)/lib$(LIBNAME).$(AR_EXT) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)
