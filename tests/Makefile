# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

include ../config.mk

INCDIR = ../include
LIBDIR = ..

ifeq ($(CROSS),)
CC ?= cc
else
CC = $(CROSS)gcc
endif


CFLAGS += -fPIC -O3 -Wall -I$(INCDIR) -L$(LIBDIR)

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

SOURCES = test.c test_detail.c
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
ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
SOURCES += test_x86.c
endif

OBJS = $(SOURCES:.c=.o)
BINARY = $(SOURCES:.c=$(BIN_EXT))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(SOURCES:.c=) *.exe *.static lib$(LIBNAME).*

$(BINARY): $(OBJS)

%$(BIN_EXT): %.o
	${CC} $(CFLAGS) $(LDFLAGS) $< -O3 -Wall -l$(LIBNAME) -o $@
	${CC} $(CFLAGS) $(LDFLAGS) $< -O3 -Wall ../lib$(LIBNAME).$(AR_EXT) -o $(subst $(BIN_EXT),,$@).static$(BIN_EXT)

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@
