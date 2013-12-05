# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

include ../Makefile.global

INCDIR = ../include
LIBDIR = ..

CFLAGS += -I$(INCDIR) -L$(LIBDIR)

LIBNAME = capstone

BIN_EXT =

.PHONY: all clean

SOURCES = test.c test_detail.c 

ifneq (,$(findstring x86,$(CAPSTONE_ARCHS)))
SOURCES += test_x86.c
endif
ifneq (,$(findstring aarch64,$(CAPSTONE_ARCHS)))
SOURCES += test_arm64.c
endif
ifneq (,$(findstring arm,$(CAPSTONE_ARCHS)))
SOURCES += test_arm.c
endif
ifneq (,$(findstring mips,$(CAPSTONE_ARCHS)))
SOURCES += test_mips.c
endif

OBJS = $(SOURCES:.c=.o)
BINARY = $(SOURCES:.c=$(BIN_EXT))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(SOURCES:.c=) $(SOURCES:.c=.exe) lib$(LIBNAME).*

$(BINARY): $(OBJS)

%$(BIN_EXT): %.o
	${CC} $(CFLAGS) $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@
