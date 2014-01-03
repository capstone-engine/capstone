# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

INCDIR = ../include
LIBDIR = ..

CC = $(CROSS)gcc

COMPILER = $(shell $(CC) -v 2>&1 )
ifeq ($(findstring clang,$(COMPILER)),clang)
# clang doesnt like -L option
CFLAGS += -fPIC -O3 -Wall -I$(INCDIR)
else
CFLAGS += -fPIC -O3 -Wall -I$(INCDIR) -L$(LIBDIR)
endif

LIBNAME = capstone

BIN_EXT =

# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
endif
endif

.PHONY: all clean

SOURCES = test.c test_detail.c test_x86.c test_arm64.c test_arm.c test_mips.c
OBJS = $(SOURCES:.c=.o)
BINARY = $(SOURCES:.c=$(BIN_EXT))

all: $(BINARY)

clean:
	rm -rf $(OBJS) $(SOURCES:.c=) $(SOURCES:.c=.exe) lib$(LIBNAME).*

$(BINARY): $(OBJS)

%$(BIN_EXT): %.o
	${CC} $(CFLAGS) $(LDFLAGS) $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@
