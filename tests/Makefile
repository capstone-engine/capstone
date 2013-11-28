# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

INCDIR = ../include
LIBDIR = ..

CC = $(CROSS)gcc

CFLAGS += -fPIC -O3 -Wall -I$(INCDIR) -L$(LIBDIR)

LIBNAME = capstone

.PHONY: all clean win_test linux windows

SOURCES = test.c test_detail.c test_x86.c test_arm64.c test_arm.c test_mips.c
OBJS = $(SOURCES:.c=.o)
BINARY_LINUX = $(SOURCES:.c=)
BINARY_WINDOWS = $(SOURCES:.c=.exe)

all: nix

nix: $(OBJS) $(BINARY_LINUX)

# Mingw32
windows: $(OBJS) $(BINARY_WINDOWS)

clean:
	rm -rf $(OBJS) $(BINARY_LINUX) $(BINARY_WINDOWS) *.dll *.so

%.exe: %.o
	${CC} $(CFLAGS) $^ -O3 -Wall $(LIBNAME).dll -o $@

%: %.o
	${CC} $(CFLAGS) $^ -O3 -Wall -l$(LIBNAME) -o $@

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

