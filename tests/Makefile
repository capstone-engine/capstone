# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

INCDIR = ../include
LIBDIR = ..

CC = $(CROSS)gcc

CFLAGS += -fPIC -O3 -Wall -I$(INCDIR) -L$(LIBDIR)

LIBNAME = capstone

.PHONY: all clean win_test

all: test test_detail test_x86 test_arm64 test_arm test_mips

test: test.o
	${CC} $(CFLAGS) test.o -O3 -Wall -l$(LIBNAME) -o test

test_detail: test_detail.o
	${CC} $(CFLAGS) test_detail.o -O3 -Wall -l$(LIBNAME) -o test_detail

test_x86: test_x86.o
	${CC} $(CFLAGS) test_x86.o -O3 -Wall -l$(LIBNAME) -o test_x86

test_arm64: test_arm64.o
	${CC} $(CFLAGS) test_arm64.o -O3 -Wall -l$(LIBNAME) -o test_arm64

test_arm: test_arm.o
	${CC} $(CFLAGS) test_arm.o -O3 -Wall -l$(LIBNAME) -o test_arm

test_mips: test_mips.o
	${CC} $(CFLAGS) test_mips.o -O3 -Wall -l$(LIBNAME) -o test_mips

# Mingw32
windows: test.o test_detail.o test_x86.o test_arm64.o test_arm.o test_mips.o
	${CC} test.o -O3 -Wall $(LIBNAME).dll -o test.exe
	${CC} test_detail.o -O3 -Wall $(LIBNAME).dll -o test_detail.exe
	${CC} test_x86.o -O3 -Wall $(LIBNAME).dll -o test_x86.exe
	${CC} test_arm64.o -O3 -Wall $(LIBNAME).dll -o test_arm64.exe
	${CC} test_arm.o -O3 -Wall $(LIBNAME).dll -o test_arm.exe
	${CC} test_mips.o -O3 -Wall $(LIBNAME).dll -o test_mips.exe

clean:
	rm -rf test_x86 test_x86.exe test_x86.o
	rm -rf test_arm64 test_arm64.exe test_arm64.o
	rm -rf test_arm test_arm.exe test_arm.o
	rm -rf test_mips test_mips.exe test_mips.o
	rm -rf test test.exe test.o
	rm -rf test_detail test_detail.exe test_detail.o
	rm -rf *.dll
	rm -rf *.so

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

