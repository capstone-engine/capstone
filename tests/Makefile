# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

INCDIR = ../include
LIBDIR = ..

CC = $(CROSS)gcc

CFLAGS += -fPIC -O3 -Wall -I$(INCDIR) -L$(LIBDIR)

LIBNAME = capstone

# Cygwin?
UNAME_S := $(shell uname -s | sed 's|.*\(CYGWIN\).*|CYGWIN|')
ifeq ($(UNAME_S),CYGWIN)
CFLAGS := $(CFLAGS:-fPIC=)
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
endif
endif

.PHONY: all clean

all: test.o test_detail.o test_x86.o test_arm64.o test_arm.o test_mips.o
	${CC} $(CFLAGS) test.o -O3 -Wall -l$(LIBNAME) -o test
	${CC} $(CFLAGS) test_detail.o -O3 -Wall -l$(LIBNAME) -o test_detail
	${CC} $(CFLAGS) test_x86.o -O3 -Wall -l$(LIBNAME) -o test_x86
	${CC} $(CFLAGS) test_arm64.o -O3 -Wall -l$(LIBNAME) -o test_arm64
	${CC} $(CFLAGS) test_arm.o -O3 -Wall -l$(LIBNAME) -o test_arm
	${CC} $(CFLAGS) test_mips.o -O3 -Wall -l$(LIBNAME) -o test_mips

clean:
	rm -rf test_x86 test_x86.exe test_x86.o
	rm -rf test_arm64 test_arm64.exe test_arm64.o
	rm -rf test_arm test_arm.exe test_arm.o
	rm -rf test_mips test_mips.exe test_mips.o
	rm -rf test test.exe test.o
	rm -rf test_detail test_detail.exe test_detail.o
	rm -f libcapstone.*

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

