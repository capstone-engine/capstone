CFLAGS += -I ../include -L ../
LDLIBS += -lcapstone

TESTS_SOURCE = $(wildcard *.c)
TESTS = $(TESTS_SOURCE:%.c=%)

.PHONY: all clean check

all: $(TESTS)

clean:
	rm -rf $(TESTS)

check: ${TESTS}
	./test_arm
	./test_arm64
	./test_basic
	./test_customized_mnem
	./test_detail
	./test_evm
	./test_iter
	./test_m680x
	./test_m68k
	./test_mips
	./test_mos65xx
	./test_ppc
	./test_skipdata
	./test_sparc
	./test_systemz
	./test_tms320c64x
	./test_x86
	./test_xcore
