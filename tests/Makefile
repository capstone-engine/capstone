CFLAGS += -I ../include -L ../
LDLIBS += -lcapstone
ENV_VARS = LD_LIBRARY_PATH=../ DYLD_LIBRARY_PATH=../ LIBCAPSTONE_PATH=../

TESTS_SOURCE = $(wildcard *.c)
TESTS = $(TESTS_SOURCE:%.c=%)

.PHONY: all clean check

all: $(TESTS)

clean:
	rm -rf $(TESTS)

check: ${TESTS}
	$(ENV_VARS) ./test_arm
	$(ENV_VARS) ./test_arm64
	$(ENV_VARS) ./test_basic
	$(ENV_VARS) ./test_customized_mnem
	$(ENV_VARS) ./test_detail
	$(ENV_VARS) ./test_evm
	$(ENV_VARS) ./test_iter
	$(ENV_VARS) ./test_m680x
	$(ENV_VARS) ./test_m68k
	$(ENV_VARS) ./test_mips
	$(ENV_VARS) ./test_mos65xx
	$(ENV_VARS) ./test_ppc
	$(ENV_VARS) ./test_skipdata
	$(ENV_VARS) ./test_sparc
	$(ENV_VARS) ./test_systemz
	$(ENV_VARS) ./test_tms320c64x
	$(ENV_VARS) ./test_x86
	$(ENV_VARS) ./test_xcore
