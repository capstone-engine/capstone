TMPDIR = /tmp/capstone_test

DIFF = diff -u -w

TEST_BASIC = $(TMPDIR)/test_basic
TEST_DETAIL = $(TMPDIR)/test_detail
TEST_CUSTOMIZED_MNEM = $(TMPDIR)/test_customized_mnem
TEST_ARM = $(TMPDIR)/test_arm
TEST_ARM64 = $(TMPDIR)/test_aarch64
TEST_M68K = $(TMPDIR)/test_m68k
TEST_MIPS = $(TMPDIR)/test_mips
TEST_MOS65XX = $(TMPDIR)/test_mos65xx
TEST_PPC = $(TMPDIR)/test_ppc
TEST_SPARC = $(TMPDIR)/test_sparc
TEST_SYSZ = $(TMPDIR)/test_systemz
TEST_X86 = $(TMPDIR)/test_x86
TEST_XCORE = $(TMPDIR)/test_xcore
TEST_WASM = $(TMPDIR)/test_wasm
TEST_BPF = $(TMPDIR)/test_bpf
TEST_RISCV = $(TMPDIR)/test_riscv
TEST_EVM = $(TMPDIR)/test_evm
TEST_M680X = $(TMPDIR)/test_m680x
TEST_TRICORE = $(TMPDIR)/test_tricore
TEST_SH = $(TMPDIR)/test_sh
TEST_TMS320C64X = $(TMPDIR)/test_tms320c64x
TEST_ALPHA = $(TMPDIR)/test_alpha
TEST_HPPA = $(TMPDIR)/test_hppa

PYTHON3 ?= python3

BUILD_TESTS ?= yes

.PHONY: all expected python java ocaml

all:
	cd python && $(MAKE) gen_const
	cd java && $(MAKE) gen_const
	cd ocaml && $(MAKE) gen_const

tests: expected python #java oclma ruby

test_java: expected java
test_python: expected python

expected:
	if [ "$(BUILD_TESTS)" = "yes" ]; then cd ../tests && $(MAKE); fi
	mkdir -p $(TMPDIR)
	../tests/test_basic > $(TEST_BASIC)_e
	../tests/test_detail > $(TEST_DETAIL)_e
	../tests/test_customized_mnem > $(TEST_CUSTOMIZED_MNEM)_e
	../tests/test_arm > $(TEST_ARM)_e
	../tests/test_aarch64 > $(TEST_ARM64)_e
	../tests/test_m68k > $(TEST_M68K)_e
	../tests/test_mips > $(TEST_MIPS)_e
	../tests/test_mos65xx > $(TEST_MOS65XX)_e
	../tests/test_ppc > $(TEST_PPC)_e
	../tests/test_sparc > $(TEST_SPARC)_e
	../tests/test_systemz > $(TEST_SYSZ)_e
	../tests/test_x86 > $(TEST_X86)_e
	../tests/test_xcore > $(TEST_XCORE)_e
	../tests/test_wasm > $(TEST_WASM)_e
	../tests/test_bpf > $(TEST_BPF)_e
	../tests/test_riscv > $(TEST_RISCV)_e
	../tests/test_evm > $(TEST_EVM)_e
	../tests/test_m680x > $(TEST_M680X)_e
	../tests/test_sh > $(TEST_SH)_e
	../tests/test_tricore > $(TEST_TRICORE)_e
	../tests/test_tms320c64x > $(TEST_TMS320C64X)_e
	../tests/test_alpha > $(TEST_ALPHA)_e
	../tests/test_hppa > $(TEST_HPPA)_e

python: FORCE
	cd python && $(MAKE)
	$(PYTHON3) python/test_basic.py > $(TEST_BASIC)_o
	$(PYTHON3) python/test_detail.py > $(TEST_DETAIL)_o
	$(PYTHON3) python/test_customized_mnem.py > $(TEST_CUSTOMIZED_MNEM)_o
	$(PYTHON3) python/test_arm.py > $(TEST_ARM)_o
	$(PYTHON3) python/test_aarch64.py > $(TEST_ARM64)_o
	$(PYTHON3) python/test_m68k.py > $(TEST_M68K)_o
	$(PYTHON3) python/test_mips.py > $(TEST_MIPS)_o
	$(PYTHON3) python/test_mos65xx.py > $(TEST_MOS65XX)_o
	$(PYTHON3) python/test_ppc.py > $(TEST_PPC)_o
	$(PYTHON3) python/test_sparc.py > $(TEST_SPARC)_o
	$(PYTHON3) python/test_systemz.py > $(TEST_SYSZ)_o
	$(PYTHON3) python/test_x86.py > $(TEST_X86)_o
	$(PYTHON3) python/test_xcore.py > $(TEST_XCORE)_o
	$(PYTHON3) python/test_wasm.py > $(TEST_WASM)_o
	$(PYTHON3) python/test_bpf.py > $(TEST_BPF)_o
	$(PYTHON3) python/test_riscv.py > $(TEST_RISCV)_o
	$(PYTHON3) python/test_evm.py > $(TEST_EVM)_o
	$(PYTHON3) python/test_m680x.py > $(TEST_M680X)_o
	$(PYTHON3) python/test_sh.py > $(TEST_SH)_o
	$(PYTHON3) python/test_tricore.py > $(TEST_TRICORE)_o
	$(PYTHON3) python/test_tms320c64x.py > $(TEST_TMS320C64X)_o
	$(PYTHON3) python/test_alpha.py > $(TEST_ALPHA)_o
	$(PYTHON3) python/test_hppa.py > $(TEST_HPPA)_o
	$(MAKE) test_diff

java: FORCE
	cd java && $(MAKE)
	cd java && ./run.sh > $(TEST_BASIC)_o
	cd java && ./run.sh arm > $(TEST_ARM)_o
	cd java && ./run.sh arm64 > $(TEST_ARM64)_o
	cd java && ./run.sh mips > $(TEST_MIPS)_o
	cd java && ./run.sh ppc > $(TEST_PPC)_o
	cd java && ./run.sh sparc > $(TEST_SPARC)_o
	cd java && ./run.sh systemz > $(TEST_SYSZ)_o
	cd java && ./run.sh x86 > $(TEST_X86)_o
	cd java && ./run.sh xcore > $(TEST_XCORE)_o
	$(MAKE) test_diff

ocaml: FORCE

test_diff: FORCE
	$(DIFF) $(TEST_BASIC)_e $(TEST_BASIC)_o
	$(DIFF) $(TEST_DETAIL)_e $(TEST_DETAIL)_o
	$(DIFF) $(TEST_CUSTOMIZED_MNEM)_e $(TEST_CUSTOMIZED_MNEM)_o
	$(DIFF) $(TEST_ARM)_e $(TEST_ARM)_o
	$(DIFF) $(TEST_ARM64)_e $(TEST_ARM64)_o
	$(DIFF) $(TEST_M68K)_e $(TEST_M68K)_o
	$(DIFF) $(TEST_MIPS)_e $(TEST_MIPS)_o
	$(DIFF) $(TEST_MOS65XX)_e $(TEST_MOS65XX)_o
	$(DIFF) $(TEST_PPC)_e $(TEST_PPC)_o
	$(DIFF) $(TEST_SPARC)_e $(TEST_SPARC)_o
	$(DIFF) $(TEST_SYSZ)_e $(TEST_SYSZ)_o
	$(DIFF) $(TEST_X86)_e $(TEST_X86)_o
	$(DIFF) $(TEST_XCORE)_e $(TEST_XCORE)_o
	$(DIFF) $(TEST_WASM)_e $(TEST_WASM)_o
	$(DIFF) $(TEST_BPF)_e $(TEST_BPF)_o
	$(DIFF) $(TEST_RISCV)_e $(TEST_RISCV)_o
	$(DIFF) $(TEST_EVM)_e $(TEST_EVM)_o
	$(DIFF) $(TEST_M680X)_e $(TEST_M680X)_o
	$(DIFF) $(TEST_SH)_e $(TEST_SH)_o
	$(DIFF) $(TEST_TRICORE)_e $(TEST_TRICORE)_o
	$(DIFF) $(TEST_TMS320C64X)_e $(TEST_TMS320C64X)_o
	$(DIFF) $(TEST_ALPHA)_e $(TEST_ALPHA)_o
	$(DIFF) $(TEST_HPPA)_e $(TEST_HPPA)_o

clean:
	rm -rf $(TMPDIR)
	cd java && $(MAKE) clean
	cd python && $(MAKE) clean
	cd ocaml && $(MAKE) clean

check:
	make -C ocaml check
	make -C python check
	make -C java check

FORCE:
