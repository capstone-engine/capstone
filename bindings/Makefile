TMPDIR = /tmp/capstone_test

DIFF = diff -u -w

TEST = $(TMPDIR)/test
TEST_ARM = $(TMPDIR)/test_arm
TEST_ARM64 = $(TMPDIR)/test_arm64
TEST_MIPS = $(TMPDIR)/test_mips
TEST_PPC = $(TMPDIR)/test_ppc
TEST_SPARC = $(TMPDIR)/test_sparc
TEST_SYSZ = $(TMPDIR)/test_systemz
TEST_X86 = $(TMPDIR)/test_x86
TEST_XCORE = $(TMPDIR)/test_xcore

.PHONY: all expected python java ocaml

all:
	cd python && $(MAKE) gen_const
	cd java && $(MAKE) gen_const
	cd ocaml && $(MAKE) gen_const

tests: expected python java #oclma ruby

test_java: expected java
test_python: expected python

expected:
	cd ../tests && $(MAKE)
	mkdir -p $(TMPDIR)
	../tests/test > $(TEST)_e
	../tests/test_arm > $(TEST_ARM)_e
	../tests/test_arm64 > $(TEST_ARM64)_e
	../tests/test_mips > $(TEST_MIPS)_e
	../tests/test_ppc > $(TEST_PPC)_e
	../tests/test_sparc > $(TEST_SPARC)_e
	../tests/test_systemz > $(TEST_SYSZ)_e
	../tests/test_x86 > $(TEST_X86)_e
	../tests/test_xcore > $(TEST_XCORE)_e

python: FORCE
	cd python && $(MAKE)
	python python/test.py > $(TEST)_o
	python python/test_arm.py > $(TEST_ARM)_o
	python python/test_arm64.py > $(TEST_ARM64)_o
	python python/test_mips.py > $(TEST_MIPS)_o
	python python/test_ppc.py > $(TEST_PPC)_o
	python python/test_sparc.py > $(TEST_SPARC)_o
	python python/test_systemz.py > $(TEST_SYSZ)_o
	python python/test_x86.py > $(TEST_X86)_o
	python python/test_xcore.py > $(TEST_XCORE)_o
	$(MAKE) test_diff

java: FORCE
	cd java && $(MAKE)
	cd java && ./run.sh > $(TEST)_o
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
	$(DIFF) $(TEST)_e $(TEST)_o
	$(DIFF) $(TEST_ARM)_e $(TEST_ARM)_o
	$(DIFF) $(TEST_ARM64)_e $(TEST_ARM64)_o
	$(DIFF) $(TEST_MIPS)_e $(TEST_MIPS)_o
	$(DIFF) $(TEST_PPC)_e $(TEST_PPC)_o
	$(DIFF) $(TEST_SPARC)_e $(TEST_SPARC)_o
	$(DIFF) $(TEST_SYSZ)_e $(TEST_SYSZ)_o
	$(DIFF) $(TEST_X86)_e $(TEST_X86)_o
	$(DIFF) $(TEST_XCORE)_e $(TEST_XCORE)_o

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
