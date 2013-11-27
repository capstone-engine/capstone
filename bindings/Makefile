TMPDIR = /tmp/capstone_test

DIFF = diff -u -b

TEST = $(TMPDIR)/test
TEST_ARM = $(TMPDIR)/test_arm
TEST_ARM64 = $(TMPDIR)/test_arm64
TEST_MIPS = $(TMPDIR)/test_mips
TEST_X86 = $(TMPDIR)/test_x86

all: expected python_test java_test #oclma_test ruby_test

expected:
	$(MAKE) -C ../tests
	mkdir -p $(TMPDIR)
	../tests/test > $(TEST)_e
	../tests/test_arm > $(TEST_ARM)_e
	../tests/test_arm64 > $(TEST_ARM64)_e
	../tests/test_mips > $(TEST_MIPS)_e
	../tests/test_x86 > $(TEST_X86)_e

python: FORCE
	python python/test.py > $(TEST)_o
	python python/test_arm.py > $(TEST_ARM)_o
	python python/test_arm64.py > $(TEST_ARM64)_o
	python python/test_mips.py > $(TEST_MIPS)_o
	python python/test_x86.py > $(TEST_X86)_o

java: FORCE
	$(MAKE) -C java
	cd java; ./run.sh > $(TEST)_o
	cd java; ./run.sh arm > $(TEST_ARM)_o
	cd java; ./run.sh arm64 > $(TEST_ARM64)_o
	cd java; ./run.sh mips > $(TEST_MIPS)_o
	cd java; ./run.sh x86 > $(TEST_X86)_o

test:
	$(DIFF) $(TEST)_e $(TEST)_o
	$(DIFF) $(TEST_ARM)_e $(TEST_ARM)_o
	$(DIFF) $(TEST_ARM64)_e $(TEST_ARM64)_o
	$(DIFF) $(TEST_MIPS)_e $(TEST_MIPS)_o
	$(DIFF) $(TEST_X86)_e $(TEST_X86)_o

python_test: python test
java_test: java test

FORCE:
