# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

ifndef BUILDDIR
BLDIR = .
OBJDIR = .
else
BLDIR = $(abspath $(BUILDDIR))/bindings/java
OBJDIR = $(abspath $(BUILDDIR))/obj/bindings/java
endif

JNA = /usr/share/java/jna/jna.jar

ifneq ($(wildcard $(JNA)),)
else
  ifneq ($(wildcard /usr/share/java/jna.jar),)
    JNA = /usr/share/java/jna.jar
  else
    JNA =
  endif
endif

PYTHON2 ?= python

CAPSTONE_JAVA = Capstone.java Arm_const.java AArch64_const.java Mips_const.java \
				X86_const.java Xcore_const.java Ppc_const.java Sparc_const.java\
				Systemz_const.java M680x_const.java Riscv_const.java Sh_const.java \
				Bpf_const.java M68k_const.java TMS320C64x_const.java Evm_const.java \
				Mos65xx_const.java Wasm_const.java Tricore_const.java Hppa_const.java \
				Loongarch_const.java Alpha_const.java Xtensa_const.java \
				Arc_const.java \
				Arm.java AArch64.java Mips.java X86.java Xcore.java Ppc.java\
				Sparc.java Systemz.java M680x.java Riscv.java Sh.java Bpf.java \
				Alpha.java Hppa.java Tricore.java Loongarch.java M68k.java \
				Evm.java Mos65xx.java Wasm.java TMS320C64x.java Xtensa.java \
				Arc.java

all: gen_const capstone tests

capstone: capstone_class
	@mkdir -p $(BLDIR)
	cd $(OBJDIR) && jar cf $(BLDIR)/capstone.jar capstone/*.class
	cp $(BLDIR)/capstone.jar cstest_java/app/libs

capstone_class: jna
ifdef BUILDDIR
	@mkdir -p $(OBJDIR)
	cd capstone && javac -d $(OBJDIR) -classpath $(JNA) $(CAPSTONE_JAVA)
else
	cd capstone && javac -classpath $(JNA) $(CAPSTONE_JAVA)
endif

tests: capstone_class jna
	@mkdir -p $(OBJDIR)
	javac -d $(OBJDIR) -classpath "$(JNA):$(BLDIR)/capstone.jar" TestBasic.java\
		TestArm.java TestAArch64.java TestMips.java TestX86.java TestXcore.java\
		TestPpc.java TestSparc.java TestSystemz.java TestM680x.java

gen_const:
	cd ../ && $(PYTHON2) const_generator.py java

jna:
	@if [ ! $(JNA) ]; then echo "*** Unable to find JNA ***"; exit 1; fi

clean:
	rm -rf $(OBJDIR)/capstone/*.class
	rm -rf $(OBJDIR)/*.class $(OBJDIR)/*.log $(BLDIR)/*.jar
ifdef BUILDDIR
	rm -rf $(BLDIR)
	rm -rf $(OBJDIR)
endif

TESTS = testbasic arm aarch64 m680x mips ppc sparc systemz x86 xcore
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./run.sh $$t > /dev/null && echo OK || echo FAILED; \
	done

cstest: capstone
	cd cstest_java && ./gradlew run -Djna.library.path=$(shell pwd)/../../build -Djna.debug_load=true --args='--verbosity=info --exclude should_fail_I.yaml --exclude should_fail_II.yaml --exclude should_fail_III.yaml --exclude should_fail_IV.yaml --exclude should_fail_V.yaml --exclude should_fail_VI.yaml'

