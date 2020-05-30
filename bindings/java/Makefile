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

CAPSTONE_JAVA = Capstone.java Arm_const.java Arm64_const.java Mips_const.java \
				X86_const.java Xcore_const.java Ppc_const.java Sparc_const.java\
				Sysz_const.java M680x_const.java \
				Arm.java Arm64.java Mips.java X86.java Xcore.java Ppc.java\
				Sparc.java Systemz.java M680x.java

all: gen_const capstone tests

capstone: capstone_class
	@mkdir -p $(BLDIR)
	cd $(OBJDIR) && jar cf $(BLDIR)/capstone.jar capstone/*.class

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
		TestArm.java TestArm64.java TestMips.java TestX86.java TestXcore.java\
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

TESTS = testbasic arm arm64 m680x mips ppc sparc systemz x86 xcore
check:
	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./run.sh $$t > /dev/null && echo OK || echo FAILED; \
	done

