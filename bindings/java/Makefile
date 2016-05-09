# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

BUILDDIR = .

ifndef BUILDDIR
BLDIR = .
OBJDIR = .
BINDIR = .
TESTDIR = .
else
BLDIR = $(abspath $(BUILDDIR))
OBJDIR = $(abspath $(BUILDDIR))/capstone/src/main/java/capstone
BINDIR = $(abspath $(BUILDDIR))/capstone/bin
TESTDIR = $(abspath $(BUILDDIR))/capstone/src/test/java/capstone
endif

ifneq ($(wildcard $(JNA)),)
else
  ifneq ($(wildcard /usr/share/java/jna.jar),)
    JNA = /usr/share/java/jna.jar
  else
    JNA = $(BLDIR)/jna.jar
  endif
endif

CAPSTONE_JAVA = Capstone.java Arm_const.java Arm64_const.java Mips_const.java \
				X86_const.java Xcore_const.java Ppc_const.java Sparc_const.java\
				Sysz_const.java \
				Arm.java Arm64.java Mips.java X86.java Xcore.java Ppc.java\
				Sparc.java Systemz.java

CAPSTONE_TEST_JAVA = Test.java\
		TestArm.java TestArm64.java TestMips.java TestX86.java TestXcore.java\
		TestPpc.java TestSparc.java TestSystemz.java

all: gen_const capstone

capstone: capstone_class
ifdef BUILDDIR
	@mkdir -p $(BLDIR)
	cd $(BLDIR) && jar cf $(BLDIR)/capstone.jar $(BINDIR)/capstone/*.class
else
	cd $(BLDIR) && jar cf $(BLDIR)/capstone.jar $(BINDIR)/*.class
endif

capstone_class: jna
ifdef BUILDDIR
	@mkdir -p $(BINDIR)
	cd $(OBJDIR) && javac -d $(BINDIR) -classpath $(JNA) $(CAPSTONE_JAVA)
else
	cd $(OBJDIR) && javac -classpath $(JNA) $(CAPSTONE_JAVA)
endif

#tests: capstone_class jna
#	@mkdir -p $(BINDIR)
#	cd $(TESTDIR) && javac -d $(BINDIR) -classpath "$(JNA):$(BLDIR)/capstone.jar" $(CAPSTONE_TEST_JAVA)

gen_const:
	cd ../ && python const_generator.py java

jna:
	@if [ ! $(JNA) ]; then echo "*** Unable to find JNA ***"; exit 1; fi

clean:
	rm -rf $(OBJDIR)/*.log $(OBJDIR)/*_const.java $(BLDIR)/capstone.jar
ifdef BUILDDIR
	rm -rf $(BINDIR)
else
	rm -rf $(BINDIR)/*.class
endif

#TESTS = test arm arm64 mips ppc sparc systemz x86 xcore
#check:
#	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./run.sh $$t > /dev/null && echo OK || echo FAILED; \
	done

