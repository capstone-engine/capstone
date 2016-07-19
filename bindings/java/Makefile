# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

BUILDDIR = .
CURRENTDIR = $(abspath $(BUILDDIR))

OS = $(shell uname)

ifneq (,$(findstring NT-,$(OS)))
CYGWIN = $(firstword $(subst /, ,$(CURRENTDIR)))
DISK_LETTER = $(word 2,$(subst /, ,$(CURRENTDIR)))
BLDIR = $(subst /$(CYGWIN)/$(DISK_LETTER),$(DISK_LETTER):, $(CURRENTDIR))
else
BLDIR = $(CURRENTDIR)
endif

ifneq ($(wildcard $(JNA)),)
else
  ifneq ($(wildcard /usr/share/java/jna.jar),)
    JNA = /usr/share/java/jna.jar
  else
    JNA = $(BLDIR)/jna.jar
  endif
endif

# FIRSTWORD_JNA = $(firstword $(subst /, ,$(JNA)))

# ifeq ($(FIRSTWORD_JNA), 'cygwin')
#     JNA = $(subst /$(CYGWIN)/$(DISK_LETTER),$(DISK_LETTER):, $(JNA))
# endif

OBJDIR = $(BLDIR)/capstone/src/main/java/capstone
BINDIR = $(BLDIR)/capstone/bin
TESTDIR = $(BLDIR)/capstone/src/test/java/capstone
NATIDIR = $(BLDIR)/capstone/src/main/native

CAPSTONE_JAVA = Capstone.java Arm_const.java Arm64_const.java Mips_const.java \
				X86_const.java Xcore_const.java Ppc_const.java Sparc_const.java\
				Sysz_const.java \
				Arm.java Arm64.java Mips.java X86.java Xcore.java Ppc.java\
				Sparc.java Systemz.java

CAPSTONE_TEST_JAVA = Test.java\
		TestArm.java TestArm64.java TestMips.java TestX86.java TestXcore.java\
		TestPpc.java TestSparc.java TestSystemz.java

all: gen_const capstone build_maven

capstone: capstone_class
	@mkdir -p $(BLDIR)
	cd $(BLDIR) && jar cf $(BLDIR)/capstone.jar $(BINDIR)/capstone/*.class

capstone_class: jna
	@mkdir -p $(BINDIR)
	cd $(OBJDIR) && javac -d $(BINDIR) -classpath $(JNA) $(CAPSTONE_JAVA)

test_maven:
	./run-tests.sh
#tests: capstone_class jna
#	@mkdir -p $(BINDIR)
#	cd $(TESTDIR) && javac -d $(BINDIR) -classpath "$(JNA):$(BLDIR)/capstone.jar" $(CAPSTONE_TEST_JAVA)

gen_const:
	cd ../ && python const_generator.py java

jna:
	@if [ ! $(JNA) ]; then echo "*** Unable to find JNA ***"; exit 1; fi

build_maven:
	@mkdir -p $(NATIDIR)
ifneq (,$(findstring NT-,$(OS)))
	cd ../.. && $(MAKE) && cp capstone.dll $(NATIDIR)
	./build-jar.bat
else
	cd ../.. && $(MAKE) && cp libcapstone.* $(NATIDIR)
	./build-jar.sh
endif
	

clean:
	rm -rf $(BLDIR)/capstone/target $(BLDIR)/capstone.jar $(OBJDIR)/*.log
	rm -rf $(BINDIR)
	rm -rf $(NATIDIR)


#TESTS = test arm arm64 mips ppc sparc systemz x86 xcore
#check:
#	@for t in $(TESTS); do \
		echo Check $$t ... ; \
		./run.sh $$t > /dev/null && echo OK || echo FAILED; \
	done

