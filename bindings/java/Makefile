# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

JNA = /usr/share/java/jna/jna.jar

ifneq ($(wildcard $(JNA)),)
else
  ifneq ($(wildcard /usr/share/java/jna.jar),)
    JNA = /usr/share/java/jna.jar
  else
    JNA =
  endif
endif

CAPSTONE_JAVA = Capstone.java Arm.java Arm64.java Mips.java X86.java

all: capstone tests

capstone: capstone_class
	jar cf capstone.jar capstone/*.class

capstone_class: jna
	cd capstone; javac -classpath $(JNA) $(CAPSTONE_JAVA)

tests: jna
	javac -classpath "$(JNA):capstone.jar" Test.java TestArm.java TestArm64.java TestMips.java TestX86.java

jna:
	@if [ ! $(JNA) ]; then echo "*** Unable to find JNA ***"; exit 1; fi

clean:
	rm -rf *.class *.log *.jar
