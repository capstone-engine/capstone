# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013>

JNA = /usr/share/java/jna/jna.jar

CAPSTONE_JAVA = Capstone.java Arm.java Arm64.java Mips.java X86.java

all: capstone tests

capstone: capstone_class
	jar cf capstone.jar capstone/*.class

capstone_class:
	cd capstone; javac -classpath $(JNA) $(CAPSTONE_JAVA)

tests:
	javac -classpath "$(JNA):capstone.jar" Test.java TestArm.java TestArm64.java TestMips.java TestX86.java

clean:
	rm -rf *.class *.log *.jar
