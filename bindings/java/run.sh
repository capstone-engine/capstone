#!/bin/sh
JNA=/usr/share/java/jna.jar

if [ ! -f ${JNA} ]; then
  if [ ! -f /usr/share/java/jna/jna.jar ]; then
    echo "*** Unable to find jna.jar *** ";
    exit;
  else
    JNA=/usr/share/java/jna/jna.jar;
  fi
fi

CAPSTONE_PATH=../../build
JAVA_OPTS="-Djna.library.path=${CAPSTONE_PATH}"

case "$1" in
  "") java -classpath ${JNA}:. ${JAVA_OPTS} TestBasic ;;
  "testbasic") java -classpath ${JNA}:. ${JAVA_OPTS} TestBasic ;;
  "arm") java -classpath ${JNA}:. ${JAVA_OPTS} TestArm ;;
  "aarch64") java -classpath ${JNA}:. ${JAVA_OPTS} TestAArch64 ;;
  "mips") java -classpath ${JNA}:. ${JAVA_OPTS} TestMips ;;
  "x86") java -classpath ${JNA}:. ${JAVA_OPTS} TestX86 ;;
  "xcore") java -classpath ${JNA}:. ${JAVA_OPTS} TestXcore; ;;
  "ppc") java -classpath ${JNA}:. ${JAVA_OPTS} TestPpc ;;
  "sparc") java -classpath ${JNA}:. ${JAVA_OPTS} TestSparc ;;
  "systemz") java -classpath ${JNA}:. ${JAVA_OPTS} TestSystemz ;;
  "m680x") java -classpath ${JNA}:. ${JAVA_OPTS} TestM680x ;;
  * ) echo "Usage: ./run.sh [arm|aarch64|m680x|mips|ppc|sparc|systemz|x86]"; exit 1;;
esac
