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

case "$1" in
  "") java -classpath ${JNA}:. Test ;;
  "test") java -classpath ${JNA}:. Test ;;
  "arm") java -classpath ${JNA}:. TestArm ;;
  "arm64") java -classpath ${JNA}:. TestArm64 ;;
  "mips") java -classpath ${JNA}:. TestMips ;;
  "x86") java -classpath ${JNA}:. TestX86 ;;
  "xcore") java -classpath ${JNA}:. TestXcore; ;;
  "ppc") java -classpath ${JNA}:. TestPpc ;;
  "sparc") java -classpath ${JNA}:. TestSparc ;;
  "systemz") java -classpath ${JNA}:. TestSystemz ;;
  * ) echo "Usage: ./run.sh [arm|arm64|mips|ppc|sparc|systemz|x86]"; exit 1;;
esac
