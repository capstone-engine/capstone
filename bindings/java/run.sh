#!/bin/sh
JNA=/usr/share/java/jna.jar

if [ ! -f ${JNA} ]; then
  echo "JNA @ ${JNA} does not exist, edit this file with the correct path";
  exit
fi

case "$1" in
  "") java -classpath ${JNA}:. Test ;;
  "arm") java -classpath ${JNA}:. TestArm ;;
  "arm64") java -classpath ${JNA}:. TestArm64 ;;
  "mips") java -classpath ${JNA}:. TestMips ;;
  "x86") java -classpath ${JNA}:. TestX86 ;;
  * ) echo "Usage: ./run.sh [arm]"; exit 1;;
esac
