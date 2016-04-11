#!/bin/sh

maven_out=$(mvn clean package -f capstone/pom.xml | tee /dev/tty)

if  [[ "$maven_out" == *"[INFO] BUILD SUCCESS"* ]] ; then 
	# search for JAR file
	#ls -ltr | grep "capstone-[[:digit:]]\.[[:digit:]]\.[[:digit:]]\(-SNAPSHOT\)\{0,1\}\.jar"
	exit 0
else 
	exit 1
fi