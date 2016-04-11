#!/bin/sh

maven_out=$(mvn clean test -f capstone/pom.xml | tee /dev/tty)

if  [[ "$maven_out" == *"[INFO] BUILD SUCCESS"* ]] ; then 
	exit 0
else 
	exit 1
fi