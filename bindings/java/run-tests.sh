#!/bin/sh

maven_out=$(mvn clean test -f capstone/pom.xml | tee /dev/tty)

case "$maven_out" in
	*"[INFO] BUILD SUCCESS"*)
		echo "Success"
		exit 0
		;;
	*)
		echo "Failed"
		exit 1
		;;
esac