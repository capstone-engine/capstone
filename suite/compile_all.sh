#! /bin/bash
# By Daniel Godas-Lopez.

export LD_LIBRARY_PATH=.

for x in default nix32 cross-win32 cross-win64 cygwin-mingw32 cygwin-mingw64 bsd clang gcc; do
	echo -n "Compiling: $x ... "
	./compile.sh $x &> /dev/null

	if [ $? == 0 ]; then
		echo "-> PASS"
	else
		echo -e "-> FAILED\n"
		continue
	fi

	for t in test test_arm test_arm64 test_detail test_mips test_x86 test_ppc; do
		./tests/$t &> /dev/null

		if [ $? -eq 0 ]; then
			echo "  Run $t -> PASS"
		else
			echo "  Run $t -> FAIL"
		fi
	done

	echo
done

make clean &> /dev/null
