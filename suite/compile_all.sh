#! /bin/bash
# By Daniel Godas-Lopez.

export LD_LIBRARY_PATH=.

for x in nix32 clang cross-win32 cross-win64 cygwin-mingw32 cygwin-mingw64; do
	./compile.sh $x &> /dev/null

	if [ $? == 0 ]; then
		echo "$x -> compiled"
	else
		echo -e "$x -> failed to compile\n"
		continue
	fi

	for t in test test_arm test_arm64 test_detail test_mips test_x86; do
		./tests/$t &> /dev/null

		if [ $? -eq 0 ]; then
			echo "  $t -> PASS"
		else
			echo "  $t -> FAIL"
		fi
	done

	echo
done

make clean &> /dev/null
