# Sample Makefile for Capstone Disassembly Engine

LIBNAME = capstone

test_arm_regression: test_arm_regression.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c -I../../include $< -o $@

clean:
	rm -rf *.o test_arm_regression
