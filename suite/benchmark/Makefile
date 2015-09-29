# Sample Makefile for Capstone Disassembly Engine

LIBNAME = capstone

test_iter_benchmark: test_iter_benchmark.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c -I../../include $< -o $@

clean:
	rm -rf *.o test_iter_benchmark
