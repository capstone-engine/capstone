# Sample Makefile for Capstone Disassembly Engine

LIBNAME = ../../build/libcapstone.a

all: test_iter_benchmark test_file_benchmark

test_iter_benchmark: test_iter_benchmark.c
	${CC} $< -O3 -Wall -o $@ -I../../include $(LIBNAME)

test_file_benchmark: test_file_benchmark.c
	${CC} $< -O3 -Wall -o $@ -I../../include $(LIBNAME)

# %.o: %.c
# 	${CC} -c  $< -o $@

clean:
	rm -rf *.o test_iter_benchmark test_file_benchmark
