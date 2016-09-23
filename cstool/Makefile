# Sample Makefile for Capstone Disassembly Engine

LIBNAME = capstone

cstool: cstool.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
