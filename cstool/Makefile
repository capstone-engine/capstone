# Sample Makefile for Capstone Disassembly Engine

include ../functions.mk

.PHONY: clean

LIBNAME = capstone

cstool: cstool.o
ifeq ($(V),0)
	$(call log,LINK,$@)
	@${CC} $< -O3 -Wall -L.. -l$(LIBNAME) -o $@
else
	${CC} $< -O3 -Wall -L.. -l$(LIBNAME) -o $@
endif

clean:
	${RM} -rf *.o cstool

%.o: %.c
ifeq ($(V),0)
	$(call log,CC,$@)
	@$(compile)
else
	$(compile)
endif
