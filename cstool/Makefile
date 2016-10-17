# Makefile for Cstool of Capstone Disassembly Engine

include ../functions.mk

.PHONY: clean

LIBNAME = capstone

CFLAGS = -I../include
LDFLAGS = -O3 -Wall -L.. -l$(LIBNAME)

cstool: cstool.o
ifeq ($(V),0)
	$(call log,LINK,$@)
	@${CC} $< $(LDFLAGS) -o $@
else
	${CC} $< $(LDFLAGS) -o $@
endif

clean:
	${RM} -rf *.o cstool

%.o: %.c
ifeq ($(V),0)
	$(call log,CC,$@)
	@${CC} $(CFLAGS) -c $< -o $@
else
	${CC} $(CFLAGS) -c $< -o $@
endif
