# Makefile for Cstool of Capstone Disassembly Engine

include ../functions.mk

.PHONY: clean all

LIBNAME = capstone

CFLAGS = -I../include
LDFLAGS = -O3 -Wall -L.. -l$(LIBNAME)

TARGET = cstool
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
ifeq ($(V),0)
	$(call log,LINK,$@)
	@${CC} $(OBJECTS) $(LDFLAGS) -o $@
else
	${CC} $(OBJECTS) $(LDFLAGS) -o $@
endif

clean:
	${RM} -rf *.o $(TARGET)

%.o: %.c
ifeq ($(V),0)
	$(call log,CC,$@)
	@${CC} $(CFLAGS) -c $< -o $@
else
	${CC} $(CFLAGS) -c $< -o $@
endif
