SRC = $(wildcard src/*.c)
OBJ = $(SRC:src/%.c=src/%.o)

CFLAGS += -I include -I ../../include
LBLIBS += -lcmocka -lcapstone
EXE = cstest

.PHONY = all clean

all: $(EXE)
$(EXE): $(OBJ)
src/%.o: src/%.c
check: $(EXE)
	cstest -d ../MC	
clean:
	rm -rf $(EXE)
