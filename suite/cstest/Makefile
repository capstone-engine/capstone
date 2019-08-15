SRC = $(wildcard src/*.c)
OBJ = $(SRC:src/%.c=src/%.o)

CFLAGS += -I include -I ../../include -L ../../
LDLIBS += -lcmocka -lcapstone
EXE = cstest

ENV_VARS = LD_LIBRARY_PATH=../../ DYLD_LIBRARY_PATH=../../ LIBCAPSTONE_PATH=../../

.PHONY = all clean

all: $(EXE)
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
src/%.o: src/%.c
check: $(EXE)
	$(ENV_VARS) ./cstest -d ../MC
clean:
	rm -rf $(EXE)
