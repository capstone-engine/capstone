SRC = $(wildcard src/*.c)
OBJ = $(SRC:src/%.c=src/%.o)

CFLAGS += -I include -I ../../include -L ../../
LDLIBS += -lcmocka -lcapstone
EXE = $(EXE_DIR)/cstest
EXE_DIR = build

ENV_VARS = LD_LIBRARY_PATH=../../ DYLD_LIBRARY_PATH=../../ LIBCAPSTONE_PATH=../../

.PHONY = all dir clean

all: dir $(EXE)
dir:
	mkdir -p $(EXE_DIR)
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
src/%.o: src/%.c
check: all
	$(ENV_VARS) ./cstest -d ../MC
clean:
	rm -rf $(EXE)
