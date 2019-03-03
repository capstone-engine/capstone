CC=gcc
ODIR=obj
TBL_GEN=tbl_gen
INC_FILE=../../arch/M68K/M68KInstructionTable.inc

gen_inc: $(TBL_GEN)
	./$(TBL_GEN) > $(INC_FILE)

tbl_gen: M68KInstructionTblGen.c
	$(CC) -O3 M68KInstructionTblGen.c -o $(TBL_GEN)

.PHONY: clean

clean:
	rm $(TBL_GEN)
