all:

x86:
	# compile disassembler2 with X86GenDisassemblerTables2.inc
	$(CC) disassemblertables2.c -o disassemblertables2

	# compile disassembler2 with X86GenDisassemblerTables_reduce2.inc
	$(CC) -DCAPSTONE_X86_REDUCE disassemblertables2.c -o disassemblertables_reduce2

arm64:
	$(CC) arm64_gen_vreg.c -o arm64_gen_vreg

clean:
	$(RM) disassemblertables2 disassemblertables_reduce2 arm64_gen_vreg
