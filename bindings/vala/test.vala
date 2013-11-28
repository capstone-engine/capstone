/* Vala/Capstone Example -- pancake <pancake@nopcode.org> */

using Capstone;

void main() {
	Insn* insn;
	uint64 handle;

	if (Capstone.open (Capstone.ARCH.X86,
			Capstone.MODE.B32, out handle) != 0) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	int n = Capstone.disasm_dyn (handle, 
		"\xc5\xf1\x6c\xc0\x90\xcc",
		6, 0x8048000, 0, out insn);
	if (n == 0) {
		stderr.printf ("invalid\n");
	} else
	if (n>0) {
		for (int i = 0; i<n; i++) {
			var op = &insn[i];
			stdout.printf ("%s %s\n", op.mnemonic, op.op_str);
		}
	}
	Capstone.close (handle);
}
