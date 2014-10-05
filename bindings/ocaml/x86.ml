(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

open X86_const

(* architecture specific info of instruction *)
type x86_op_mem = {
	segment: int;
	base: int;
	index: int;
	scale: int;
	disp: int;
}

type x86_op_value =
	| X86_OP_INVALID of int
	| X86_OP_REG of int
	| X86_OP_IMM of int
	| X86_OP_FP of float
	| X86_OP_MEM of x86_op_mem

type x86_op = {
	value: x86_op_value;
	size: int;
	avx_bcast: int;
	avx_zero_opmask: int;
}

type cs_x86 = { 
	prefix: int array;
	opcode: int array;
	rex: int;
	addr_size: int;
	modrm: int;
	sib: int;
	disp: int;
	sib_index: int;
	sib_scale: int;
	sib_base: int;
	sse_cc: int;
	avx_cc: int;
	avx_sae: int;
	avx_rm: int;
	operands: x86_op array;
}
