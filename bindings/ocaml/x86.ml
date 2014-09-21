(* Capstone Disassembler Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open X86_const

(* architecture specific info of instruction *)
type x86_op_mem = {
	base: int;
	index: int;
	scale: int;
	displ: int;
}

type x86_op = 
	| X86_OP_INVALID of int
	| X86_OP_REG of int
	| X86_OP_IMM of int
	| X86_OP_FP of float
	| X86_OP_MEM of x86_op_mem

type cs_x86 = { 
	prefix: int array;
	segment: int;
	opcode: int array;
	op_size: int;
	addr_size: int;
	disp_size: int;
	imm_size: int;
	modrm: int;
	sib: int;
	disp: int;
	sib_index: int;
	sib_scale: int;
	sib_base: int;
	op_count: int;
	operands: x86_op array;
}
