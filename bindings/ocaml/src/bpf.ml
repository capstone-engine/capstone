(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024> *)

type bpf_op_mem = {
	base: int;
	disp: int;
}

type bpf_op_value = 
	| BPF_OP_INVALID of int
	| BPF_OP_REG of int
	| BPF_OP_IMM of int
	| BPF_OP_OFF of int
	| BPF_OP_MEM of bpf_op_mem
	| BPF_OP_MMEM of int
	| BPF_OP_MSH of int
	| BPF_OP_EXT of int

type bpf_op = {
	value: bpf_op_value;
	is_signed: bool;
	is_pkt: bool;
	access: int;
}

type cs_bpf = { 
	operands: bpf_op array;
}
