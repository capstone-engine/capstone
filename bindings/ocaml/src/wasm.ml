(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type wasm_op_brtable = {
	length: int;
	address: int;
	default_target: int
}

type wasm_op_value =
	| WASM_OP_INVALID of int
	| WASM_OP_NONE
	| WASM_OP_INT7 of int
	| WASM_OP_VARUINT32 of int
	| WASM_OP_VARUINT64 of int
	| WASM_OP_UINT32 of int
	| WASM_OP_UINT64 of int
	| WASM_OP_IMM of int
	| WASM_OP_BRTABLE of wasm_op_brtable

type wasm_op = {
	value: wasm_op_value;
}

type cs_wasm = {
	operands: wasm_op array;
}
