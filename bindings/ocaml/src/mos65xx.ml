(* Capstone Disassembly Engine
 * By Anton Kochkov <anton.kochkov@gmail.com>, 2024 *)

(* architecture specific info of instruction *)

type mos65xx_op_value =
	| MOS65XX_OP_INVALID of int
	| MOS65XX_OP_REG of int
	| MOS65XX_OP_IMM of int
	| MOS65XX_OP_MEM of int

type mos65xx_op = {
	value: mos65xx_op_value;
}

type cs_mos65xx = {
	operands: mos65xx_op array;
	am: int;
	modifies_flags: bool;
}
