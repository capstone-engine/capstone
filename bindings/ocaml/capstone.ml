(* Capstone Disassembler Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> *)

open Arm
open Arm64
open Mips
open X86
open Printf	(* debug *)

type arch =
  | CS_ARCH_ARM
  | CS_ARCH_ARM64
  | CS_ARCH_MIPS
  | CS_ARCH_X86

type mode =
  |	CS_MODE_LITTLE_ENDIAN	(* little-endian mode (default mode) *)
  |	CS_MODE_SYNTAX_INTEL	(* Intel X86 asm syntax (default for CS_ARCH_X86) *)
  |	CS_MODE_ARM			(* ARM mode *)
  |	CS_MODE_16			(* 16-bit mode (for X86, Mips) *)
  |	CS_MODE_32			(* 32-bit mode (for X86, Mips) *)
  |	CS_MODE_64			(* 64-bit mode (for X86, Mips) *)
  |	CS_MODE_THUMB		(* ARM's Thumb mode, including Thumb-2 *)
  |	CS_MODE_MICRO		(* MicroMips mode (MIPS architecture) *)
  |	CS_MODE_N64			(* Nintendo-64 mode (MIPS architecture) *)
  |	CS_MODE_SYNTAX_ATT	(* X86 ATT asm syntax (for CS_ARCH_X86 only) *)
  |	CS_MODE_BIG_ENDIAN	(* big-endian mode *)

type cs_arch = 
	| CS_INFO_ARM of cs_arm
	| CS_INFO_ARM64 of cs_arm64
	| CS_INFO_MIPS of cs_mips
	| CS_INFO_X86 of cs_x86

type cs_insn0 = {
	id: int;
	address: int;
	size: int;
	mnemonic: string;
	op_str: string;
	regs_read: int array;
	regs_write: int array;
	groups: int array;
	arch: cs_arch;
}

external cs_open: arch -> mode list -> Int64.t option = "ocaml_cs_open"
external cs_disasm_quick: arch -> mode list -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm_quick"
external cs_disasm_dyn: arch -> Int64.t -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm_dyn"
external cs_reg_name: arch -> int -> string = "cs_register_name"
external cs_insn_name: Int64.t -> int -> string = "cs_instruction_name"

class cs_insn c a =
	let csh = c in
	let (id, address, size, mnemonic, op_str, regs_read, regs_write, groups, arch) =
	(a.id, a.address, a.size, a.mnemonic, a.op_str, a.regs_read, a.regs_write,
		a.groups, a.arch) in
	object
		method id = id;
		method address = address;
		method size = size;
		method mnemonic = mnemonic;
		method op_str = op_str;
		method regs_read = regs_read;
		method regs_write = regs_write;
		method groups = groups;
		method arch = arch;
		method insn_name = cs_insn_name csh id;
	end;;

let cs_insn_group handle insn group_id =
	List.exists (fun g -> g == group_id) (Array.to_list insn.groups);;

let cs_reg_read handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_read);;

let cs_reg_write handle insn reg_id =
	List.exists (fun g -> g == reg_id) (Array.to_list insn.regs_write);;


class cs a m =
	let mode = m and arch = a in
	let csh = cs_open arch mode in
	object
		method disasm code offset count =
			match csh with
			| None -> [];
			| Some v ->
			let insns = (cs_disasm_dyn arch v code offset count) in
			List.map (fun x -> new cs_insn v x) insns;

	end;;

