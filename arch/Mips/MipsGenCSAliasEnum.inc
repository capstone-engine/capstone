/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

	MIPS_INS_ALIAS_MOVE, // Real instr.: MIPS_OR
	MIPS_INS_ALIAS_BAL, // Real instr.: MIPS_BGEZAL
	MIPS_INS_ALIAS_JALR_HB, // Real instr.: MIPS_JALR_HB
	MIPS_INS_ALIAS_NEG, // Real instr.: MIPS_SUB
	MIPS_INS_ALIAS_NEGU, // Real instr.: MIPS_SUBu
	MIPS_INS_ALIAS_NOP, // Real instr.: MIPS_SLL
	MIPS_INS_ALIAS_BNEZL, // Real instr.: MIPS_BNEL
	MIPS_INS_ALIAS_BEQZL, // Real instr.: MIPS_BEQL
	MIPS_INS_ALIAS_SYSCALL, // Real instr.: MIPS_SYSCALL
	MIPS_INS_ALIAS_BREAK, // Real instr.: MIPS_BREAK
	MIPS_INS_ALIAS_EI, // Real instr.: MIPS_EI
	MIPS_INS_ALIAS_DI, // Real instr.: MIPS_DI
	MIPS_INS_ALIAS_TEQ, // Real instr.: MIPS_TEQ
	MIPS_INS_ALIAS_TGE, // Real instr.: MIPS_TGE
	MIPS_INS_ALIAS_TGEU, // Real instr.: MIPS_TGEU
	MIPS_INS_ALIAS_TLT, // Real instr.: MIPS_TLT
	MIPS_INS_ALIAS_TLTU, // Real instr.: MIPS_TLTU
	MIPS_INS_ALIAS_TNE, // Real instr.: MIPS_TNE
	MIPS_INS_ALIAS_RDHWR, // Real instr.: MIPS_RDHWR
	MIPS_INS_ALIAS_SDBBP, // Real instr.: MIPS_SDBBP
	MIPS_INS_ALIAS_SYNC, // Real instr.: MIPS_SYNC
	MIPS_INS_ALIAS_HYPCALL, // Real instr.: MIPS_HYPCALL
	MIPS_INS_ALIAS_NOR, // Real instr.: MIPS_NORImm
	MIPS_INS_ALIAS_C_F_S, // Real instr.: MIPS_C_F_S
	MIPS_INS_ALIAS_C_UN_S, // Real instr.: MIPS_C_UN_S
	MIPS_INS_ALIAS_C_EQ_S, // Real instr.: MIPS_C_EQ_S
	MIPS_INS_ALIAS_C_UEQ_S, // Real instr.: MIPS_C_UEQ_S
	MIPS_INS_ALIAS_C_OLT_S, // Real instr.: MIPS_C_OLT_S
	MIPS_INS_ALIAS_C_ULT_S, // Real instr.: MIPS_C_ULT_S
	MIPS_INS_ALIAS_C_OLE_S, // Real instr.: MIPS_C_OLE_S
	MIPS_INS_ALIAS_C_ULE_S, // Real instr.: MIPS_C_ULE_S
	MIPS_INS_ALIAS_C_SF_S, // Real instr.: MIPS_C_SF_S
	MIPS_INS_ALIAS_C_NGLE_S, // Real instr.: MIPS_C_NGLE_S
	MIPS_INS_ALIAS_C_SEQ_S, // Real instr.: MIPS_C_SEQ_S
	MIPS_INS_ALIAS_C_NGL_S, // Real instr.: MIPS_C_NGL_S
	MIPS_INS_ALIAS_C_LT_S, // Real instr.: MIPS_C_LT_S
	MIPS_INS_ALIAS_C_NGE_S, // Real instr.: MIPS_C_NGE_S
	MIPS_INS_ALIAS_C_LE_S, // Real instr.: MIPS_C_LE_S
	MIPS_INS_ALIAS_C_NGT_S, // Real instr.: MIPS_C_NGT_S
	MIPS_INS_ALIAS_BC1T, // Real instr.: MIPS_BC1T
	MIPS_INS_ALIAS_BC1F, // Real instr.: MIPS_BC1F
	MIPS_INS_ALIAS_C_F_D, // Real instr.: MIPS_C_F_D32
	MIPS_INS_ALIAS_C_UN_D, // Real instr.: MIPS_C_UN_D32
	MIPS_INS_ALIAS_C_EQ_D, // Real instr.: MIPS_C_EQ_D32
	MIPS_INS_ALIAS_C_UEQ_D, // Real instr.: MIPS_C_UEQ_D32
	MIPS_INS_ALIAS_C_OLT_D, // Real instr.: MIPS_C_OLT_D32
	MIPS_INS_ALIAS_C_ULT_D, // Real instr.: MIPS_C_ULT_D32
	MIPS_INS_ALIAS_C_OLE_D, // Real instr.: MIPS_C_OLE_D32
	MIPS_INS_ALIAS_C_ULE_D, // Real instr.: MIPS_C_ULE_D32
	MIPS_INS_ALIAS_C_SF_D, // Real instr.: MIPS_C_SF_D32
	MIPS_INS_ALIAS_C_NGLE_D, // Real instr.: MIPS_C_NGLE_D32
	MIPS_INS_ALIAS_C_SEQ_D, // Real instr.: MIPS_C_SEQ_D32
	MIPS_INS_ALIAS_C_NGL_D, // Real instr.: MIPS_C_NGL_D32
	MIPS_INS_ALIAS_C_LT_D, // Real instr.: MIPS_C_LT_D32
	MIPS_INS_ALIAS_C_NGE_D, // Real instr.: MIPS_C_NGE_D32
	MIPS_INS_ALIAS_C_LE_D, // Real instr.: MIPS_C_LE_D32
	MIPS_INS_ALIAS_C_NGT_D, // Real instr.: MIPS_C_NGT_D32
	MIPS_INS_ALIAS_BC1TL, // Real instr.: MIPS_BC1TL
	MIPS_INS_ALIAS_BC1FL, // Real instr.: MIPS_BC1FL
	MIPS_INS_ALIAS_DNEG, // Real instr.: MIPS_DSUB
	MIPS_INS_ALIAS_DNEGU, // Real instr.: MIPS_DSUBu
	MIPS_INS_ALIAS_SLT, // Real instr.: MIPS_SLTImm64
	MIPS_INS_ALIAS_SLTU, // Real instr.: MIPS_SLTUImm64
	MIPS_INS_ALIAS_SIGRIE, // Real instr.: MIPS_SIGRIE
	MIPS_INS_ALIAS_JR, // Real instr.: MIPS_JALR
	MIPS_INS_ALIAS_JRC, // Real instr.: MIPS_JIC
	MIPS_INS_ALIAS_JALRC, // Real instr.: MIPS_JIALC
	MIPS_INS_ALIAS_DIV, // Real instr.: MIPS_DIV
	MIPS_INS_ALIAS_DIVU, // Real instr.: MIPS_DIVU
	MIPS_INS_ALIAS_LAPC, // Real instr.: MIPS_ADDIUPC
	MIPS_INS_ALIAS_WRDSP, // Real instr.: MIPS_WRDSP
	MIPS_INS_ALIAS_DMT, // Real instr.: MIPS_DMT
	MIPS_INS_ALIAS_EMT, // Real instr.: MIPS_EMT
	MIPS_INS_ALIAS_DVPE, // Real instr.: MIPS_DVPE
	MIPS_INS_ALIAS_EVPE, // Real instr.: MIPS_EVPE
	MIPS_INS_ALIAS_YIELD, // Real instr.: MIPS_YIELD
	MIPS_INS_ALIAS_MFTC0, // Real instr.: MIPS_MFTC0
	MIPS_INS_ALIAS_MFTLO, // Real instr.: MIPS_MFTLO
	MIPS_INS_ALIAS_MFTHI, // Real instr.: MIPS_MFTHI
	MIPS_INS_ALIAS_MFTACX, // Real instr.: MIPS_MFTACX
	MIPS_INS_ALIAS_MTTC0, // Real instr.: MIPS_MTTC0
	MIPS_INS_ALIAS_MTTLO, // Real instr.: MIPS_MTTLO
	MIPS_INS_ALIAS_MTTHI, // Real instr.: MIPS_MTTHI
	MIPS_INS_ALIAS_MTTACX, // Real instr.: MIPS_MTTACX
	MIPS_INS_ALIAS_WAIT, // Real instr.: MIPS_WAIT_MM
	MIPS_INS_ALIAS_SW, // Real instr.: MIPS_SWSP_MM
	MIPS_INS_ALIAS_JALRC_HB, // Real instr.: MIPS_JALRC_HB_MMR6
