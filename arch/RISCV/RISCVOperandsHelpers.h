#ifndef __RISCV_OPERANDS_HELPERS_H__
#define __RISCV_OPERANDS_HELPERS_H__

#include "../../include/capstone/capstone.h"
#include "RISCVAst.gen.inc"

#include "RISCVRVContextHelpers.h"

// Those macros are hand-written helpers to transform register values
// to the enum values exposed by the capstone module
// The generated disassembler uses 0..31 indices to refer to all registers of
// any type but the capstone module gives all the register flat sequential enum
// values i.e. enum {<enum values for integer registers>, <enum values for float
// regisers, ...} Therefore, we should map the 0..31 range to a corresponding
// range for each register type

// The simplest values are the integer registers, they are
// 1, 2, 3, ..., 32
// the transformation is a straightforward shift by 1
#define AS_GEN_PURPOSE_REG(r) ((r) + 1)
#define IS_GEN_PURPOSE_REG(r) ((r) <= 32)
#define INDEX_FROM_GEN_PURPOSE_REG(r) ((r) - 1)

// (half-)floats and doubles are more complex
// their enum values come after the values for the general purpose regs,
// but the 3 register types are all interleaved

// half float enum values start at 33 and increment by 3 each time (33, 36, 39,
// ...)
#define AS_HALF_FLOAT_REG(r) ((3 * (r)) + 33)
#define INDEX_FROM_HALF_FLOAT_REG(r) (((r) - 33)/3)

// and float enum values are 34, 37, 40, ...
#define AS_FLOAT_REG(r) ((3 * (r)) + 34)
#define IS_FLOAT_REG(r) ((r) >= 34 && (r) <= 127 && ((r) % 3 == 1))
#define INDEX_FROM_FLOAT_REG(r) (((r) - 34)/3)

// and double enum values are 35, 38, 41, ...
#define AS_DOUBLE_REG(r) ((3 * (r)) + 35)
#define IS_DOUBLE_REG(r) ((r) >= 35 && (r) <= 128 && ((r) % 3 == 2))
#define INDEX_FROM_DOUBLE_REG(r) (((r) - 35)/3)

// vector registers are 129, ..., 160
#define AS_VECTOR_REG(r) ((r) + 129)
#define IS_VECTOR_REG(r) ((r) >= 129)
#define INDEX_FROM_VECTOR_REG(r) ((r) - 129)

#define AS_COMPRESSED_GEN_PURPOSE_REG(r) AS_GEN_PURPOSE_REG((r) + 8)
#define AS_COMPRESSED_FLOAT_REG(r) AS_FLOAT_REG((r) + 8)

#define FLOAT_REG_TO_HALF_FLOAT_REG(r) ((r)-1)
#define FLOAT_REG_TO_DOUBLE_REG(r) ((r) + 1)

// TODO: implement sign and zero extension as in the Sail stdlib
#define ZERO_EXTEND(i) (i)
#define SIGN_EXTEND(i) (i)

// memory operands is harder to infer than register operands due to their
// deceptive apperance as regular immediates (who just happen to get added to
// base registers and result in addresses)
//
// For those instructions, we simply detect the relevant instruction and
// manually fill its operands
// This shouldn't be too hard, as the RISC-V is a riscv architecture that has
// dedicated instructions for accessing memory and it doesn't access memory
// outside of those instructions (unlike, say, x86) Additionally, some registers
// are inferred wrong for some special instructions, we also manually edit those
static inline void patch_operands(struct ast *tree, cs_riscv_op *ops, uint8_t *op_count,
                    RVContext *ctx) {
  switch (tree->ast_node_type) {
  case RISCV_LOADRES: {
    // the read from rs1 is falsely inferred as a register read
    // but it's actually a memory read with displacement 0
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.loadres.rs1);
    ops[0].mem.disp = 0;
    ops[0].access = CS_AC_READ;
    break;
  }
  // same as loadres
  case RISCV_STORECON: {
    ops[1].type = RISCV_OP_MEM;
    ops[1].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.storecon.rs1);
    ops[1].mem.disp = 0;
    ops[1].access = CS_AC_WRITE;
    break;
  }
  // same as loadres
  case RISCV_AMO: {
    ops[1].type = RISCV_OP_MEM;
    ops[1].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.amo.rs1);
    ops[1].mem.disp = 0;
    ops[1].access = CS_AC_READ;
    break;
  }

  // the immediate and rs1 are falsely inferred as an
  // immediate operand and a register acccess
  // correct them to a memory operand
  case RISCV_LOAD: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.load.rs1);
    ops[0].mem.disp = SIGN_EXTEND(tree->ast_node.load.imm);
    ops[0].access = CS_AC_READ;
    // shift the destination operand
    ops[1] = ops[2];
    *op_count = *op_count - 1;
    break;
  }

  case RISCV_STORE: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.store.rs1);
    ops[0].mem.disp = SIGN_EXTEND(tree->ast_node.store.imm);
    ops[0].access = CS_AC_WRITE;
    // no need to shift anything, ops[1] is already the third operand
    // "delete" the false register operand containing rs1
    *op_count = *op_count - 1;
    break;
  }

  case RISCV_LOAD_FP: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.load_fp.rs1);
    ops[0].mem.disp = SIGN_EXTEND(tree->ast_node.load_fp.imm);
    ops[0].access = CS_AC_READ;
    // shift the destination operand
    ops[1] = ops[2];
    *op_count = *op_count - 1;
    break;
  }

  case RISCV_STORE_FP: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_GEN_PURPOSE_REG(tree->ast_node.store_fp.rs1);
    ops[0].mem.disp = SIGN_EXTEND(tree->ast_node.store_fp.imm);
    ops[0].access = CS_AC_WRITE;
    // no need to shift anything, ops[1] is already the third operand
    // "delete" the false register operand containing rs1
    *op_count = *op_count - 1;
    break;
  }

  // TODO: figure out a more detailed way of representing this instructions' addressing mode
  case RISCV_ZICBOZ:
  case RISCV_ZICBOM: 
  case RISCV_VLSEGTYPE:
  case RISCV_VLSEGFFTYPE:
  case RISCV_VSSEGTYPE:
  case RISCV_VLSSEGTYPE:
  case RISCV_VSSSEGTYPE:
  case RISCV_VLUXSEGTYPE:
  case RISCV_VLOXSEGTYPE:
  case RISCV_VSUXSEGTYPE:
  case RISCV_VLRETYPE:
  case RISCV_VSRETYPE:
  case RISCV_VMTYPE: {
    // for now we just give up and say that the offset is unknown, 
    // but it's possible to write parameters for a symbolic formula for each instruction type 
    // (for example if an instructions performs memory accesses according to the formula a*X+b, we could
    // a, b, and the lower and upper bounds for X are assembly-time parameters that could be extracted)
    for (uint32_t i = 0; i < *op_count; i++) {
      if (ops[i].type == RISCV_OP_MEM) {
        ops[i].mem.type = RISCV_OP_MEM_RUNTIME;
      }
    }
    break;
  }

  default: break;
  }

  // fix up special compressed instructions, which are assumed by the generator
  // to always reference integer registers
  // this assumption is mostly true, but few reference FP registers,
  // and some also have memory operands
  uint8_t sp = AS_GEN_PURPOSE_REG(2); // sp register
  switch (tree->ast_node_type) {
  // short synonym for a LOAD_FP with base sp
  case RISCV_C_FLDSP: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = sp;
    ops[0].mem.disp = SIGN_EXTEND(ZERO_EXTEND(tree->ast_node.c_fldsp.uimm << 3));
    ops[0].access = CS_AC_READ;
    break;
  }
  // short synonym for a STORE_FP with base sp
  case RISCV_C_FSDSP: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = sp;
    ops[0].mem.disp = SIGN_EXTEND(ZERO_EXTEND(tree->ast_node.c_fsdsp.uimm << 3));
    ops[0].access = CS_AC_WRITE;
    break;
  }

  // short synonyms for arbitrary loads and stores
  case RISCV_C_FLD: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_COMPRESSED_GEN_PURPOSE_REG(tree->ast_node.c_fld.rsc);
    ops[0].mem.disp = SIGN_EXTEND(ZERO_EXTEND(tree->ast_node.c_fld.uimm << 3));
    ops[0].access = CS_AC_READ;
    ops[1] = ops[2];
    ops[1].reg = AS_COMPRESSED_FLOAT_REG(tree->ast_node.c_fld.rdc);
    *op_count = *op_count - 1;
    break;
  }

  case RISCV_C_FSD: {
    ops[0].type = RISCV_OP_MEM;
    ops[0].mem.base = AS_COMPRESSED_GEN_PURPOSE_REG(tree->ast_node.c_fsd.rsc1);
    ops[0].mem.disp = SIGN_EXTEND(ZERO_EXTEND(tree->ast_node.c_fsd.uimm << 3));
    ops[0].access = CS_AC_WRITE;
    ops[1] = ops[2];
    ops[1].reg = AS_COMPRESSED_FLOAT_REG(tree->ast_node.c_fsd.rsc2);
    *op_count = *op_count - 1;
    break;
  }
  default: break;
  }

  // determine if the instruction has float operands but the FP width is 16 bits
  // or 64 bits, in which case the FP register is patched up to the double or
  // half-float equivalent
  if (ctx->flen == 16 || ctx->flen == 64) {
    for (uint32_t i = 0; i < *op_count; i++) {
      if (ops[i].type == RISCV_OP_REG && IS_FLOAT_REG(ops[i].reg)) {
        ops[i].reg = (ctx->flen == 16) ? FLOAT_REG_TO_HALF_FLOAT_REG(ops[i].reg)
                                       : FLOAT_REG_TO_DOUBLE_REG(ops[i].reg);
      }
    }
  }
}

#endif