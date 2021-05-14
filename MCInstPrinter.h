//
// Created by Phosphorus15 on 2021/5/14.
//

#ifndef CAPSTONE_MCINSTPRINTER_H
#define CAPSTONE_MCINSTPRINTER_H

#include "MCInst.h"
#include "capstone/platform.h"
#include "stdlib.h"

typedef enum CondKind {
  AliasPatternCond_K_Feature,	    // Match only if a feature is enabled.
  AliasPatternCond_K_NegFeature,    // Match only if a feature is disabled.
  AliasPatternCond_K_OrFeature,	    // Match only if one of a set of features is
				    // enabled.
  AliasPatternCond_K_OrNegFeature,  // Match only if one of a set of features is
				    // disabled.
  AliasPatternCond_K_EndOrFeatures, // Note end of list of K_Or(Neg)?Features.
  AliasPatternCond_K_Ignore,	    // Match any operand.
  AliasPatternCond_K_Reg,	    // Match a specific register.
  AliasPatternCond_K_TiedReg,	    // Match another already matched register.
  AliasPatternCond_K_Imm,	    // Match a specific immediate.
  AliasPatternCond_K_RegClass,	    // Match registers in a class.
  AliasPatternCond_K_Custom,	    // Call custom matcher by index.
} CondKind;

typedef struct PatternsForOpcode {
  uint32_t Opcode;
  uint16_t PatternStart;
  uint16_t NumPatterns;
} PatternsForOpcode;

typedef struct AliasPattern {
  uint32_t AsmStrOffset;
  uint32_t AliasCondStart;
  uint8_t NumOperands;
  uint8_t NumConds;
} AliasPattern;

typedef struct AliasPatternCond {
  CondKind Kind;
  uint32_t Value;
} AliasPatternCond;

static int cmp_less(const void *l, const void *r)
{
  return ((signed)((const PatternsForOpcode *)l)->Opcode) -
	 ((signed)((const PatternsForOpcode *)r)->Opcode);
}

// Binary Search Implementation - let's use bsearch for now
static PatternsForOpcode *Binary_Search(const PatternsForOpcode *OpToPatterns,
					const unsigned opcode, unsigned len)
{
  return bsearch((void *)&opcode, (void *)OpToPatterns, len,
		 sizeof(PatternsForOpcode), cmp_less);
}

// TODO I'm not sure if this is complete, refer to lib/MC/MCInstPrinter.cpp in
// llvm-project
static bool MCInstPrinter_matchAliasCondition(
    const MCInst *MI, unsigned *OpIdx, const PatternsForOpcode *OpToPatterns,
    const AliasPattern *Patterns, const AliasPatternCond *Conds,
    const AliasPatternCond *Cond, bool *OrPredicateResult);

const char *MCInstPrinter_matchAliasPatterns(
    const MCInst *MI, const PatternsForOpcode *OpToPatterns,
    const AliasPattern *Patterns, const AliasPatternCond *Conds,
    const char *AsmStrings[], unsigned len);

#endif // CAPSTONE_MCINSTPRINTER_H
