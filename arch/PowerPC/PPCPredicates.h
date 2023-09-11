/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically translated source file from LLVM. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Only small edits allowed. */
/* For multiple similar edits, please create a Patch for the translator. */

/* Capstone's C++ file translator: */
/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

//===-- PPCPredicates.h - PPC Branch Predicate Information ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file describes the PowerPC branch predicates.
//
//===----------------------------------------------------------------------===//

#ifndef CS_PPC_PREDICATES_H
#define CS_PPC_PREDICATES_H

// GCC #defines PPC on Linux but we use it as our namespace name
#include "capstone/ppc.h"
#undef PPC

// Generated files will use "namespace PPC". To avoid symbol clash,
// undefine PPC here. PPC may be predefined on some hosts.
#undef PPC

// Predicates moved to ppc.h
typedef ppc_pred PPC_Predicate;

/// Invert the specified predicate.  != -> ==, < -> >=.
PPC_Predicate InvertPredicate(PPC_Predicate Opcode);
/// Assume the condition register is set by MI(a,b), return the predicate if
/// we modify the instructions such that condition register is set by MI(b,a).
PPC_Predicate getSwappedPredicate(PPC_Predicate Opcode);
/// Return the condition without hint bits.
static inline unsigned PPC_getPredicateCondition(PPC_Predicate Opcode)
{
	return (unsigned)(Opcode & ~PPC_BR_HINT_MASK);
}

/// Return the hint bits of the predicate.
static inline unsigned PPC_getPredicateHint(PPC_Predicate Opcode)
{
	return (unsigned)(Opcode & PPC_BR_HINT_MASK);
}

/// Return predicate consisting of specified condition and hint bits.
static inline PPC_Predicate PPC_getPredicate(unsigned Condition, unsigned Hint)
{
	return (PPC_Predicate)((Condition & ~PPC_BR_HINT_MASK) |
			       (Hint & PPC_BR_HINT_MASK));
}

#endif // CS_PPC_PREDICATES_H
