#ifndef __ARCH_H__
#define __ARCH_H__

#define MAX_ARCH 32

void (*init_arch[MAX_ARCH]) (cs_struct *);
cs_err (*option_arch[MAX_ARCH]) (cs_struct*, cs_opt_type, size_t value);

#ifdef CS_SUPPORT_X86
#include "arch/X86/include.h"
#endif
#ifdef CS_SUPPORT_ARM
#include "arch/ARM/include.h"
#endif
#ifdef CS_SUPPORT_AARCH64
#include "arch/AArch64/include.h"
#endif
#ifdef CS_SUPPORT_MIPS
#include "arch/Mips/include.h"
#endif

#endif
