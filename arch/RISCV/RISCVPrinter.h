#ifndef __RISCV_PRINTER__H_
#define __RISCV_PRINTER__H_

#include "../../cs_priv.h"

//#include "riscv_ast2str.gen.inc" FIXME: uncomment when printer is implemented

void riscv_printer(MCInst *MI, SStream *OS, void *info);

#endif