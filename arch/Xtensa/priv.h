/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#ifndef CAPSTONE_PRIV_H
#define CAPSTONE_PRIV_H

#define llvm_unreachable(x) assert(0 && x)
#define printExpr(E, O) assert(0 && "unimplemented expr")
#define MCExpr_print(E, OS, MAI, InParens) assert(0 && "unimplemented expr")

#define GET_REGINFO_ENUM
#include "XtensaGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "XtensaGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "XtensaGenSubtargetInfo.inc"

#endif //CAPSTONE_PRIV_H
