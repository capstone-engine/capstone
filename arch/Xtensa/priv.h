#ifndef CAPSTONE_PRIV_H
#define CAPSTONE_PRIV_H

#define report_fatal_error(x) assert(0 && x)
#define llvm_unreachable(x) assert(0 && x)
#define MCRegister unsigned
#define MCExpr void
#define MCOperand_getExpr(MC) assert(0 && "unimplemented expr")
#define printExpr(E, O) assert(0 && "unimplemented expr")

#define GET_REGINFO_ENUM
#include "XtensaGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "XtensaGenInstrInfo.inc"

#endif //CAPSTONE_PRIV_H
