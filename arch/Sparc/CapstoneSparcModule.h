//
// Created by Phosphorus15 on 2021/7/13.
//

#ifndef CAPSTONE_CAPSTONESPARCMODULE_H
#define CAPSTONE_CAPSTONESPARCMODULE_H

static void llvm_unreachable(const char *info) {}

static void assert(int val) {}

static DecodeStatus DecodeLoadInt(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadIntPair(MCInst *Inst, unsigned insn,
                                      uint64_t Address,
                                      MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadDFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadQFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadCP(MCInst *Inst, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadCPPair(MCInst *Inst, unsigned insn,
                                     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreInt(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreIntPair(MCInst *Inst, unsigned insn,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreDFP(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreQFP(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreCP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder);

static DecodeStatus DecodeStoreCPPair(MCInst *Inst, unsigned insn,
                                      uint64_t Address,
                                      MCRegisterInfo *Decoder);

static DecodeStatus DecodeCall(MCInst *Inst, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeSIMM13(MCInst *Inst, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeJMPL(MCInst *Inst, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeReturn(MCInst *MI, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeSWAP(MCInst *Inst, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeTRAP(MCInst *Inst, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeIntRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeI64RegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus DecodeDFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeFCCRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeASRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) ;

static DecodeStatus DecodePRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus DecodeQFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#define GET_REGINFO_MC_DESC

#include "SparcGenDisassemblerTables.inc"

FieldFromInstruction(fieldFromInstruction_4, uint32_t)

DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)

DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4,
                  decodeToMCInst, uint32_t)

static const unsigned IntRegDecoderTable[] = {
        SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7,
        SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7,
        SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7,
        SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7};

static const unsigned FPRegDecoderTable[] = {
        SP_F0, SP_F1, SP_F2, SP_F3, SP_F4, SP_F5, SP_F6, SP_F7,
        SP_F8, SP_F9, SP_F10, SP_F11, SP_F12, SP_F13, SP_F14, SP_F15,
        SP_F16, SP_F17, SP_F18, SP_F19, SP_F20, SP_F21, SP_F22, SP_F23,
        SP_F24, SP_F25, SP_F26, SP_F27, SP_F28, SP_F29, SP_F30, SP_F31};

static const unsigned DFPRegDecoderTable[] = {
        SP_D0, SP_D16, SP_D1, SP_D17, SP_D2, SP_D18, SP_D3, SP_D19,
        SP_D4, SP_D20, SP_D5, SP_D21, SP_D6, SP_D22, SP_D7, SP_D23,
        SP_D8, SP_D24, SP_D9, SP_D25, SP_D10, SP_D26, SP_D11, SP_D27,
        SP_D12, SP_D28, SP_D13, SP_D29, SP_D14, SP_D30, SP_D15, SP_D31};

static const unsigned QFPRegDecoderTable[] = {
        SP_Q0, SP_Q8, ~0U, ~0U, SP_Q1, SP_Q9, ~0U, ~0U, SP_Q2, SP_Q10, ~0U, ~0U,
        SP_Q3, SP_Q11, ~0U, ~0U, SP_Q4, SP_Q12, ~0U, ~0U, SP_Q5, SP_Q13, ~0U, ~0U,
        SP_Q6, SP_Q14, ~0U, ~0U, SP_Q7, SP_Q15, ~0U, ~0U};

static const unsigned FCCRegDecoderTable[] = {SP_FCC0, SP_FCC1, SP_FCC2,
                                              SP_FCC3};

static const unsigned ASRRegDecoderTable[] = {
        SP_Y, SP_ASR1, SP_ASR2, SP_ASR3, SP_ASR4, SP_ASR5, SP_ASR6,
        SP_ASR7, SP_ASR8, SP_ASR9, SP_ASR10, SP_ASR11, SP_ASR12, SP_ASR13,
        SP_ASR14, SP_ASR15, SP_ASR16, SP_ASR17, SP_ASR18, SP_ASR19, SP_ASR20,
        SP_ASR21, SP_ASR22, SP_ASR23, SP_ASR24, SP_ASR25, SP_ASR26, SP_ASR27,
        SP_ASR28, SP_ASR29, SP_ASR30, SP_ASR31};

static const unsigned PRRegDecoderTable[] = {
        SP_TPC, SP_TNPC, SP_TSTATE, SP_TT, SP_TICK,
        SP_TBA, SP_PSTATE, SP_TL, SP_PIL, SP_CWP,
        SP_CANSAVE, SP_CANRESTORE, SP_CLEANWIN, SP_OTHERWIN, SP_WSTATE};

static const uint16_t IntPairDecoderTable[] = {
        SP_G0_G1, SP_G2_G3, SP_G4_G5, SP_G6_G7, SP_O0_O1, SP_O2_O3,
        SP_O4_O5, SP_O6_O7, SP_L0_L1, SP_L2_L3, SP_L4_L5, SP_L6_L7,
        SP_I0_I1, SP_I2_I3, SP_I4_I5, SP_I6_I7,
};

static const unsigned CPRegDecoderTable[] = {
        SP_C0, SP_C1, SP_C2, SP_C3, SP_C4, SP_C5, SP_C6, SP_C7,
        SP_C8, SP_C9, SP_C10, SP_C11, SP_C12, SP_C13, SP_C14, SP_C15,
        SP_C16, SP_C17, SP_C18, SP_C19, SP_C20, SP_C21, SP_C22, SP_C23,
        SP_C24, SP_C25, SP_C26, SP_C27, SP_C28, SP_C29, SP_C30, SP_C31};

static const uint16_t CPPairDecoderTable[] = {
        SP_C0_C1, SP_C2_C3, SP_C4_C5, SP_C6_C7, SP_C8_C9, SP_C10_C11,
        SP_C12_C13, SP_C14_C15, SP_C16_C17, SP_C18_C19, SP_C20_C21, SP_C22_C23,
        SP_C24_C25, SP_C26_C27, SP_C28_C29, SP_C30_C31};

static DecodeStatus DecodeIntRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    unsigned Reg = IntRegDecoderTable[RegNo];
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeI64RegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    unsigned Reg = IntRegDecoderTable[RegNo];
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    unsigned Reg = FPRegDecoderTable[RegNo];
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeDFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    unsigned Reg = DFPRegDecoderTable[RegNo];
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeQFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;

    unsigned Reg = QFPRegDecoderTable[RegNo];
    if (Reg == ~0U)
        return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeCPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    unsigned Reg = CPRegDecoderTable[RegNo];
    MCOperand_CreateReg0(Inst, Reg);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeFCCRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 3)
        return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, FCCRegDecoderTable[RegNo]);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeASRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, ASRRegDecoderTable[RegNo]);
    return MCDisassembler_Success;
}

static DecodeStatus DecodePRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
    if (RegNo >= sizeof(PRRegDecoderTable))
        return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, PRRegDecoderTable[RegNo]);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeIntPairRegisterClass(MCInst *Inst, unsigned RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
    DecodeStatus S = MCDisassembler_Success;

    if (RegNo > 31)
        return MCDisassembler_Fail;

    if ((RegNo & 1))
        S = MCDisassembler_SoftFail;

    unsigned RegisterPair = IntPairDecoderTable[RegNo / 2];
    MCOperand_CreateReg0(Inst, RegisterPair);
    return S;
}

static DecodeStatus DecodeCPPairRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
    if (RegNo > 31)
        return MCDisassembler_Fail;

    unsigned RegisterPair = CPPairDecoderTable[RegNo / 2];
    MCOperand_CreateReg0(Inst, RegisterPair);
    return MCDisassembler_Success;
}

typedef DecodeStatus (*DecodeFunc)(MCInst *MI, unsigned insn, uint64_t Address,
                                   MCRegisterInfo *Decoder);

static DecodeStatus DecodeMem(MCInst *MI, unsigned insn, uint64_t Address,
                              MCRegisterInfo *Decoder, bool isLoad,
                              DecodeFunc DecodeRD) {
    unsigned rd = fieldFromInstruction_4(insn, 25, 5);
    unsigned rs1 = fieldFromInstruction_4(insn, 14, 5);
    bool isImm = fieldFromInstruction_4(insn, 13, 1);
    bool hasAsi = fieldFromInstruction_4(insn, 23, 1); // (in op3 field)
    unsigned asi = fieldFromInstruction_4(insn, 5, 8);
    unsigned rs2 = 0;
    unsigned simm13 = 0;
    if (isImm)
        simm13 = SignExtend32(fieldFromInstruction_4(insn, 0, 13), 13);
    else
        rs2 = fieldFromInstruction_4(insn, 0, 5);

    DecodeStatus status;
    if (isLoad) {
        status = DecodeRD(MI, rd, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }

    // Decode rs1.
    status = DecodeIntRegsRegisterClass(MI, rs1, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode imm|rs2.
    if (isImm)
        MCOperand_CreateImm0(MI, simm13);
    else {
        status = DecodeIntRegsRegisterClass(MI, rs2, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }

    if (hasAsi)
        MCOperand_CreateImm0(MI, asi);

    if (!isLoad) {
        status = DecodeRD(MI, rd, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }
    return MCDisassembler_Success;
}

static DecodeStatus DecodeLoadInt(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeIntRegsRegisterClass);
}

static DecodeStatus DecodeLoadIntPair(MCInst *Inst, unsigned insn,
                                      uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeIntPairRegisterClass);
}

static DecodeStatus DecodeLoadFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeFPRegsRegisterClass);
}

static DecodeStatus DecodeLoadDFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeDFPRegsRegisterClass);
}

static DecodeStatus DecodeLoadQFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeQFPRegsRegisterClass);
}

static DecodeStatus DecodeLoadCP(MCInst *Inst, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeCPRegsRegisterClass);
}

static DecodeStatus DecodeLoadCPPair(MCInst *Inst, unsigned insn,
                                     uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, true,
                     DecodeCPPairRegisterClass);
}

static DecodeStatus DecodeStoreInt(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeIntRegsRegisterClass);
}

static DecodeStatus DecodeStoreIntPair(MCInst *Inst, unsigned insn,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeIntPairRegisterClass);
}

static DecodeStatus DecodeStoreFP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeFPRegsRegisterClass);
}

static DecodeStatus DecodeStoreDFP(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeDFPRegsRegisterClass);
}

static DecodeStatus DecodeStoreQFP(MCInst *Inst, unsigned insn,
                                   uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeQFPRegsRegisterClass);
}

static DecodeStatus DecodeStoreCP(MCInst *Inst, unsigned insn, uint64_t Address,
                                  MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeCPRegsRegisterClass);
}

static DecodeStatus DecodeStoreCPPair(MCInst *Inst, unsigned insn,
                                      uint64_t Address, MCRegisterInfo *Decoder) {
    return DecodeMem(Inst, insn, Address, Decoder, false,
                     DecodeCPPairRegisterClass);
}

static DecodeStatus DecodeCall(MCInst *MI, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder) {
    unsigned tgt = fieldFromInstruction_4(insn, 0, 30);
    tgt <<= 2;
    //  if (!tryAddingSymbolicOperand(tgt+Address, false, Address,
    //				0, 30, MI, Decoder))
    MCOperand_CreateImm0(MI, tgt);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeSIMM13(MCInst *MI, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder) {
    unsigned tgt = SignExtend32(fieldFromInstruction_4(insn, 0, 13), 13);
    MCOperand_CreateImm0(MI, tgt);
    return MCDisassembler_Success;
}

static DecodeStatus DecodeJMPL(MCInst *MI, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder) {

    unsigned rd = fieldFromInstruction_4(insn, 25, 5);
    unsigned rs1 = fieldFromInstruction_4(insn, 14, 5);
    unsigned isImm = fieldFromInstruction_4(insn, 13, 1);
    unsigned rs2 = 0;
    unsigned simm13 = 0;
    if (isImm)
        simm13 = SignExtend32(fieldFromInstruction_4(insn, 0, 13), 13);
    else
        rs2 = fieldFromInstruction_4(insn, 0, 5);

    // Decode RD.
    DecodeStatus status = DecodeIntRegsRegisterClass(MI, rd, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS1.
    status = DecodeIntRegsRegisterClass(MI, rs1, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS1 | SIMM13.
    if (isImm)
        MCOperand_CreateImm0(MI, simm13);
    else {
        status = DecodeIntRegsRegisterClass(MI, rs2, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }
    return MCDisassembler_Success;
}

static DecodeStatus DecodeReturn(MCInst *MI, unsigned insn, uint64_t Address,
                                 MCRegisterInfo *Decoder) {

    unsigned rs1 = fieldFromInstruction_4(insn, 14, 5);
    unsigned isImm = fieldFromInstruction_4(insn, 13, 1);
    unsigned rs2 = 0;
    unsigned simm13 = 0;
    if (isImm)
        simm13 = SignExtend32(fieldFromInstruction_4(insn, 0, 13), 13);
    else
        rs2 = fieldFromInstruction_4(insn, 0, 5);

    // Decode RS1.
    DecodeStatus status = DecodeIntRegsRegisterClass(MI, rs1, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS2 | SIMM13.
    if (isImm)
        MCOperand_CreateImm0(MI, simm13);
    else {
        status = DecodeIntRegsRegisterClass(MI, rs2, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }
    return MCDisassembler_Success;
}

static DecodeStatus DecodeSWAP(MCInst *MI, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder) {

    unsigned rd = fieldFromInstruction_4(insn, 25, 5);
    unsigned rs1 = fieldFromInstruction_4(insn, 14, 5);
    unsigned isImm = fieldFromInstruction_4(insn, 13, 1);
    bool hasAsi = fieldFromInstruction_4(insn, 23, 1); // (in op3 field)
    unsigned asi = fieldFromInstruction_4(insn, 5, 8);
    unsigned rs2 = 0;
    unsigned simm13 = 0;
    if (isImm)
        simm13 = SignExtend32(fieldFromInstruction_4(insn, 0, 13), 13);
    else
        rs2 = fieldFromInstruction_4(insn, 0, 5);

    // Decode RD.
    DecodeStatus status = DecodeIntRegsRegisterClass(MI, rd, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS1.
    status = DecodeIntRegsRegisterClass(MI, rs1, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS1 | SIMM13.
    if (isImm)
        MCOperand_CreateImm0(MI, simm13);
    else {
        status = DecodeIntRegsRegisterClass(MI, rs2, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }

    if (hasAsi)
        MCOperand_CreateImm0(MI, asi);

    return MCDisassembler_Success;
}

static DecodeStatus DecodeTRAP(MCInst *MI, unsigned insn, uint64_t Address,
                               MCRegisterInfo *Decoder) {

    unsigned rs1 = fieldFromInstruction_4(insn, 14, 5);
    unsigned isImm = fieldFromInstruction_4(insn, 13, 1);
    unsigned cc = fieldFromInstruction_4(insn, 25, 4);
    unsigned rs2 = 0;
    unsigned imm7 = 0;
    if (isImm)
        imm7 = fieldFromInstruction_4(insn, 0, 7);
    else
        rs2 = fieldFromInstruction_4(insn, 0, 5);

    // Decode RS1.
    DecodeStatus status = DecodeIntRegsRegisterClass(MI, rs1, Address, Decoder);
    if (status != MCDisassembler_Success)
        return status;

    // Decode RS1 | IMM7.
    if (isImm)
        MCOperand_CreateImm0(MI, imm7);
    else {
        status = DecodeIntRegsRegisterClass(MI, rs2, Address, Decoder);
        if (status != MCDisassembler_Success)
            return status;
    }

    // Decode CC
    MCOperand_CreateImm0(MI, cc);

    return MCDisassembler_Success;
}

#endif // CAPSTONE_CAPSTONESPARCMODULE_H
