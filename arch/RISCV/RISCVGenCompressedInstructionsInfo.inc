/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Compress instruction Source Fragment                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: RISCV.td                                                             *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GEN_COMPRESS_INSTR
#undef GEN_COMPRESS_INSTR

static bool RISCVValidateMCOperandForCompress(MCInst *MI,MCOperand *MCOp,
                  unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    CS_ASSERT_RET_VAL(0,false);
	 return false;
    break;
  case 1: {
  // uimm10_lsb00nonzero

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(8, 2, Imm) && (Imm != 0);

  }
  case 2: {
  // simm6nonzero

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return (Imm != 0) && isIntN(6, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 3: {
  // simm6

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isIntN(6, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 4: {
  // simm10_lsb0000nonzero

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedIntN(6, 4, Imm) && (Imm != 0);

  }
  case 5: {
  // simm9_lsb0

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isShiftedIntN(8, 1, Imm);
    return MCOperand_isExpr(MCOp);


  }
  case 6: {
  // uimm8_lsb000

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(5, 3, Imm);

  }
  case 7: {
  // uimm9_lsb000

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(6, 3, Imm);

  }
  case 8: {
  // uimm7_lsb00

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(5, 2, Imm);

  }
  case 9: {
  // uimm8_lsb00

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(6, 2, Imm);

  }
  case 10: {
  // simm12_lsb0

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isShiftedIntN(11, 1, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 11: {
  // uimm2

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isUIntN(2, Imm);

  }
  case 12: {
  // uimm2_lsb0

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    return isShiftedUIntN(1, 1, Imm);

  }
  case 13: {
  // c_lui_imm

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return (Imm != 0) && (isUIntN(5, Imm) ||
             (Imm >= 0xfffe0 && Imm <= 0xfffff));
    return MCOperand_isExpr(MCOp);

  }
  case 14: {
  // uimmlog2xlennonzero

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    if (RISCV_getFeatureBits(MI->csh->mode,RISCV_Feature64Bit))
      return  isUIntN(6, Imm) && (Imm != 0);
    return isUIntN(5, Imm) && (Imm != 0);
  }
  }
}

static bool compressInst(MCInst *OutInst,
                         MCInst *MI) {
  switch (MCInst_getOpcode(MI)) {
    default: return false;
    case RISCV_ADD: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.mv	$rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_MV);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mv	$rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_MV);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.add	$rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_ADD);
      // Operand: rs1_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.add	$rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_ADD);
      // Operand: rs1_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ADD
    case RISCV_ADDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // c.addi4spn	$rd, $rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_ADDI4SPN);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0)) {
      // c.nop
      MCInst_setOpcode(OutInst, RISCV_C_NOP);

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 2)) {
      // c.addi	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_ADDI);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 3)) {
      // c.li	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_LI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X2) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X2) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 4)) {
      // c.addi16sp	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_ADDI16SP);
      // Operand: rd_wb
      MCOperand_CreateReg0(OutInst, RISCV_X2);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X2);
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mv	$rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_MV);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ADDI
    case RISCV_ADDIW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 3)) {
      // c.addiw	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_ADDIW);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 3)) {
      // c.li	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_LI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case ADDIW
    case RISCV_ADDW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.addw	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_ADDW);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.addw	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_ADDW);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ADDW
    case RISCV_ADD_UW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZba) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.w	$rd
      MCInst_setOpcode(OutInst, RISCV_C_ZEXT_W);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ADD_UW
    case RISCV_AND: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.and	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_AND);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.and	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_AND);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case AND
    case RISCV_ANDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 3)) {
      // c.andi	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_ANDI);
      // Operand: rs1_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 255) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.b	$rd
      MCInst_setOpcode(OutInst, RISCV_C_ZEXT_B);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ANDI
    case RISCV_BEQ: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.beqz	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_BEQZ);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.beqz	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_BEQZ);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case BEQ
    case RISCV_BNE: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.bnez	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_BNEZ);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.bnez	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_BNEZ);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case BNE
    case RISCV_EBREAK: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // c.ebreak
      MCInst_setOpcode(OutInst, RISCV_C_EBREAK);

      return true;
    } // if
      break;
    } // case EBREAK
    case RISCV_FLD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.fld	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FLD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.fldsp	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FLDSP);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case FLD
    case RISCV_FLW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.flw	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FLW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.flwsp	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FLWSP);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case FLW
    case RISCV_FSD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.fsd	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FSD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.fsdsp	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FSDSP);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case FSD
    case RISCV_FSW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.fsw	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FSW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.fswsp	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_FSWSP);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case FSW
    case RISCV_JAL: {
    if (!RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 1), 10)) {
      // c.jal	$offset
      MCInst_setOpcode(OutInst, RISCV_C_JAL);
      // Operand: offset
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 1), 10)) {
      // c.j	$offset
      MCInst_setOpcode(OutInst, RISCV_C_J);
      // Operand: offset
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case JAL
    case RISCV_JALR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.jr	$rs1
      MCInst_setOpcode(OutInst, RISCV_C_JR);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.jalr	$rs1
      MCInst_setOpcode(OutInst, RISCV_C_JALR);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case JALR
    case RISCV_LBU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 11)) {
      // c.lbu	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LBU);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case LBU
    case RISCV_LD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.ld	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LDSP);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case LD
    case RISCV_LH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.lh	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LH);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case LH
    case RISCV_LHU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.lhu	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LHU);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case LHU
    case RISCV_LUI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0X2RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 1), 13)) {
      // c.lui	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_LUI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case LUI
    case RISCV_LW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.lw	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_LWSP);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case LW
    case RISCV_MUL: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtM) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZmmul)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.mul	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_MUL);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtM) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZmmul)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mul	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_MUL);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case MUL
    case RISCV_OR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.or	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_OR);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.or	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_OR);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case OR
    case RISCV_SB: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 11)) {
      // c.sb	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SB);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SB
    case RISCV_SD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.sd	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SDSP);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SD
    case RISCV_SEXT_B: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.sext.b	$rd
      MCInst_setOpcode(OutInst, RISCV_C_SEXT_B);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case SEXT_B
    case RISCV_SEXT_H: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.sext.h	$rd
      MCInst_setOpcode(OutInst, RISCV_C_SEXT_H);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case SEXT_H
    case RISCV_SH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.sh	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SH);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SH
    case RISCV_SLLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.slli	$rd, $imm
      MCInst_setOpcode(OutInst, RISCV_C_SLLI);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SLLI
    case RISCV_SRAI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.srai	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_SRAI);
      // Operand: rs1_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SRAI
    case RISCV_SRLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.srli	$rs1, $imm
      MCInst_setOpcode(OutInst, RISCV_C_SRLI);
      // Operand: rs1_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SRLI
    case RISCV_SSPOPCHK: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X5)) {
      // c.sspopchk	$rs1
      MCInst_setOpcode(OutInst, RISCV_C_SSPOPCHK);
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X5);

      return true;
    } // if
      break;
    } // case SSPOPCHK
    case RISCV_SSPUSH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1)) {
      // c.sspush	$rs1
      MCInst_setOpcode(OutInst, RISCV_C_SSPUSH);
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X1);

      return true;
    } // if
      break;
    } // case SSPUSH
    case RISCV_SUB: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.sub	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_SUB);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SUB
    case RISCV_SUBW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.subw	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_SUBW);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SUBW
    case RISCV_SW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.sw	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForCompress(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_C_SWSP);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case SW
    case RISCV_UNIMP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // c.unimp
      MCInst_setOpcode(OutInst, RISCV_C_UNIMP);

      return true;
    } // if
      break;
    } // case UNIMP
    case RISCV_XOR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.xor	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_XOR);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.xor	$rd, $rs2
      MCInst_setOpcode(OutInst, RISCV_C_XOR);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case XOR
    case RISCV_XORI: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == -1) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.not	$rd
      MCInst_setOpcode(OutInst, RISCV_C_NOT);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case XORI
    case RISCV_ZEXT_H_RV32: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.h	$rd
      MCInst_setOpcode(OutInst, RISCV_C_ZEXT_H);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case ZEXT_H_RV32
    case RISCV_ZEXT_H_RV64: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.h	$rd
      MCInst_setOpcode(OutInst, RISCV_C_ZEXT_H);
      // Operand: rd_wb
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if

    } // case ZEXT_H_RV64
  } // switch
  return false;
}

#endif //GEN_COMPRESS_INSTR

#ifdef GEN_UNCOMPRESS_INSTR
#undef GEN_UNCOMPRESS_INSTR

static bool RISCVValidateMCOperandForUncompress(MCInst *MI,MCOperand *MCOp,
                  unsigned PredicateIndex) {
  switch (PredicateIndex) {
  default:
    CS_ASSERT_RET_VAL(0,false);
	 return false;
    break;
  case 1: {
  // simm12

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isIntN(12, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 2: {
  // simm13_lsb0

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isShiftedIntN(12, 1, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 3: {
  // simm21_lsb0_jal

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isShiftedIntN(20, 1, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 4: {
  // uimm20_lui

    int64_t Imm;
    if ((Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return isUIntN(20, Imm);
    return MCOperand_isExpr(MCOp);

  }
  case 5: {
  // uimmlog2xlen

    int64_t Imm;
    if (!(Imm = MCOperand_getImm(MCOp), MCOperand_isImm(MCOp)))
      return false;
    if (RISCV_getFeatureBits(MI->csh->mode,RISCV_Feature64Bit))
      return isUIntN(6, Imm);
    return isUIntN(5, Imm);

  }
  }
}

static bool uncompressInst(MCInst *OutInst,
                           MCInst *MI) {
  switch (MCInst_getOpcode(MI)) {
    default: return false;
    case RISCV_C_ADD: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // add	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_ADD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADD
    case RISCV_C_ADDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADDI
    case RISCV_C_ADDI16SP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X2) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X2) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X2);
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X2);
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADDI16SP
    case RISCV_C_ADDI4SPN: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADDI4SPN
    case RISCV_C_ADDIW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // addiw	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDIW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADDIW
    case RISCV_C_ADDW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // addw	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_ADDW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ADDW
    case RISCV_C_AND: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // and	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_AND);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_AND
    case RISCV_C_ANDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // andi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ANDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_ANDI
    case RISCV_C_BEQZ: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 1), 2)) {
      // beq	$rs1, $rs2, $imm12
      MCInst_setOpcode(OutInst, RISCV_BEQ);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case C_BEQZ
    case RISCV_C_BNEZ: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 1), 2)) {
      // bne	$rs1, $rs2, $imm12
      MCInst_setOpcode(OutInst, RISCV_BNE);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case C_BNEZ
    case RISCV_C_EBREAK: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // ebreak
      MCInst_setOpcode(OutInst, RISCV_EBREAK);

      return true;
    } // if
      break;
    } // case C_EBREAK
    case RISCV_C_FLD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fld	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FLD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FLD
    case RISCV_C_FLDSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fld	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FLD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FLDSP
    case RISCV_C_FLW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // flw	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FLW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FLW
    case RISCV_C_FLWSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // flw	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FLW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FLWSP
    case RISCV_C_FSD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fsd	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FSD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FSD
    case RISCV_C_FSDSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fsd	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FSD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FSDSP
    case RISCV_C_FSW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fsw	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FSW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FSW
    case RISCV_C_FSWSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // fsw	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_FSW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_FSWSP
    case RISCV_C_J: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 0), 3)) {
      // jal	$rd, $imm20
      MCInst_setOpcode(OutInst, RISCV_JAL);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: imm20
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
      break;
    } // case C_J
    case RISCV_C_JAL: {
    if (!RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 0), 3)) {
      // jal	$rd, $imm20
      MCInst_setOpcode(OutInst, RISCV_JAL);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X1);
      // Operand: imm20
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
      break;
    } // case C_JAL
    case RISCV_C_JALR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, 0), 1)) {
      // jalr	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_JALR);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X1);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, 0);

      return true;
    } // if
      break;
    } // case C_JALR
    case RISCV_C_JR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, 0), 1)) {
      // jalr	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_JALR);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, 0);

      return true;
    } // if
      break;
    } // case C_JR
    case RISCV_C_LBU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // lbu	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LBU);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LBU
    case RISCV_C_LD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // ld	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LD
    case RISCV_C_LDSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // ld	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LD);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LDSP
    case RISCV_C_LH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // lh	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LH);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LH
    case RISCV_C_LHU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // lhu	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LHU);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LHU
    case RISCV_C_LI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 1), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case C_LI
    case RISCV_C_LUI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 1), 4)) {
      // lui	$rd, $imm20
      MCInst_setOpcode(OutInst, RISCV_LUI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm20
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));

      return true;
    } // if
      break;
    } // case C_LUI
    case RISCV_C_LW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // lw	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LW
    case RISCV_C_LWSP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // lw	$rd, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_LW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_LWSP
    case RISCV_C_MUL: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtM) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZmmul)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // mul	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_MUL);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_MUL
    case RISCV_C_MV: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, 0), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, 0);

      return true;
    } // if
      break;
    } // case C_MV
    case RISCV_C_NOP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, 0), 1)) {
      // addi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ADDI);
      // Operand: rd
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X0);
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, 0);

      return true;
    } // if
      break;
    } // case C_NOP
    case RISCV_C_NOT: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, -1), 1)) {
      // xori	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_XORI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, -1);

      return true;
    } // if
      break;
    } // case C_NOT
    case RISCV_C_OR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // or	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_OR);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_OR
    case RISCV_C_SB: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sb	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SB);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SB
    case RISCV_C_SD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sd	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SD
    case RISCV_C_SDSP: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sd	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SD);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SDSP
    case RISCV_C_SEXT_B: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0))))) {
      // sext.b	$rd, $rs1
      MCInst_setOpcode(OutInst, RISCV_SEXT_B);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
      break;
    } // case C_SEXT_B
    case RISCV_C_SEXT_H: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0))))) {
      // sext.h	$rd, $rs1
      MCInst_setOpcode(OutInst, RISCV_SEXT_H);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
      break;
    } // case C_SEXT_H
    case RISCV_C_SH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sh	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SH);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SH
    case RISCV_C_SLLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // slli	$rd, $rs1, $shamt
      MCInst_setOpcode(OutInst, RISCV_SLLI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: shamt
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SLLI
    case RISCV_C_SRAI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // srai	$rd, $rs1, $shamt
      MCInst_setOpcode(OutInst, RISCV_SRAI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: shamt
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SRAI
    case RISCV_C_SRLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 5)) {
      // srli	$rd, $rs1, $shamt
      MCInst_setOpcode(OutInst, RISCV_SRLI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: shamt
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SRLI
    case RISCV_C_SSPOPCHK: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X5)) {
      // sspopchk	$rs1
      MCInst_setOpcode(OutInst, RISCV_SSPOPCHK);
      // Operand: rs1
      MCOperand_CreateReg0(OutInst, RISCV_X5);

      return true;
    } // if
      break;
    } // case C_SSPOPCHK
    case RISCV_C_SSPUSH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1)) {
      // sspush	$rs2
      MCInst_setOpcode(OutInst, RISCV_SSPUSH);
      // Operand: rs2
      MCOperand_CreateReg0(OutInst, RISCV_X1);

      return true;
    } // if
      break;
    } // case C_SSPUSH
    case RISCV_C_SUB: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // sub	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_SUB);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SUB
    case RISCV_C_SUBW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // subw	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_SUBW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SUBW
    case RISCV_C_SW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sw	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SW
    case RISCV_C_SWSP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCInst_getOperand(MI, 2), 1)) {
      // sw	$rs2, ${imm12}(${rs1})
      MCInst_setOpcode(OutInst, RISCV_SW);
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 1));
      // Operand: imm12
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_SWSP
    case RISCV_C_UNIMP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // unimp
      MCInst_setOpcode(OutInst, RISCV_UNIMP);

      return true;
    } // if
      break;
    } // case C_UNIMP
    case RISCV_C_XOR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // xor	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_XOR);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 2));

      return true;
    } // if
      break;
    } // case C_XOR
    case RISCV_C_ZEXT_B: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      RISCVValidateMCOperandForUncompress(MI,MCOperand_CreateImm1(MI, 255), 1)) {
      // andi	$rd, $rs1, $imm12
      MCInst_setOpcode(OutInst, RISCV_ANDI);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: imm12
      MCOperand_CreateImm0(OutInst, 255);

      return true;
    } // if
      break;
    } // case C_ZEXT_B
    case RISCV_C_ZEXT_H: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0))))) {
      // zext.h	$rd, $rs1
      MCInst_setOpcode(OutInst, RISCV_ZEXT_H_RV32);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0))))) {
      // zext.h	$rd, $rs1
      MCInst_setOpcode(OutInst, RISCV_ZEXT_H_RV64);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));

      return true;
    } // if
      break;
    } // case C_ZEXT_H
    case RISCV_C_ZEXT_W: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZba) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0))))) {
      // add.uw	$rd, $rs1, $rs2
      MCInst_setOpcode(OutInst, RISCV_ADD_UW);
      // Operand: rd
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs1
      MCInst_addOperand2(OutInst, MCInst_getOperand(MI, 0));
      // Operand: rs2
      MCOperand_CreateReg0(OutInst, RISCV_X0);

      return true;
    } // if

    } // case C_ZEXT_W
  } // switch
  return false;
}

#endif //GEN_UNCOMPRESS_INSTR


#ifdef GEN_CHECK_COMPRESS_INSTR
#undef GEN_CHECK_COMPRESS_INSTR

static bool RISCVValidateMachineOperand(MCInst *MI,MCOperand *MO,
                  unsigned PredicateIndex) {
  int64_t Imm = MCOperand_getImm(MO);
  switch (PredicateIndex) {
  default:
    CS_ASSERT_RET_VAL(0,false);
	 return false;
    break;
  case 1: {
  // simm6nonzero
  return (Imm != 0) && isIntN(6, Imm);
  }
  case 2: {
  // simm10_lsb0000nonzero
  return (Imm != 0) && isShiftedIntN(6, 4, Imm);
  }
  case 3: {
  // uimm10_lsb00nonzero
  return isShiftedUIntN(8, 2, Imm) && (Imm != 0);
  }
  case 4: {
  // simm6
  return isIntN(6, Imm);
  }
  case 5: {
  // simm9_lsb0
  return isShiftedIntN(8, 1, Imm);
  }
  case 6: {
  // uimm8_lsb000
  return isShiftedUIntN(5, 3, Imm);
  }
  case 7: {
  // uimm9_lsb000
  return isShiftedUIntN(6, 3, Imm);
  }
  case 8: {
  // uimm7_lsb00
  return isShiftedUIntN(5, 2, Imm);
  }
  case 9: {
  // uimm8_lsb00
  return isShiftedUIntN(6, 2, Imm);
  }
  case 10: {
  // simm12_lsb0
  return isShiftedIntN(11, 1, Imm);
  }
  case 11: {
  // uimm2
  return isUIntN(2, Imm);
  }
  case 12: {
  // uimm2_lsb0
  return isShiftedUIntN(1, 1, Imm);
  }
  case 13: {
  // c_lui_imm
  return (Imm != 0) &&
                                 (isUIntN(5, Imm) ||
                                  (Imm >= 0xfffe0 && Imm <= 0xfffff));
  }
  case 14: {
  // uimmlog2xlennonzero

  if (RISCV_getFeatureBits(MI->csh->mode,RISCV_Feature64Bit))
    return isUIntN(6, Imm) && (Imm != 0);
  return isUIntN(5, Imm) && (Imm != 0);

  }
  }
}

static bool isCompressibleInst(MCInst *MI) {
  switch (MCInst_getOpcode(MI)) {
    default: return false;
    case RISCV_ADD: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.add	$rs1, $rs2
      // Operand: rs1_wb
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.add	$rs1, $rs2
      // Operand: rs1_wb
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
      break;
    } // case ADD
    case RISCV_ADDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 1)) {
      // c.addi	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X2) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X2) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 2)) {
      // c.addi16sp	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 3)) {
      // c.addi4spn	$rd, $rs1, $imm
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 4)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mv	$rs1, $rs2
      // Operand: rs1
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0)) {
      // c.nop
      return true;
    } // if
      break;
    } // case ADDI
    case RISCV_ADDIW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 4)) {
      // c.addiw	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 4)) {
      // c.li	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
      break;
    } // case ADDIW
    case RISCV_ADDW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.addw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.addw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case ADDW
    case RISCV_ADD_UW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZba) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.w	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case ADD_UW
    case RISCV_AND: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.and	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.and	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case AND
    case RISCV_ANDI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 4)) {
      // c.andi	$rs1, $imm
      // Operand: rs1_wb
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 255) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.b	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case ANDI
    case RISCV_BEQ: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.beqz	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.beqz	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case BEQ
    case RISCV_BNE: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.bnez	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 5)) {
      // c.bnez	$rs1, $imm
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case BNE
    case RISCV_EBREAK: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // c.ebreak
      return true;
    } // if
      break;
    } // case EBREAK
    case RISCV_FLD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.fld	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.fldsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case FLD
    case RISCV_FLW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.flw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.flwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case FLW
    case RISCV_FSD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.fsd	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtD) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcd)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR64RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.fsdsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case FSD
    case RISCV_FSW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32CRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.fsw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtF) &&
      !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZce) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcf)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_FPR32RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.fswsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case FSW
    case RISCV_JAL: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      MCOperand_isImm(MCInst_getOperand(MI, 1)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 1), 10)) {
      // c.j	$offset
      // Operand: offset
      return true;
    } // if
    if (!RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1) &&
      MCOperand_isImm(MCInst_getOperand(MI, 1)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 1), 10)) {
      // c.jal	$offset
      // Operand: offset
      return true;
    } // if
      break;
    } // case JAL
    case RISCV_JALR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.jalr	$rs1
      // Operand: rs1
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X0) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.jr	$rs1
      // Operand: rs1
      return true;
    } // if
      break;
    } // case JALR
    case RISCV_LBU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 11)) {
      // c.lbu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case LBU
    case RISCV_LD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.ld	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.ldsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case LD
    case RISCV_LH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.lh	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case LH
    case RISCV_LHU: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.lhu	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case LHU
    case RISCV_LUI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0X2RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 1)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 1), 13)) {
      // c.lui	$rd, $imm
      // Operand: rd
      // Operand: imm
      return true;
    } // if
      break;
    } // case LUI
    case RISCV_LW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.lw	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.lwsp	$rd, ${imm}(${rs1})
      // Operand: rd
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case LW
    case RISCV_MUL: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtM) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZmmul)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.mul	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtM) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZmmul)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.mul	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case MUL
    case RISCV_OR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.or	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.or	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case OR
    case RISCV_SB: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 11)) {
      // c.sb	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SB
    case RISCV_SD: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 6)) {
      // c.sd	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 7)) {
      // c.sdsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SD
    case RISCV_SEXT_B: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.sext.b	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case SEXT_B
    case RISCV_SEXT_H: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.sext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case SEXT_H
    case RISCV_SH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 12)) {
      // c.sh	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SH
    case RISCV_SLLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRNoX0RegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.slli	$rd, $imm
      // Operand: rd_wb
      // Operand: rd
      // Operand: imm
      return true;
    } // if
      break;
    } // case SLLI
    case RISCV_SRAI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.srai	$rs1, $imm
      // Operand: rs1_wb
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SRAI
    case RISCV_SRLI: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 14)) {
      // c.srli	$rs1, $imm
      // Operand: rs1_wb
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SRLI
    case RISCV_SSPOPCHK: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X5)) {
      // c.sspopchk	$rs1
      // Operand: rs1
      return true;
    } // if
      break;
    } // case SSPOPCHK
    case RISCV_SSPUSH: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcmop) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZicfiss) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 0)) == RISCV_X1)) {
      // c.sspush	$rs1
      // Operand: rs1
      return true;
    } // if
      break;
    } // case SSPUSH
    case RISCV_SUB: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.sub	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case SUB
    case RISCV_SUBW: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit) &&
      (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.subw	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case SUBW
    case RISCV_SW: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 8)) {
      // c.sw	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 0)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_SPRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
      RISCVValidateMachineOperand(MI,MCInst_getOperand(MI, 2), 9)) {
      // c.swsp	$rs2, ${imm}(${rs1})
      // Operand: rs2
      // Operand: rs1
      // Operand: imm
      return true;
    } // if
      break;
    } // case SW
    case RISCV_UNIMP: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca))) {
      // c.unimp
      return true;
    } // if
      break;
    } // case UNIMP
    case RISCV_XOR: {
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2))))) {
      // c.xor	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
    if ((RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtC) || RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZca)) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 2)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 2))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 2)))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.xor	$rd, $rs2
      // Operand: rd_wb
      // Operand: rd
      // Operand: rs2
      return true;
    } // if
      break;
    } // case XOR
    case RISCV_XORI: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isImm(MCInst_getOperand(MI, 2))) &&
      (MCOperand_getImm(MCInst_getOperand(MI, 2)) == -1) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.not	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case XORI
    case RISCV_ZEXT_H_RV32: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if
      break;
    } // case ZEXT_H_RV32
    case RISCV_ZEXT_H_RV64: {
    if (RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZbb) &&
      RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureStdExtZcb) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) && (MCOperand_isReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_getReg(MCInst_getOperand(MI, 1)) ==  MCOperand_getReg(MCInst_getOperand(MI, 0))) &&
      (MCOperand_isReg(MCInst_getOperand(MI, 1))) &&
      (MCRegisterClass_contains(MCRegisterInfo_getRegClass(MI->MRI, RISCV_GPRCRegClassID),MCOperand_getReg(MCInst_getOperand(MI, 1))))) {
      // c.zext.h	$rd
      // Operand: rd_wb
      // Operand: rd
      return true;
    } // if

    } // case ZEXT_H_RV64
  } // switch
  return false;
}

#endif //GEN_CHECK_COMPRESS_INSTR
