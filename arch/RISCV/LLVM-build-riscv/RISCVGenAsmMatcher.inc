/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Assembly Matcher Source Fragment                                           *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_ASSEMBLER_HEADER
#undef GET_ASSEMBLER_HEADER
  // This should be included into the middle of the declaration of
  // your subclasses implementation of MCTargetAsmParser.
  uint64_t ComputeAvailableFeatures(const FeatureBitset& FB) const;
  void convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                       const OperandVector &Operands);
  void convertToMapAndConstraints(unsigned Kind,
                           const OperandVector &Operands) override;
  unsigned MatchInstructionImpl(const OperandVector &Operands,
                                MCInst &Inst,
                                uint64_t &ErrorInfo,
                                bool matchingInlineAsm,
                                unsigned VariantID = 0);
  OperandMatchResultTy MatchOperandParserImpl(
    OperandVector &Operands,
    StringRef Mnemonic,
    bool ParseForAllFeatures = false);
  OperandMatchResultTy tryCustomParseOperand(
    OperandVector &Operands,
    unsigned MCK);

#endif // GET_ASSEMBLER_HEADER_INFO


#ifdef GET_OPERAND_DIAGNOSTIC_TYPES
#undef GET_OPERAND_DIAGNOSTIC_TYPES

  Match_InvalidBareSymbol,
  Match_InvalidCLUIImm,
  Match_InvalidCSRSystemRegister,
  Match_InvalidFRMArg,
  Match_InvalidFenceArg,
  Match_InvalidImmXLen,
  Match_InvalidSImm10Lsb0000NonZero,
  Match_InvalidSImm12,
  Match_InvalidSImm12Lsb0,
  Match_InvalidSImm13Lsb0,
  Match_InvalidSImm21Lsb0JAL,
  Match_InvalidSImm6,
  Match_InvalidSImm6NonZero,
  Match_InvalidSImm9Lsb0,
  Match_InvalidUImm10Lsb00NonZero,
  Match_InvalidUImm20AUIPC,
  Match_InvalidUImm20LUI,
  Match_InvalidUImm5,
  Match_InvalidUImm7Lsb00,
  Match_InvalidUImm8Lsb00,
  Match_InvalidUImm8Lsb000,
  Match_InvalidUImm9Lsb000,
  Match_InvalidUImmLog2XLen,
  Match_InvalidUImmLog2XLenNonZero,
  END_OPERAND_DIAGNOSTIC_TYPES
#endif // GET_OPERAND_DIAGNOSTIC_TYPES


#ifdef GET_REGISTER_MATCHER
#undef GET_REGISTER_MATCHER

// Flags for subtarget features that participate in instruction matching.
enum SubtargetFeatureFlag : uint8_t {
  Feature_HasStdExtM = (1ULL << 4),
  Feature_HasStdExtA = (1ULL << 0),
  Feature_HasStdExtF = (1ULL << 3),
  Feature_HasStdExtD = (1ULL << 2),
  Feature_HasStdExtC = (1ULL << 1),
  Feature_IsRV64 = (1ULL << 6),
  Feature_IsRV32 = (1ULL << 5),
  Feature_None = 0
};

static unsigned MatchRegisterName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 30 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 20 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 2 strings to match.
        return 33;	 // "f0"
      case '1':	 // 2 strings to match.
        return 35;	 // "f1"
      case '2':	 // 2 strings to match.
        return 37;	 // "f2"
      case '3':	 // 2 strings to match.
        return 39;	 // "f3"
      case '4':	 // 2 strings to match.
        return 41;	 // "f4"
      case '5':	 // 2 strings to match.
        return 43;	 // "f5"
      case '6':	 // 2 strings to match.
        return 45;	 // "f6"
      case '7':	 // 2 strings to match.
        return 47;	 // "f7"
      case '8':	 // 2 strings to match.
        return 49;	 // "f8"
      case '9':	 // 2 strings to match.
        return 51;	 // "f9"
      }
      break;
    case 'x':	 // 10 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return 1;	 // "x0"
      case '1':	 // 1 string to match.
        return 2;	 // "x1"
      case '2':	 // 1 string to match.
        return 3;	 // "x2"
      case '3':	 // 1 string to match.
        return 4;	 // "x3"
      case '4':	 // 1 string to match.
        return 5;	 // "x4"
      case '5':	 // 1 string to match.
        return 6;	 // "x5"
      case '6':	 // 1 string to match.
        return 7;	 // "x6"
      case '7':	 // 1 string to match.
        return 8;	 // "x7"
      case '8':	 // 1 string to match.
        return 9;	 // "x8"
      case '9':	 // 1 string to match.
        return 10;	 // "x9"
      }
      break;
    }
    break;
  case 3:	 // 66 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 44 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 53;	 // "f10"
        case '1':	 // 2 strings to match.
          return 55;	 // "f11"
        case '2':	 // 2 strings to match.
          return 57;	 // "f12"
        case '3':	 // 2 strings to match.
          return 59;	 // "f13"
        case '4':	 // 2 strings to match.
          return 61;	 // "f14"
        case '5':	 // 2 strings to match.
          return 63;	 // "f15"
        case '6':	 // 2 strings to match.
          return 65;	 // "f16"
        case '7':	 // 2 strings to match.
          return 67;	 // "f17"
        case '8':	 // 2 strings to match.
          return 69;	 // "f18"
        case '9':	 // 2 strings to match.
          return 71;	 // "f19"
        }
        break;
      case '2':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 73;	 // "f20"
        case '1':	 // 2 strings to match.
          return 75;	 // "f21"
        case '2':	 // 2 strings to match.
          return 77;	 // "f22"
        case '3':	 // 2 strings to match.
          return 79;	 // "f23"
        case '4':	 // 2 strings to match.
          return 81;	 // "f24"
        case '5':	 // 2 strings to match.
          return 83;	 // "f25"
        case '6':	 // 2 strings to match.
          return 85;	 // "f26"
        case '7':	 // 2 strings to match.
          return 87;	 // "f27"
        case '8':	 // 2 strings to match.
          return 89;	 // "f28"
        case '9':	 // 2 strings to match.
          return 91;	 // "f29"
        }
        break;
      case '3':	 // 4 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 93;	 // "f30"
        case '1':	 // 2 strings to match.
          return 95;	 // "f31"
        }
        break;
      }
      break;
    case 'x':	 // 22 strings to match.
      switch (Name[1]) {
      default: break;
      case '1':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return 11;	 // "x10"
        case '1':	 // 1 string to match.
          return 12;	 // "x11"
        case '2':	 // 1 string to match.
          return 13;	 // "x12"
        case '3':	 // 1 string to match.
          return 14;	 // "x13"
        case '4':	 // 1 string to match.
          return 15;	 // "x14"
        case '5':	 // 1 string to match.
          return 16;	 // "x15"
        case '6':	 // 1 string to match.
          return 17;	 // "x16"
        case '7':	 // 1 string to match.
          return 18;	 // "x17"
        case '8':	 // 1 string to match.
          return 19;	 // "x18"
        case '9':	 // 1 string to match.
          return 20;	 // "x19"
        }
        break;
      case '2':	 // 10 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return 21;	 // "x20"
        case '1':	 // 1 string to match.
          return 22;	 // "x21"
        case '2':	 // 1 string to match.
          return 23;	 // "x22"
        case '3':	 // 1 string to match.
          return 24;	 // "x23"
        case '4':	 // 1 string to match.
          return 25;	 // "x24"
        case '5':	 // 1 string to match.
          return 26;	 // "x25"
        case '6':	 // 1 string to match.
          return 27;	 // "x26"
        case '7':	 // 1 string to match.
          return 28;	 // "x27"
        case '8':	 // 1 string to match.
          return 29;	 // "x28"
        case '9':	 // 1 string to match.
          return 30;	 // "x29"
        }
        break;
      case '3':	 // 2 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 1 string to match.
          return 31;	 // "x30"
        case '1':	 // 1 string to match.
          return 32;	 // "x31"
        }
        break;
      }
      break;
    }
    break;
  }
  return 0;
}

static unsigned MatchRegisterAltName(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 2:	 // 29 strings to match.
    switch (Name[0]) {
    default: break;
    case 'a':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return 11;	 // "a0"
      case '1':	 // 1 string to match.
        return 12;	 // "a1"
      case '2':	 // 1 string to match.
        return 13;	 // "a2"
      case '3':	 // 1 string to match.
        return 14;	 // "a3"
      case '4':	 // 1 string to match.
        return 15;	 // "a4"
      case '5':	 // 1 string to match.
        return 16;	 // "a5"
      case '6':	 // 1 string to match.
        return 17;	 // "a6"
      case '7':	 // 1 string to match.
        return 18;	 // "a7"
      }
      break;
    case 'g':	 // 1 string to match.
      if (Name[1] != 'p')
        break;
      return 4;	 // "gp"
    case 'r':	 // 1 string to match.
      if (Name[1] != 'a')
        break;
      return 2;	 // "ra"
    case 's':	 // 11 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return 9;	 // "s0"
      case '1':	 // 1 string to match.
        return 10;	 // "s1"
      case '2':	 // 1 string to match.
        return 19;	 // "s2"
      case '3':	 // 1 string to match.
        return 20;	 // "s3"
      case '4':	 // 1 string to match.
        return 21;	 // "s4"
      case '5':	 // 1 string to match.
        return 22;	 // "s5"
      case '6':	 // 1 string to match.
        return 23;	 // "s6"
      case '7':	 // 1 string to match.
        return 24;	 // "s7"
      case '8':	 // 1 string to match.
        return 25;	 // "s8"
      case '9':	 // 1 string to match.
        return 26;	 // "s9"
      case 'p':	 // 1 string to match.
        return 3;	 // "sp"
      }
      break;
    case 't':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case '0':	 // 1 string to match.
        return 6;	 // "t0"
      case '1':	 // 1 string to match.
        return 7;	 // "t1"
      case '2':	 // 1 string to match.
        return 8;	 // "t2"
      case '3':	 // 1 string to match.
        return 29;	 // "t3"
      case '4':	 // 1 string to match.
        return 30;	 // "t4"
      case '5':	 // 1 string to match.
        return 31;	 // "t5"
      case '6':	 // 1 string to match.
        return 32;	 // "t6"
      case 'p':	 // 1 string to match.
        return 5;	 // "tp"
      }
      break;
    }
    break;
  case 3:	 // 58 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 56 strings to match.
      switch (Name[1]) {
      default: break;
      case 'a':	 // 16 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 53;	 // "fa0"
        case '1':	 // 2 strings to match.
          return 55;	 // "fa1"
        case '2':	 // 2 strings to match.
          return 57;	 // "fa2"
        case '3':	 // 2 strings to match.
          return 59;	 // "fa3"
        case '4':	 // 2 strings to match.
          return 61;	 // "fa4"
        case '5':	 // 2 strings to match.
          return 63;	 // "fa5"
        case '6':	 // 2 strings to match.
          return 65;	 // "fa6"
        case '7':	 // 2 strings to match.
          return 67;	 // "fa7"
        }
        break;
      case 's':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 49;	 // "fs0"
        case '1':	 // 2 strings to match.
          return 51;	 // "fs1"
        case '2':	 // 2 strings to match.
          return 69;	 // "fs2"
        case '3':	 // 2 strings to match.
          return 71;	 // "fs3"
        case '4':	 // 2 strings to match.
          return 73;	 // "fs4"
        case '5':	 // 2 strings to match.
          return 75;	 // "fs5"
        case '6':	 // 2 strings to match.
          return 77;	 // "fs6"
        case '7':	 // 2 strings to match.
          return 79;	 // "fs7"
        case '8':	 // 2 strings to match.
          return 81;	 // "fs8"
        case '9':	 // 2 strings to match.
          return 83;	 // "fs9"
        }
        break;
      case 't':	 // 20 strings to match.
        switch (Name[2]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 33;	 // "ft0"
        case '1':	 // 2 strings to match.
          return 35;	 // "ft1"
        case '2':	 // 2 strings to match.
          return 37;	 // "ft2"
        case '3':	 // 2 strings to match.
          return 39;	 // "ft3"
        case '4':	 // 2 strings to match.
          return 41;	 // "ft4"
        case '5':	 // 2 strings to match.
          return 43;	 // "ft5"
        case '6':	 // 2 strings to match.
          return 45;	 // "ft6"
        case '7':	 // 2 strings to match.
          return 47;	 // "ft7"
        case '8':	 // 2 strings to match.
          return 89;	 // "ft8"
        case '9':	 // 2 strings to match.
          return 91;	 // "ft9"
        }
        break;
      }
      break;
    case 's':	 // 2 strings to match.
      if (Name[1] != '1')
        break;
      switch (Name[2]) {
      default: break;
      case '0':	 // 1 string to match.
        return 27;	 // "s10"
      case '1':	 // 1 string to match.
        return 28;	 // "s11"
      }
      break;
    }
    break;
  case 4:	 // 9 strings to match.
    switch (Name[0]) {
    default: break;
    case 'f':	 // 8 strings to match.
      switch (Name[1]) {
      default: break;
      case 's':	 // 4 strings to match.
        if (Name[2] != '1')
          break;
        switch (Name[3]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 85;	 // "fs10"
        case '1':	 // 2 strings to match.
          return 87;	 // "fs11"
        }
        break;
      case 't':	 // 4 strings to match.
        if (Name[2] != '1')
          break;
        switch (Name[3]) {
        default: break;
        case '0':	 // 2 strings to match.
          return 93;	 // "ft10"
        case '1':	 // 2 strings to match.
          return 95;	 // "ft11"
        }
        break;
      }
      break;
    case 'z':	 // 1 string to match.
      if (memcmp(Name.data()+1, "ero", 3) != 0)
        break;
      return 1;	 // "zero"
    }
    break;
  }
  return 0;
}

#endif // GET_REGISTER_MATCHER


#ifdef GET_SUBTARGET_FEATURE_NAME
#undef GET_SUBTARGET_FEATURE_NAME

// User-level names for subtarget features that participate in
// instruction matching.
static const char *getSubtargetFeatureName(uint64_t Val) {
  switch(Val) {
  case Feature_HasStdExtM: return "";
  case Feature_HasStdExtA: return "";
  case Feature_HasStdExtF: return "";
  case Feature_HasStdExtD: return "";
  case Feature_HasStdExtC: return "";
  case Feature_IsRV64: return "";
  case Feature_IsRV32: return "";
  default: return "(unknown)";
  }
}

#endif // GET_SUBTARGET_FEATURE_NAME


#ifdef GET_MATCHER_IMPLEMENTATION
#undef GET_MATCHER_IMPLEMENTATION

static void applyMnemonicAliases(StringRef &Mnemonic, uint64_t Features, unsigned VariantID) {
  switch (VariantID) {
    case 0:
      switch (Mnemonic.size()) {
      default: break;
      case 4:	 // 1 string to match.
        if (memcmp(Mnemonic.data()+0, "move", 4) != 0)
          break;
        Mnemonic = "mv";	 // "move"
        return;
      case 5:	 // 1 string to match.
        if (memcmp(Mnemonic.data()+0, "scall", 5) != 0)
          break;
        Mnemonic = "ecall";	 // "scall"
        return;
      case 6:	 // 1 string to match.
        if (memcmp(Mnemonic.data()+0, "sbreak", 6) != 0)
          break;
        Mnemonic = "ebreak";	 // "sbreak"
        return;
      case 7:	 // 2 strings to match.
        if (memcmp(Mnemonic.data()+0, "fmv.", 4) != 0)
          break;
        switch (Mnemonic[4]) {
        default: break;
        case 's':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+5, ".x", 2) != 0)
            break;
          if ((Features & Feature_HasStdExtF) == Feature_HasStdExtF)	 // "fmv.s.x"
            Mnemonic = "fmv.w.x";
          return;
        case 'x':	 // 1 string to match.
          if (memcmp(Mnemonic.data()+5, ".s", 2) != 0)
            break;
          if ((Features & Feature_HasStdExtF) == Feature_HasStdExtF)	 // "fmv.x.s"
            Mnemonic = "fmv.x.w";
          return;
        }
        break;
      }
    break;
  }
  switch (Mnemonic.size()) {
  default: break;
  case 4:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "move", 4) != 0)
      break;
    Mnemonic = "mv";	 // "move"
    return;
  case 5:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "scall", 5) != 0)
      break;
    Mnemonic = "ecall";	 // "scall"
    return;
  case 6:	 // 1 string to match.
    if (memcmp(Mnemonic.data()+0, "sbreak", 6) != 0)
      break;
    Mnemonic = "ebreak";	 // "sbreak"
    return;
  case 7:	 // 2 strings to match.
    if (memcmp(Mnemonic.data()+0, "fmv.", 4) != 0)
      break;
    switch (Mnemonic[4]) {
    default: break;
    case 's':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+5, ".x", 2) != 0)
        break;
      if ((Features & Feature_HasStdExtF) == Feature_HasStdExtF)	 // "fmv.s.x"
        Mnemonic = "fmv.w.x";
      return;
    case 'x':	 // 1 string to match.
      if (memcmp(Mnemonic.data()+5, ".s", 2) != 0)
        break;
      if ((Features & Feature_HasStdExtF) == Feature_HasStdExtF)	 // "fmv.x.s"
        Mnemonic = "fmv.x.w";
      return;
    }
    break;
  }
}

enum {
  Tie0_1_1,
};

static const uint8_t TiedAsmOperandTable[][3] = {
  /* Tie0_1_1 */ { 0, 1, 1 },
};

namespace {
enum OperatorConversionKind {
  CVT_Done,
  CVT_Reg,
  CVT_Tied,
  CVT_95_Reg,
  CVT_95_addImmOperands,
  CVT_regX0,
  CVT_95_addCSRSystemRegisterOperands,
  CVT_imm_95_7,
  CVT_95_addFRMArgOperands,
  CVT_imm_95_15,
  CVT_95_addFenceArgOperands,
  CVT_imm_95_3,
  CVT_imm_95_1,
  CVT_imm_95_2,
  CVT_regX1,
  CVT_imm_95_0,
  CVT_imm_95__MINUS_1,
  CVT_imm_95_3072,
  CVT_imm_95_3200,
  CVT_imm_95_3074,
  CVT_imm_95_3202,
  CVT_imm_95_3073,
  CVT_imm_95_3201,
  CVT_NUM_CONVERTERS
};

enum InstructionConversionKind {
  Convert__Reg1_0__Reg1_1__Reg1_2,
  Convert__Reg1_0__Reg1_1__SImm121_2,
  Convert__Reg1_0__Reg1_3__Reg1_1,
  Convert__Reg1_0__UImm20AUIPC1_1,
  Convert__Reg1_0__Reg1_1__SImm13Lsb01_2,
  Convert__Reg1_0__regX0__SImm13Lsb01_1,
  Convert__Reg1_1__Reg1_0__SImm13Lsb01_2,
  Convert__regX0__Reg1_0__SImm13Lsb01_1,
  Convert__Reg1_0__Tie0_1_1__Reg1_1,
  Convert__Reg1_0__Tie0_1_1__SImm6NonZero1_1,
  Convert__Reg1_0__Tie0_1_1__SImm10Lsb0000NonZero1_1,
  Convert__Reg1_0__Reg1_1__UImm10Lsb00NonZero1_2,
  Convert__Reg1_0__Tie0_1_1__SImm61_1,
  Convert__Reg1_0__SImm9Lsb01_1,
  Convert_NoOperands,
  Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1,
  Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1,
  Convert__Reg1_0__Reg1_3__UImm7Lsb001_1,
  Convert__Reg1_0__Reg1_3__UImm8Lsb001_1,
  Convert__SImm12Lsb01_0,
  Convert__Reg1_0,
  Convert__Reg1_0__SImm61_1,
  Convert__Reg1_0__CLUIImm1_1,
  Convert__Reg1_0__Reg1_1,
  Convert__Reg1_0__Tie0_1_1__UImmLog2XLenNonZero1_1,
  Convert__BareSymbol1_0,
  Convert__regX0__CSRSystemRegister1_0__Reg1_1,
  Convert__regX0__CSRSystemRegister1_0__UImm51_1,
  Convert__Reg1_0__CSRSystemRegister1_1__regX0,
  Convert__Reg1_0__CSRSystemRegister1_1__Reg1_2,
  Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2,
  Convert__Reg1_0__Reg1_1__Reg1_1,
  Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7,
  Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3,
  Convert__Reg1_0__Reg1_1__imm_95_7,
  Convert__Reg1_0__Reg1_1__FRMArg1_2,
  Convert__imm_95_15__imm_95_15,
  Convert__FenceArg1_0__FenceArg1_1,
  Convert__Reg1_0__Reg1_2__Reg1_1,
  Convert__Reg1_0__Reg1_3__SImm121_1,
  Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7,
  Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4,
  Convert__Reg1_0__imm_95_3__regX0,
  Convert__Reg1_0__imm_95_1__regX0,
  Convert__Reg1_0__imm_95_2__regX0,
  Convert__regX0__imm_95_3__Reg1_0,
  Convert__Reg1_0__imm_95_3__Reg1_1,
  Convert__regX0__imm_95_1__Reg1_0,
  Convert__Reg1_0__imm_95_1__Reg1_1,
  Convert__regX0__imm_95_1__UImm51_0,
  Convert__Reg1_0__imm_95_1__UImm51_1,
  Convert__regX0__imm_95_2__Reg1_0,
  Convert__Reg1_0__imm_95_2__Reg1_1,
  Convert__regX0__imm_95_2__UImm51_0,
  Convert__Reg1_0__imm_95_2__UImm51_1,
  Convert__regX0__SImm21Lsb0JAL1_0,
  Convert__regX1__SImm21Lsb0JAL1_0,
  Convert__Reg1_0__SImm21Lsb0JAL1_1,
  Convert__regX1__Reg1_0__imm_95_0,
  Convert__regX0__Reg1_0__imm_95_0,
  Convert__Reg1_0__ImmXLen1_1,
  Convert__Reg1_0__BareSymbol1_1,
  Convert__Reg1_0__Reg1_2,
  Convert__Reg1_0__UImm20LUI1_1,
  Convert__imm_95_0__imm_95_0,
  Convert__Reg1_0__Reg1_1__imm_95_0,
  Convert__Reg1_0__regX0__Reg1_1,
  Convert__regX0__regX0__imm_95_0,
  Convert__Reg1_0__Reg1_1__imm_95__MINUS_1,
  Convert__Reg1_0__imm_95_3072__regX0,
  Convert__Reg1_0__imm_95_3200__regX0,
  Convert__Reg1_0__imm_95_3074__regX0,
  Convert__Reg1_0__imm_95_3202__regX0,
  Convert__Reg1_0__imm_95_3073__regX0,
  Convert__Reg1_0__imm_95_3201__regX0,
  Convert__regX0__regX1__imm_95_0,
  Convert__Reg1_0__Reg1_1__imm_95_1,
  Convert__regX0__regX0,
  Convert__Reg1_0__regX0,
  Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2,
  Convert__Reg1_0__Reg1_1__UImm51_2,
  Convert__Reg1_0__Reg1_1__regX0,
  CVT_NUM_SIGNATURES
};

} // end anonymous namespace

static const uint8_t ConversionTable[CVT_NUM_SIGNATURES][11] = {
  // Convert__Reg1_0__Reg1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm121_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_3__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__UImm20AUIPC1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__SImm13Lsb01_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__regX0__SImm13Lsb01_1
  { CVT_95_Reg, 1, CVT_regX0, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_1__Reg1_0__SImm13Lsb01_2
  { CVT_95_Reg, 2, CVT_95_Reg, 1, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__regX0__Reg1_0__SImm13Lsb01_1
  { CVT_regX0, 0, CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__SImm6NonZero1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__SImm10Lsb0000NonZero1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm10Lsb00NonZero1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__SImm61_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__SImm9Lsb01_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert_NoOperands
  { CVT_Done },
  // Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_3__UImm7Lsb001_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_3__UImm8Lsb001_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__SImm12Lsb01_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0
  { CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__SImm61_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__CLUIImm1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Tie0_1_1__UImmLog2XLenNonZero1_1
  { CVT_95_Reg, 1, CVT_Tied, Tie0_1_1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__BareSymbol1_0
  { CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__regX0__CSRSystemRegister1_0__Reg1_1
  { CVT_regX0, 0, CVT_95_addCSRSystemRegisterOperands, 1, CVT_95_Reg, 2, CVT_Done },
  // Convert__regX0__CSRSystemRegister1_0__UImm51_1
  { CVT_regX0, 0, CVT_95_addCSRSystemRegisterOperands, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__CSRSystemRegister1_1__regX0
  { CVT_95_Reg, 1, CVT_95_addCSRSystemRegisterOperands, 2, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__CSRSystemRegister1_1__Reg1_2
  { CVT_95_Reg, 1, CVT_95_addCSRSystemRegisterOperands, 2, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_95_addCSRSystemRegisterOperands, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_addFRMArgOperands, 4, CVT_Done },
  // Convert__Reg1_0__Reg1_1__imm_95_7
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__FRMArg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addFRMArgOperands, 3, CVT_Done },
  // Convert__imm_95_15__imm_95_15
  { CVT_imm_95_15, 0, CVT_imm_95_15, 0, CVT_Done },
  // Convert__FenceArg1_0__FenceArg1_1
  { CVT_95_addFenceArgOperands, 1, CVT_95_addFenceArgOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_2__Reg1_1
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_95_Reg, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_3__SImm121_1
  { CVT_95_Reg, 1, CVT_95_Reg, 4, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_imm_95_7, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_Reg, 3, CVT_95_Reg, 4, CVT_95_addFRMArgOperands, 5, CVT_Done },
  // Convert__Reg1_0__imm_95_3__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_1__regX0
  { CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_2__regX0
  { CVT_95_Reg, 1, CVT_imm_95_2, 0, CVT_regX0, 0, CVT_Done },
  // Convert__regX0__imm_95_3__Reg1_0
  { CVT_regX0, 0, CVT_imm_95_3, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_3__Reg1_1
  { CVT_95_Reg, 1, CVT_imm_95_3, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__regX0__imm_95_1__Reg1_0
  { CVT_regX0, 0, CVT_imm_95_1, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_1__Reg1_1
  { CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__regX0__imm_95_1__UImm51_0
  { CVT_regX0, 0, CVT_imm_95_1, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_1__UImm51_1
  { CVT_95_Reg, 1, CVT_imm_95_1, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__regX0__imm_95_2__Reg1_0
  { CVT_regX0, 0, CVT_imm_95_2, 0, CVT_95_Reg, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_2__Reg1_1
  { CVT_95_Reg, 1, CVT_imm_95_2, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__regX0__imm_95_2__UImm51_0
  { CVT_regX0, 0, CVT_imm_95_2, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__imm_95_2__UImm51_1
  { CVT_95_Reg, 1, CVT_imm_95_2, 0, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__regX0__SImm21Lsb0JAL1_0
  { CVT_regX0, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__regX1__SImm21Lsb0JAL1_0
  { CVT_regX1, 0, CVT_95_addImmOperands, 1, CVT_Done },
  // Convert__Reg1_0__SImm21Lsb0JAL1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__regX1__Reg1_0__imm_95_0
  { CVT_regX1, 0, CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__regX0__Reg1_0__imm_95_0
  { CVT_regX0, 0, CVT_95_Reg, 1, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__ImmXLen1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__BareSymbol1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__Reg1_0__Reg1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 3, CVT_Done },
  // Convert__Reg1_0__UImm20LUI1_1
  { CVT_95_Reg, 1, CVT_95_addImmOperands, 2, CVT_Done },
  // Convert__imm_95_0__imm_95_0
  { CVT_imm_95_0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__imm_95_0
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__regX0__Reg1_1
  { CVT_95_Reg, 1, CVT_regX0, 0, CVT_95_Reg, 2, CVT_Done },
  // Convert__regX0__regX0__imm_95_0
  { CVT_regX0, 0, CVT_regX0, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__imm_95__MINUS_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_imm_95__MINUS_1, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3072__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3072, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3200__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3200, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3074__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3074, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3202__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3202, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3073__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3073, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__imm_95_3201__regX0
  { CVT_95_Reg, 1, CVT_imm_95_3201, 0, CVT_regX0, 0, CVT_Done },
  // Convert__regX0__regX1__imm_95_0
  { CVT_regX0, 0, CVT_regX1, 0, CVT_imm_95_0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__imm_95_1
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_imm_95_1, 0, CVT_Done },
  // Convert__regX0__regX0
  { CVT_regX0, 0, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__regX0
  { CVT_95_Reg, 1, CVT_regX0, 0, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__UImm51_2
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_95_addImmOperands, 3, CVT_Done },
  // Convert__Reg1_0__Reg1_1__regX0
  { CVT_95_Reg, 1, CVT_95_Reg, 2, CVT_regX0, 0, CVT_Done },
};

void RISCVAsmParser::
convertToMCInst(unsigned Kind, MCInst &Inst, unsigned Opcode,
                const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  unsigned OpIdx;
  Inst.setOpcode(Opcode);
  for (const uint8_t *p = Converter; *p; p+= 2) {
    OpIdx = *(p + 1);
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_Tied: {
      assert(OpIdx < (size_t)(std::end(TiedAsmOperandTable) -
                          std::begin(TiedAsmOperandTable)) &&
             "Tied operand not found");
      unsigned TiedResOpnd = TiedAsmOperandTable[OpIdx][0];
      if (TiedResOpnd != (uint8_t) -1)
        Inst.addOperand(Inst.getOperand(TiedResOpnd));
      break;
    }
    case CVT_95_Reg:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addRegOperands(Inst, 1);
      break;
    case CVT_95_addImmOperands:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addImmOperands(Inst, 1);
      break;
    case CVT_regX0:
      Inst.addOperand(MCOperand::createReg(RISCV::X0));
      break;
    case CVT_95_addCSRSystemRegisterOperands:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addCSRSystemRegisterOperands(Inst, 1);
      break;
    case CVT_imm_95_7:
      Inst.addOperand(MCOperand::createImm(7));
      break;
    case CVT_95_addFRMArgOperands:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addFRMArgOperands(Inst, 1);
      break;
    case CVT_imm_95_15:
      Inst.addOperand(MCOperand::createImm(15));
      break;
    case CVT_95_addFenceArgOperands:
      static_cast<RISCVOperand&>(*Operands[OpIdx]).addFenceArgOperands(Inst, 1);
      break;
    case CVT_imm_95_3:
      Inst.addOperand(MCOperand::createImm(3));
      break;
    case CVT_imm_95_1:
      Inst.addOperand(MCOperand::createImm(1));
      break;
    case CVT_imm_95_2:
      Inst.addOperand(MCOperand::createImm(2));
      break;
    case CVT_regX1:
      Inst.addOperand(MCOperand::createReg(RISCV::X1));
      break;
    case CVT_imm_95_0:
      Inst.addOperand(MCOperand::createImm(0));
      break;
    case CVT_imm_95__MINUS_1:
      Inst.addOperand(MCOperand::createImm(-1));
      break;
    case CVT_imm_95_3072:
      Inst.addOperand(MCOperand::createImm(3072));
      break;
    case CVT_imm_95_3200:
      Inst.addOperand(MCOperand::createImm(3200));
      break;
    case CVT_imm_95_3074:
      Inst.addOperand(MCOperand::createImm(3074));
      break;
    case CVT_imm_95_3202:
      Inst.addOperand(MCOperand::createImm(3202));
      break;
    case CVT_imm_95_3073:
      Inst.addOperand(MCOperand::createImm(3073));
      break;
    case CVT_imm_95_3201:
      Inst.addOperand(MCOperand::createImm(3201));
      break;
    }
  }
}

void RISCVAsmParser::
convertToMapAndConstraints(unsigned Kind,
                           const OperandVector &Operands) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  unsigned NumMCOperands = 0;
  const uint8_t *Converter = ConversionTable[Kind];
  for (const uint8_t *p = Converter; *p; p+= 2) {
    switch (*p) {
    default: llvm_unreachable("invalid conversion entry!");
    case CVT_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      ++NumMCOperands;
      break;
    case CVT_Tied:
      ++NumMCOperands;
      break;
    case CVT_95_Reg:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("r");
      NumMCOperands += 1;
      break;
    case CVT_95_addImmOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_regX0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_95_addCSRSystemRegisterOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_7:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addFRMArgOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_15:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_95_addFenceArgOperands:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      NumMCOperands += 1;
      break;
    case CVT_imm_95_3:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_2:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_regX1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("m");
      ++NumMCOperands;
      break;
    case CVT_imm_95_0:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95__MINUS_1:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3072:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3200:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3074:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3202:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3073:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    case CVT_imm_95_3201:
      Operands[*(p + 1)]->setMCOperandNum(NumMCOperands);
      Operands[*(p + 1)]->setConstraint("");
      ++NumMCOperands;
      break;
    }
  }
}

namespace {

/// MatchClassKind - The kinds of classes which participate in
/// instruction matching.
enum MatchClassKind {
  InvalidMatchClass = 0,
  OptionalMatchClass = 1,
  MCK__40_, // '('
  MCK__41_, // ')'
  MCK_LAST_TOKEN = MCK__41_,
  MCK_SP, // register class 'SP'
  MCK_Reg6, // derived register class
  MCK_FPR32C, // register class 'FPR32C'
  MCK_FPR64C, // register class 'FPR64C'
  MCK_GPRC, // register class 'GPRC'
  MCK_GPRTC, // register class 'GPRTC'
  MCK_GPRNoX0X2, // register class 'GPRNoX0X2'
  MCK_GPRNoX0, // register class 'GPRNoX0'
  MCK_FPR32, // register class 'FPR32'
  MCK_FPR64, // register class 'FPR64'
  MCK_GPR, // register class 'GPR'
  MCK_LAST_REGISTER = MCK_GPR,
  MCK_BareSymbol, // user defined class 'BareSymbol'
  MCK_CLUIImm, // user defined class 'CLUIImmAsmOperand'
  MCK_CSRSystemRegister, // user defined class 'CSRSystemRegister'
  MCK_FRMArg, // user defined class 'FRMArg'
  MCK_FenceArg, // user defined class 'FenceArg'
  MCK_Imm, // user defined class 'ImmAsmOperand'
  MCK_SImm21Lsb0JAL, // user defined class 'Simm21Lsb0JALAsmOperand'
  MCK_UImmLog2XLen, // user defined class 'UImmLog2XLenAsmOperand'
  MCK_UImmLog2XLenNonZero, // user defined class 'UImmLog2XLenNonZeroAsmOperand'
  MCK_SImm6, // user defined class 'anonymous_1446'
  MCK_SImm6NonZero, // user defined class 'anonymous_1447'
  MCK_UImm7Lsb00, // user defined class 'anonymous_1448'
  MCK_UImm8Lsb00, // user defined class 'anonymous_1449'
  MCK_UImm8Lsb000, // user defined class 'anonymous_1450'
  MCK_SImm9Lsb0, // user defined class 'anonymous_1451'
  MCK_UImm9Lsb000, // user defined class 'anonymous_1452'
  MCK_UImm10Lsb00NonZero, // user defined class 'anonymous_1453'
  MCK_SImm10Lsb0000NonZero, // user defined class 'anonymous_1454'
  MCK_SImm12Lsb0, // user defined class 'anonymous_1455'
  MCK_UImm5, // user defined class 'anonymous_950'
  MCK_SImm12, // user defined class 'anonymous_951'
  MCK_SImm13Lsb0, // user defined class 'anonymous_952'
  MCK_UImm20LUI, // user defined class 'anonymous_953'
  MCK_UImm20AUIPC, // user defined class 'anonymous_954'
  MCK_ImmXLen, // user defined class 'anonymous_955'
  NumMatchClassKinds
};

}

static unsigned getDiagKindFromRegisterClass(MatchClassKind RegisterClass) {
  return MCTargetAsmParser::Match_InvalidOperand;
}

static MatchClassKind matchTokenString(StringRef Name) {
  switch (Name.size()) {
  default: break;
  case 1:	 // 2 strings to match.
    switch (Name[0]) {
    default: break;
    case '(':	 // 1 string to match.
      return MCK__40_;	 // "("
    case ')':	 // 1 string to match.
      return MCK__41_;	 // ")"
    }
    break;
  }
  return InvalidMatchClass;
}

/// isSubclass - Compute whether \p A is a subclass of \p B.
static bool isSubclass(MatchClassKind A, MatchClassKind B) {
  if (A == B)
    return true;

  switch (A) {
  default:
    return false;

  case MCK_SP:
    switch (B) {
    default: return false;
    case MCK_GPRNoX0: return true;
    case MCK_GPR: return true;
    }

  case MCK_Reg6:
    switch (B) {
    default: return false;
    case MCK_GPRC: return true;
    case MCK_GPRTC: return true;
    case MCK_GPRNoX0X2: return true;
    case MCK_GPRNoX0: return true;
    case MCK_GPR: return true;
    }

  case MCK_FPR32C:
    return B == MCK_FPR32;

  case MCK_FPR64C:
    return B == MCK_FPR64;

  case MCK_GPRC:
    switch (B) {
    default: return false;
    case MCK_GPRNoX0X2: return true;
    case MCK_GPRNoX0: return true;
    case MCK_GPR: return true;
    }

  case MCK_GPRTC:
    switch (B) {
    default: return false;
    case MCK_GPRNoX0X2: return true;
    case MCK_GPRNoX0: return true;
    case MCK_GPR: return true;
    }

  case MCK_GPRNoX0X2:
    switch (B) {
    default: return false;
    case MCK_GPRNoX0: return true;
    case MCK_GPR: return true;
    }

  case MCK_GPRNoX0:
    return B == MCK_GPR;
  }
}

static unsigned validateOperandClass(MCParsedAsmOperand &GOp, MatchClassKind Kind) {
  RISCVOperand &Operand = (RISCVOperand&)GOp;
  if (Kind == InvalidMatchClass)
    return MCTargetAsmParser::Match_InvalidOperand;

  if (Operand.isToken() && Kind <= MCK_LAST_TOKEN)
    return isSubclass(matchTokenString(Operand.getToken()), Kind) ?
             MCTargetAsmParser::Match_Success :
             MCTargetAsmParser::Match_InvalidOperand;

  switch (Kind) {
  default: break;
  // 'BareSymbol' class
  case MCK_BareSymbol: {
    DiagnosticPredicate DP(Operand.isBareSymbol());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidBareSymbol;
    break;
    }
  // 'CLUIImm' class
  case MCK_CLUIImm: {
    DiagnosticPredicate DP(Operand.isCLUIImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidCLUIImm;
    break;
    }
  // 'CSRSystemRegister' class
  case MCK_CSRSystemRegister: {
    DiagnosticPredicate DP(Operand.isCSRSystemRegister());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidCSRSystemRegister;
    break;
    }
  // 'FRMArg' class
  case MCK_FRMArg: {
    DiagnosticPredicate DP(Operand.isFRMArg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidFRMArg;
    break;
    }
  // 'FenceArg' class
  case MCK_FenceArg: {
    DiagnosticPredicate DP(Operand.isFenceArg());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidFenceArg;
    break;
    }
  // 'Imm' class
  case MCK_Imm: {
    DiagnosticPredicate DP(Operand.isImm());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    break;
    }
  // 'SImm21Lsb0JAL' class
  case MCK_SImm21Lsb0JAL: {
    DiagnosticPredicate DP(Operand.isSImm21Lsb0JAL());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm21Lsb0JAL;
    break;
    }
  // 'UImmLog2XLen' class
  case MCK_UImmLog2XLen: {
    DiagnosticPredicate DP(Operand.isUImmLog2XLen());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImmLog2XLen;
    break;
    }
  // 'UImmLog2XLenNonZero' class
  case MCK_UImmLog2XLenNonZero: {
    DiagnosticPredicate DP(Operand.isUImmLog2XLenNonZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImmLog2XLenNonZero;
    break;
    }
  // 'SImm6' class
  case MCK_SImm6: {
    DiagnosticPredicate DP(Operand.isSImm6());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm6;
    break;
    }
  // 'SImm6NonZero' class
  case MCK_SImm6NonZero: {
    DiagnosticPredicate DP(Operand.isSImm6NonZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm6NonZero;
    break;
    }
  // 'UImm7Lsb00' class
  case MCK_UImm7Lsb00: {
    DiagnosticPredicate DP(Operand.isUImm7Lsb00());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm7Lsb00;
    break;
    }
  // 'UImm8Lsb00' class
  case MCK_UImm8Lsb00: {
    DiagnosticPredicate DP(Operand.isUImm8Lsb00());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm8Lsb00;
    break;
    }
  // 'UImm8Lsb000' class
  case MCK_UImm8Lsb000: {
    DiagnosticPredicate DP(Operand.isUImm8Lsb000());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm8Lsb000;
    break;
    }
  // 'SImm9Lsb0' class
  case MCK_SImm9Lsb0: {
    DiagnosticPredicate DP(Operand.isSImm9Lsb0());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm9Lsb0;
    break;
    }
  // 'UImm9Lsb000' class
  case MCK_UImm9Lsb000: {
    DiagnosticPredicate DP(Operand.isUImm9Lsb000());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm9Lsb000;
    break;
    }
  // 'UImm10Lsb00NonZero' class
  case MCK_UImm10Lsb00NonZero: {
    DiagnosticPredicate DP(Operand.isUImm10Lsb00NonZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm10Lsb00NonZero;
    break;
    }
  // 'SImm10Lsb0000NonZero' class
  case MCK_SImm10Lsb0000NonZero: {
    DiagnosticPredicate DP(Operand.isSImm10Lsb0000NonZero());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm10Lsb0000NonZero;
    break;
    }
  // 'SImm12Lsb0' class
  case MCK_SImm12Lsb0: {
    DiagnosticPredicate DP(Operand.isSImm12Lsb0());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm12Lsb0;
    break;
    }
  // 'UImm5' class
  case MCK_UImm5: {
    DiagnosticPredicate DP(Operand.isUImm5());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm5;
    break;
    }
  // 'SImm12' class
  case MCK_SImm12: {
    DiagnosticPredicate DP(Operand.isSImm12());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm12;
    break;
    }
  // 'SImm13Lsb0' class
  case MCK_SImm13Lsb0: {
    DiagnosticPredicate DP(Operand.isSImm13Lsb0());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidSImm13Lsb0;
    break;
    }
  // 'UImm20LUI' class
  case MCK_UImm20LUI: {
    DiagnosticPredicate DP(Operand.isUImm20LUI());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm20LUI;
    break;
    }
  // 'UImm20AUIPC' class
  case MCK_UImm20AUIPC: {
    DiagnosticPredicate DP(Operand.isUImm20AUIPC());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidUImm20AUIPC;
    break;
    }
  // 'ImmXLen' class
  case MCK_ImmXLen: {
    DiagnosticPredicate DP(Operand.isImmXLen());
    if (DP.isMatch())
      return MCTargetAsmParser::Match_Success;
    if (DP.isNearMatch())
      return RISCVAsmParser::Match_InvalidImmXLen;
    break;
    }
  } // end switch (Kind)

  if (Operand.isReg()) {
    MatchClassKind OpKind;
    switch (Operand.getReg()) {
    default: OpKind = InvalidMatchClass; break;
    case RISCV::X0: OpKind = MCK_GPR; break;
    case RISCV::X1: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X2: OpKind = MCK_SP; break;
    case RISCV::X3: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X4: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X5: OpKind = MCK_GPRTC; break;
    case RISCV::X6: OpKind = MCK_GPRTC; break;
    case RISCV::X7: OpKind = MCK_GPRTC; break;
    case RISCV::X8: OpKind = MCK_GPRC; break;
    case RISCV::X9: OpKind = MCK_GPRC; break;
    case RISCV::X10: OpKind = MCK_Reg6; break;
    case RISCV::X11: OpKind = MCK_Reg6; break;
    case RISCV::X12: OpKind = MCK_Reg6; break;
    case RISCV::X13: OpKind = MCK_Reg6; break;
    case RISCV::X14: OpKind = MCK_Reg6; break;
    case RISCV::X15: OpKind = MCK_Reg6; break;
    case RISCV::X16: OpKind = MCK_GPRTC; break;
    case RISCV::X17: OpKind = MCK_GPRTC; break;
    case RISCV::X18: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X19: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X20: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X21: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X22: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X23: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X24: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X25: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X26: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X27: OpKind = MCK_GPRNoX0X2; break;
    case RISCV::X28: OpKind = MCK_GPRTC; break;
    case RISCV::X29: OpKind = MCK_GPRTC; break;
    case RISCV::X30: OpKind = MCK_GPRTC; break;
    case RISCV::X31: OpKind = MCK_GPRTC; break;
    case RISCV::F0_32: OpKind = MCK_FPR32; break;
    case RISCV::F1_32: OpKind = MCK_FPR32; break;
    case RISCV::F2_32: OpKind = MCK_FPR32; break;
    case RISCV::F3_32: OpKind = MCK_FPR32; break;
    case RISCV::F4_32: OpKind = MCK_FPR32; break;
    case RISCV::F5_32: OpKind = MCK_FPR32; break;
    case RISCV::F6_32: OpKind = MCK_FPR32; break;
    case RISCV::F7_32: OpKind = MCK_FPR32; break;
    case RISCV::F8_32: OpKind = MCK_FPR32C; break;
    case RISCV::F9_32: OpKind = MCK_FPR32C; break;
    case RISCV::F10_32: OpKind = MCK_FPR32C; break;
    case RISCV::F11_32: OpKind = MCK_FPR32C; break;
    case RISCV::F12_32: OpKind = MCK_FPR32C; break;
    case RISCV::F13_32: OpKind = MCK_FPR32C; break;
    case RISCV::F14_32: OpKind = MCK_FPR32C; break;
    case RISCV::F15_32: OpKind = MCK_FPR32C; break;
    case RISCV::F16_32: OpKind = MCK_FPR32; break;
    case RISCV::F17_32: OpKind = MCK_FPR32; break;
    case RISCV::F18_32: OpKind = MCK_FPR32; break;
    case RISCV::F19_32: OpKind = MCK_FPR32; break;
    case RISCV::F20_32: OpKind = MCK_FPR32; break;
    case RISCV::F21_32: OpKind = MCK_FPR32; break;
    case RISCV::F22_32: OpKind = MCK_FPR32; break;
    case RISCV::F23_32: OpKind = MCK_FPR32; break;
    case RISCV::F24_32: OpKind = MCK_FPR32; break;
    case RISCV::F25_32: OpKind = MCK_FPR32; break;
    case RISCV::F26_32: OpKind = MCK_FPR32; break;
    case RISCV::F27_32: OpKind = MCK_FPR32; break;
    case RISCV::F28_32: OpKind = MCK_FPR32; break;
    case RISCV::F29_32: OpKind = MCK_FPR32; break;
    case RISCV::F30_32: OpKind = MCK_FPR32; break;
    case RISCV::F31_32: OpKind = MCK_FPR32; break;
    case RISCV::F0_64: OpKind = MCK_FPR64; break;
    case RISCV::F1_64: OpKind = MCK_FPR64; break;
    case RISCV::F2_64: OpKind = MCK_FPR64; break;
    case RISCV::F3_64: OpKind = MCK_FPR64; break;
    case RISCV::F4_64: OpKind = MCK_FPR64; break;
    case RISCV::F5_64: OpKind = MCK_FPR64; break;
    case RISCV::F6_64: OpKind = MCK_FPR64; break;
    case RISCV::F7_64: OpKind = MCK_FPR64; break;
    case RISCV::F8_64: OpKind = MCK_FPR64C; break;
    case RISCV::F9_64: OpKind = MCK_FPR64C; break;
    case RISCV::F10_64: OpKind = MCK_FPR64C; break;
    case RISCV::F11_64: OpKind = MCK_FPR64C; break;
    case RISCV::F12_64: OpKind = MCK_FPR64C; break;
    case RISCV::F13_64: OpKind = MCK_FPR64C; break;
    case RISCV::F14_64: OpKind = MCK_FPR64C; break;
    case RISCV::F15_64: OpKind = MCK_FPR64C; break;
    case RISCV::F16_64: OpKind = MCK_FPR64; break;
    case RISCV::F17_64: OpKind = MCK_FPR64; break;
    case RISCV::F18_64: OpKind = MCK_FPR64; break;
    case RISCV::F19_64: OpKind = MCK_FPR64; break;
    case RISCV::F20_64: OpKind = MCK_FPR64; break;
    case RISCV::F21_64: OpKind = MCK_FPR64; break;
    case RISCV::F22_64: OpKind = MCK_FPR64; break;
    case RISCV::F23_64: OpKind = MCK_FPR64; break;
    case RISCV::F24_64: OpKind = MCK_FPR64; break;
    case RISCV::F25_64: OpKind = MCK_FPR64; break;
    case RISCV::F26_64: OpKind = MCK_FPR64; break;
    case RISCV::F27_64: OpKind = MCK_FPR64; break;
    case RISCV::F28_64: OpKind = MCK_FPR64; break;
    case RISCV::F29_64: OpKind = MCK_FPR64; break;
    case RISCV::F30_64: OpKind = MCK_FPR64; break;
    case RISCV::F31_64: OpKind = MCK_FPR64; break;
    }
    return isSubclass(OpKind, Kind) ? (unsigned)MCTargetAsmParser::Match_Success :
                                      getDiagKindFromRegisterClass(Kind);
  }

  if (Kind > MCK_LAST_TOKEN && Kind <= MCK_LAST_REGISTER)
    return getDiagKindFromRegisterClass(Kind);

  return MCTargetAsmParser::Match_InvalidOperand;
}

#ifndef NDEBUG
const char *getMatchClassName(MatchClassKind Kind) {
  switch (Kind) {
  case InvalidMatchClass: return "InvalidMatchClass";
  case OptionalMatchClass: return "OptionalMatchClass";
  case MCK__40_: return "MCK__40_";
  case MCK__41_: return "MCK__41_";
  case MCK_SP: return "MCK_SP";
  case MCK_Reg6: return "MCK_Reg6";
  case MCK_FPR32C: return "MCK_FPR32C";
  case MCK_FPR64C: return "MCK_FPR64C";
  case MCK_GPRC: return "MCK_GPRC";
  case MCK_GPRTC: return "MCK_GPRTC";
  case MCK_GPRNoX0X2: return "MCK_GPRNoX0X2";
  case MCK_GPRNoX0: return "MCK_GPRNoX0";
  case MCK_FPR32: return "MCK_FPR32";
  case MCK_FPR64: return "MCK_FPR64";
  case MCK_GPR: return "MCK_GPR";
  case MCK_BareSymbol: return "MCK_BareSymbol";
  case MCK_CLUIImm: return "MCK_CLUIImm";
  case MCK_CSRSystemRegister: return "MCK_CSRSystemRegister";
  case MCK_FRMArg: return "MCK_FRMArg";
  case MCK_FenceArg: return "MCK_FenceArg";
  case MCK_Imm: return "MCK_Imm";
  case MCK_SImm21Lsb0JAL: return "MCK_SImm21Lsb0JAL";
  case MCK_UImmLog2XLen: return "MCK_UImmLog2XLen";
  case MCK_UImmLog2XLenNonZero: return "MCK_UImmLog2XLenNonZero";
  case MCK_SImm6: return "MCK_SImm6";
  case MCK_SImm6NonZero: return "MCK_SImm6NonZero";
  case MCK_UImm7Lsb00: return "MCK_UImm7Lsb00";
  case MCK_UImm8Lsb00: return "MCK_UImm8Lsb00";
  case MCK_UImm8Lsb000: return "MCK_UImm8Lsb000";
  case MCK_SImm9Lsb0: return "MCK_SImm9Lsb0";
  case MCK_UImm9Lsb000: return "MCK_UImm9Lsb000";
  case MCK_UImm10Lsb00NonZero: return "MCK_UImm10Lsb00NonZero";
  case MCK_SImm10Lsb0000NonZero: return "MCK_SImm10Lsb0000NonZero";
  case MCK_SImm12Lsb0: return "MCK_SImm12Lsb0";
  case MCK_UImm5: return "MCK_UImm5";
  case MCK_SImm12: return "MCK_SImm12";
  case MCK_SImm13Lsb0: return "MCK_SImm13Lsb0";
  case MCK_UImm20LUI: return "MCK_UImm20LUI";
  case MCK_UImm20AUIPC: return "MCK_UImm20AUIPC";
  case MCK_ImmXLen: return "MCK_ImmXLen";
  case NumMatchClassKinds: return "NumMatchClassKinds";
  }
  llvm_unreachable("unhandled MatchClassKind!");
}

#endif // NDEBUG
uint64_t RISCVAsmParser::
ComputeAvailableFeatures(const FeatureBitset& FB) const {
  uint64_t Features = 0;
  if ((FB[RISCV::FeatureStdExtM]))
    Features |= Feature_HasStdExtM;
  if ((FB[RISCV::FeatureStdExtA]))
    Features |= Feature_HasStdExtA;
  if ((FB[RISCV::FeatureStdExtF]))
    Features |= Feature_HasStdExtF;
  if ((FB[RISCV::FeatureStdExtD]))
    Features |= Feature_HasStdExtD;
  if ((FB[RISCV::FeatureStdExtC]))
    Features |= Feature_HasStdExtC;
  if ((FB[RISCV::Feature64Bit]))
    Features |= Feature_IsRV64;
  if ((!FB[RISCV::Feature64Bit]))
    Features |= Feature_IsRV32;
  return Features;
}

static bool checkAsmTiedOperandConstraints(const RISCVAsmParser&AsmParser,
                               unsigned Kind,
                               const OperandVector &Operands,
                               uint64_t &ErrorInfo) {
  assert(Kind < CVT_NUM_SIGNATURES && "Invalid signature!");
  const uint8_t *Converter = ConversionTable[Kind];
  for (const uint8_t *p = Converter; *p; p+= 2) {
    switch (*p) {
    case CVT_Tied: {
      unsigned OpIdx = *(p+1);
      assert(OpIdx < (size_t)(std::end(TiedAsmOperandTable) -
                              std::begin(TiedAsmOperandTable)) &&
             "Tied operand not found");
      unsigned OpndNum1 = TiedAsmOperandTable[OpIdx][1];
      unsigned OpndNum2 = TiedAsmOperandTable[OpIdx][2];
      if (OpndNum1 != OpndNum2) {
        auto &SrcOp1 = Operands[OpndNum1];
        auto &SrcOp2 = Operands[OpndNum2];
        if (SrcOp1->isReg() && SrcOp2->isReg()) {
          if (!AsmParser.regsEqual(*SrcOp1, *SrcOp2)) {
            ErrorInfo = OpndNum2;
            return false;
          }
        }
      }
      break;
    }
    default:
      break;
    }
  }
  return true;
}

static const char *const MnemonicTable =
    "\003add\004addi\005addiw\004addw\010amoadd.d\013amoadd.d.aq\015amoadd.d"
    ".aqrl\013amoadd.d.rl\010amoadd.w\013amoadd.w.aq\015amoadd.w.aqrl\013amo"
    "add.w.rl\010amoand.d\013amoand.d.aq\015amoand.d.aqrl\013amoand.d.rl\010"
    "amoand.w\013amoand.w.aq\015amoand.w.aqrl\013amoand.w.rl\010amomax.d\013"
    "amomax.d.aq\015amomax.d.aqrl\013amomax.d.rl\010amomax.w\013amomax.w.aq\015"
    "amomax.w.aqrl\013amomax.w.rl\tamomaxu.d\014amomaxu.d.aq\016amomaxu.d.aq"
    "rl\014amomaxu.d.rl\tamomaxu.w\014amomaxu.w.aq\016amomaxu.w.aqrl\014amom"
    "axu.w.rl\010amomin.d\013amomin.d.aq\015amomin.d.aqrl\013amomin.d.rl\010"
    "amomin.w\013amomin.w.aq\015amomin.w.aqrl\013amomin.w.rl\tamominu.d\014a"
    "mominu.d.aq\016amominu.d.aqrl\014amominu.d.rl\tamominu.w\014amominu.w.a"
    "q\016amominu.w.aqrl\014amominu.w.rl\007amoor.d\namoor.d.aq\014amoor.d.a"
    "qrl\namoor.d.rl\007amoor.w\namoor.w.aq\014amoor.w.aqrl\namoor.w.rl\tamo"
    "swap.d\014amoswap.d.aq\016amoswap.d.aqrl\014amoswap.d.rl\tamoswap.w\014"
    "amoswap.w.aq\016amoswap.w.aqrl\014amoswap.w.rl\010amoxor.d\013amoxor.d."
    "aq\015amoxor.d.aqrl\013amoxor.d.rl\010amoxor.w\013amoxor.w.aq\015amoxor"
    ".w.aqrl\013amoxor.w.rl\003and\004andi\005auipc\003beq\004beqz\003bge\004"
    "bgeu\004bgez\003bgt\004bgtu\004bgtz\003ble\004bleu\004blez\003blt\004bl"
    "tu\004bltz\003bne\004bnez\005c.add\006c.addi\nc.addi16sp\nc.addi4spn\007"
    "c.addiw\006c.addw\005c.and\006c.andi\006c.beqz\006c.bnez\010c.ebreak\005"
    "c.fld\007c.fldsp\005c.flw\007c.flwsp\005c.fsd\007c.fsdsp\005c.fsw\007c."
    "fswsp\003c.j\005c.jal\006c.jalr\004c.jr\004c.ld\006c.ldsp\004c.li\005c."
    "lui\004c.lw\006c.lwsp\004c.mv\005c.nop\004c.or\004c.sd\006c.sdsp\006c.s"
    "lli\006c.srai\006c.srli\005c.sub\006c.subw\004c.sw\006c.swsp\007c.unimp"
    "\005c.xor\004call\004csrc\005csrci\004csrr\005csrrc\006csrrci\005csrrs\006"
    "csrrsi\005csrrw\006csrrwi\004csrs\005csrsi\004csrw\005csrwi\003div\004d"
    "ivu\005divuw\004divw\006ebreak\005ecall\006fabs.d\006fabs.s\006fadd.d\006"
    "fadd.s\010fclass.d\010fclass.s\010fcvt.d.l\tfcvt.d.lu\010fcvt.d.s\010fc"
    "vt.d.w\tfcvt.d.wu\010fcvt.l.d\010fcvt.l.s\tfcvt.lu.d\tfcvt.lu.s\010fcvt"
    ".s.d\010fcvt.s.l\tfcvt.s.lu\010fcvt.s.w\tfcvt.s.wu\010fcvt.w.d\010fcvt."
    "w.s\tfcvt.wu.d\tfcvt.wu.s\006fdiv.d\006fdiv.s\005fence\007fence.i\tfenc"
    "e.tso\005feq.d\005feq.s\005fge.d\005fge.s\005fgt.d\005fgt.s\003fld\005f"
    "le.d\005fle.s\005flt.d\005flt.s\003flw\007fmadd.d\007fmadd.s\006fmax.d\006"
    "fmax.s\006fmin.d\006fmin.s\007fmsub.d\007fmsub.s\006fmul.d\006fmul.s\005"
    "fmv.d\007fmv.d.x\005fmv.s\007fmv.w.x\007fmv.x.d\007fmv.x.w\006fneg.d\006"
    "fneg.s\010fnmadd.d\010fnmadd.s\010fnmsub.d\010fnmsub.s\005frcsr\007frfl"
    "ags\004frrm\005fscsr\003fsd\007fsflags\010fsflagsi\007fsgnj.d\007fsgnj."
    "s\010fsgnjn.d\010fsgnjn.s\010fsgnjx.d\010fsgnjx.s\007fsqrt.d\007fsqrt.s"
    "\004fsrm\005fsrmi\006fsub.d\006fsub.s\003fsw\001j\003jal\004jalr\002jr\002"
    "lb\003lbu\002ld\002lh\003lhu\002li\003lla\004lr.d\007lr.d.aq\tlr.d.aqrl"
    "\007lr.d.rl\004lr.w\007lr.w.aq\tlr.w.aqrl\007lr.w.rl\003lui\002lw\003lw"
    "u\004mret\003mul\004mulh\006mulhsu\005mulhu\004mulw\002mv\003neg\004neg"
    "w\003nop\003not\002or\003ori\007rdcycle\010rdcycleh\trdinstret\nrdinstr"
    "eth\006rdtime\007rdtimeh\003rem\004remu\005remuw\004remw\003ret\002sb\004"
    "sc.d\007sc.d.aq\tsc.d.aqrl\007sc.d.rl\004sc.w\007sc.w.aq\tsc.w.aqrl\007"
    "sc.w.rl\002sd\004seqz\006sext.w\nsfence.vma\003sgt\004sgtu\004sgtz\002s"
    "h\003sll\004slli\005slliw\004sllw\003slt\004slti\005sltiu\004sltu\004sl"
    "tz\004snez\003sra\004srai\005sraiw\004sraw\004sret\003srl\004srli\005sr"
    "liw\004srlw\003sub\004subw\002sw\004tail\005unimp\004uret\003wfi\003xor"
    "\004xori";

namespace {
  struct MatchEntry {
    uint16_t Mnemonic;
    uint16_t Opcode;
    uint16_t ConvertFn;
    uint8_t RequiredFeatures;
    uint8_t Classes[5];
    StringRef getMnemonic() const {
      return StringRef(MnemonicTable + Mnemonic + 1,
                       MnemonicTable[Mnemonic]);
    }
  };

  // Predicate for searching for an opcode.
  struct LessOpcode {
    bool operator()(const MatchEntry &LHS, StringRef RHS) {
      return LHS.getMnemonic() < RHS;
    }
    bool operator()(StringRef LHS, const MatchEntry &RHS) {
      return LHS < RHS.getMnemonic();
    }
    bool operator()(const MatchEntry &LHS, const MatchEntry &RHS) {
      return LHS.getMnemonic() < RHS.getMnemonic();
    }
  };
} // end anonymous namespace.

static const MatchEntry MatchTable0[] = {
  { 0 /* add */, RISCV::ADD, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 0 /* add */, RISCV::ADDI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 4 /* addi */, RISCV::ADDI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 9 /* addiw */, RISCV::ADDIW, Convert__Reg1_0__Reg1_1__SImm121_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 15 /* addw */, RISCV::ADDW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 15 /* addw */, RISCV::ADDIW, Convert__Reg1_0__Reg1_1__SImm121_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 20 /* amoadd.d */, RISCV::AMOADD_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 29 /* amoadd.d.aq */, RISCV::AMOADD_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 41 /* amoadd.d.aqrl */, RISCV::AMOADD_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 55 /* amoadd.d.rl */, RISCV::AMOADD_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 67 /* amoadd.w */, RISCV::AMOADD_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 76 /* amoadd.w.aq */, RISCV::AMOADD_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 88 /* amoadd.w.aqrl */, RISCV::AMOADD_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 102 /* amoadd.w.rl */, RISCV::AMOADD_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 114 /* amoand.d */, RISCV::AMOAND_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 123 /* amoand.d.aq */, RISCV::AMOAND_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 135 /* amoand.d.aqrl */, RISCV::AMOAND_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 149 /* amoand.d.rl */, RISCV::AMOAND_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 161 /* amoand.w */, RISCV::AMOAND_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 170 /* amoand.w.aq */, RISCV::AMOAND_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 182 /* amoand.w.aqrl */, RISCV::AMOAND_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 196 /* amoand.w.rl */, RISCV::AMOAND_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 208 /* amomax.d */, RISCV::AMOMAX_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 217 /* amomax.d.aq */, RISCV::AMOMAX_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 229 /* amomax.d.aqrl */, RISCV::AMOMAX_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 243 /* amomax.d.rl */, RISCV::AMOMAX_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 255 /* amomax.w */, RISCV::AMOMAX_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 264 /* amomax.w.aq */, RISCV::AMOMAX_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 276 /* amomax.w.aqrl */, RISCV::AMOMAX_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 290 /* amomax.w.rl */, RISCV::AMOMAX_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 302 /* amomaxu.d */, RISCV::AMOMAXU_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 312 /* amomaxu.d.aq */, RISCV::AMOMAXU_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 325 /* amomaxu.d.aqrl */, RISCV::AMOMAXU_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 340 /* amomaxu.d.rl */, RISCV::AMOMAXU_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 353 /* amomaxu.w */, RISCV::AMOMAXU_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 363 /* amomaxu.w.aq */, RISCV::AMOMAXU_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 376 /* amomaxu.w.aqrl */, RISCV::AMOMAXU_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 391 /* amomaxu.w.rl */, RISCV::AMOMAXU_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 404 /* amomin.d */, RISCV::AMOMIN_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 413 /* amomin.d.aq */, RISCV::AMOMIN_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 425 /* amomin.d.aqrl */, RISCV::AMOMIN_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 439 /* amomin.d.rl */, RISCV::AMOMIN_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 451 /* amomin.w */, RISCV::AMOMIN_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 460 /* amomin.w.aq */, RISCV::AMOMIN_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 472 /* amomin.w.aqrl */, RISCV::AMOMIN_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 486 /* amomin.w.rl */, RISCV::AMOMIN_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 498 /* amominu.d */, RISCV::AMOMINU_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 508 /* amominu.d.aq */, RISCV::AMOMINU_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 521 /* amominu.d.aqrl */, RISCV::AMOMINU_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 536 /* amominu.d.rl */, RISCV::AMOMINU_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 549 /* amominu.w */, RISCV::AMOMINU_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 559 /* amominu.w.aq */, RISCV::AMOMINU_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 572 /* amominu.w.aqrl */, RISCV::AMOMINU_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 587 /* amominu.w.rl */, RISCV::AMOMINU_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 600 /* amoor.d */, RISCV::AMOOR_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 608 /* amoor.d.aq */, RISCV::AMOOR_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 619 /* amoor.d.aqrl */, RISCV::AMOOR_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 632 /* amoor.d.rl */, RISCV::AMOOR_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 643 /* amoor.w */, RISCV::AMOOR_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 651 /* amoor.w.aq */, RISCV::AMOOR_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 662 /* amoor.w.aqrl */, RISCV::AMOOR_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 675 /* amoor.w.rl */, RISCV::AMOOR_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 686 /* amoswap.d */, RISCV::AMOSWAP_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 696 /* amoswap.d.aq */, RISCV::AMOSWAP_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 709 /* amoswap.d.aqrl */, RISCV::AMOSWAP_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 724 /* amoswap.d.rl */, RISCV::AMOSWAP_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 737 /* amoswap.w */, RISCV::AMOSWAP_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 747 /* amoswap.w.aq */, RISCV::AMOSWAP_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 760 /* amoswap.w.aqrl */, RISCV::AMOSWAP_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 775 /* amoswap.w.rl */, RISCV::AMOSWAP_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 788 /* amoxor.d */, RISCV::AMOXOR_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 797 /* amoxor.d.aq */, RISCV::AMOXOR_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 809 /* amoxor.d.aqrl */, RISCV::AMOXOR_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 823 /* amoxor.d.rl */, RISCV::AMOXOR_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 835 /* amoxor.w */, RISCV::AMOXOR_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 844 /* amoxor.w.aq */, RISCV::AMOXOR_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 856 /* amoxor.w.aqrl */, RISCV::AMOXOR_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 870 /* amoxor.w.rl */, RISCV::AMOXOR_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 882 /* and */, RISCV::AND, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 882 /* and */, RISCV::ANDI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 886 /* andi */, RISCV::ANDI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 891 /* auipc */, RISCV::AUIPC, Convert__Reg1_0__UImm20AUIPC1_1, 0, { MCK_GPR, MCK_UImm20AUIPC }, },
  { 897 /* beq */, RISCV::BEQ, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 901 /* beqz */, RISCV::BEQ, Convert__Reg1_0__regX0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 906 /* bge */, RISCV::BGE, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 910 /* bgeu */, RISCV::BGEU, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 915 /* bgez */, RISCV::BGE, Convert__Reg1_0__regX0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 920 /* bgt */, RISCV::BLT, Convert__Reg1_1__Reg1_0__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 924 /* bgtu */, RISCV::BLTU, Convert__Reg1_1__Reg1_0__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 929 /* bgtz */, RISCV::BLT, Convert__regX0__Reg1_0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 934 /* ble */, RISCV::BGE, Convert__Reg1_1__Reg1_0__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 938 /* bleu */, RISCV::BGEU, Convert__Reg1_1__Reg1_0__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 943 /* blez */, RISCV::BGE, Convert__regX0__Reg1_0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 948 /* blt */, RISCV::BLT, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 952 /* bltu */, RISCV::BLTU, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 957 /* bltz */, RISCV::BLT, Convert__Reg1_0__regX0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 962 /* bne */, RISCV::BNE, Convert__Reg1_0__Reg1_1__SImm13Lsb01_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm13Lsb0 }, },
  { 966 /* bnez */, RISCV::BNE, Convert__Reg1_0__regX0__SImm13Lsb01_1, 0, { MCK_GPR, MCK_SImm13Lsb0 }, },
  { 971 /* c.add */, RISCV::C_ADD, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_GPRNoX0 }, },
  { 977 /* c.addi */, RISCV::C_ADDI, Convert__Reg1_0__Tie0_1_1__SImm6NonZero1_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_SImm6NonZero }, },
  { 984 /* c.addi16sp */, RISCV::C_ADDI16SP, Convert__Reg1_0__Tie0_1_1__SImm10Lsb0000NonZero1_1, Feature_HasStdExtC, { MCK_SP, MCK_SImm10Lsb0000NonZero }, },
  { 995 /* c.addi4spn */, RISCV::C_ADDI4SPN, Convert__Reg1_0__Reg1_1__UImm10Lsb00NonZero1_2, Feature_HasStdExtC, { MCK_GPRC, MCK_SP, MCK_UImm10Lsb00NonZero }, },
  { 1006 /* c.addiw */, RISCV::C_ADDIW, Convert__Reg1_0__Tie0_1_1__SImm61_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRNoX0, MCK_SImm6 }, },
  { 1014 /* c.addw */, RISCV::C_ADDW, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRC, MCK_GPRC }, },
  { 1021 /* c.and */, RISCV::C_AND, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_GPRC }, },
  { 1027 /* c.andi */, RISCV::C_ANDI, Convert__Reg1_0__Tie0_1_1__SImm61_1, Feature_HasStdExtC, { MCK_GPRC, MCK_SImm6 }, },
  { 1034 /* c.beqz */, RISCV::C_BEQZ, Convert__Reg1_0__SImm9Lsb01_1, Feature_HasStdExtC, { MCK_GPRC, MCK_SImm9Lsb0 }, },
  { 1041 /* c.bnez */, RISCV::C_BNEZ, Convert__Reg1_0__SImm9Lsb01_1, Feature_HasStdExtC, { MCK_GPRC, MCK_SImm9Lsb0 }, },
  { 1048 /* c.ebreak */, RISCV::C_EBREAK, Convert_NoOperands, Feature_HasStdExtC, {  }, },
  { 1057 /* c.fld */, RISCV::C_FLD, Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1, Feature_HasStdExtC|Feature_HasStdExtD, { MCK_FPR64C, MCK_UImm8Lsb000, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1063 /* c.fldsp */, RISCV::C_FLDSP, Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1, Feature_HasStdExtC|Feature_HasStdExtD, { MCK_FPR64, MCK_UImm9Lsb000, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1071 /* c.flw */, RISCV::C_FLW, Convert__Reg1_0__Reg1_3__UImm7Lsb001_1, Feature_HasStdExtC|Feature_HasStdExtF|Feature_IsRV32, { MCK_FPR32C, MCK_UImm7Lsb00, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1077 /* c.flwsp */, RISCV::C_FLWSP, Convert__Reg1_0__Reg1_3__UImm8Lsb001_1, Feature_HasStdExtC|Feature_HasStdExtF|Feature_IsRV32, { MCK_FPR32, MCK_UImm8Lsb00, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1085 /* c.fsd */, RISCV::C_FSD, Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1, Feature_HasStdExtC|Feature_HasStdExtD, { MCK_FPR64C, MCK_UImm8Lsb000, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1091 /* c.fsdsp */, RISCV::C_FSDSP, Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1, Feature_HasStdExtC|Feature_HasStdExtD, { MCK_FPR64, MCK_UImm9Lsb000, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1099 /* c.fsw */, RISCV::C_FSW, Convert__Reg1_0__Reg1_3__UImm7Lsb001_1, Feature_HasStdExtC|Feature_HasStdExtF|Feature_IsRV32, { MCK_FPR32C, MCK_UImm7Lsb00, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1105 /* c.fswsp */, RISCV::C_FSWSP, Convert__Reg1_0__Reg1_3__UImm8Lsb001_1, Feature_HasStdExtC|Feature_HasStdExtF|Feature_IsRV32, { MCK_FPR32, MCK_UImm8Lsb00, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1113 /* c.j */, RISCV::C_J, Convert__SImm12Lsb01_0, Feature_HasStdExtC, { MCK_SImm12Lsb0 }, },
  { 1117 /* c.jal */, RISCV::C_JAL, Convert__SImm12Lsb01_0, Feature_HasStdExtC|Feature_IsRV32, { MCK_SImm12Lsb0 }, },
  { 1123 /* c.jalr */, RISCV::C_JALR, Convert__Reg1_0, Feature_HasStdExtC, { MCK_GPRNoX0 }, },
  { 1130 /* c.jr */, RISCV::C_JR, Convert__Reg1_0, Feature_HasStdExtC, { MCK_GPRNoX0 }, },
  { 1135 /* c.ld */, RISCV::C_LD, Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRC, MCK_UImm8Lsb000, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1140 /* c.ldsp */, RISCV::C_LDSP, Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRNoX0, MCK_UImm9Lsb000, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1147 /* c.li */, RISCV::C_LI, Convert__Reg1_0__SImm61_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_SImm6 }, },
  { 1152 /* c.lui */, RISCV::C_LUI, Convert__Reg1_0__CLUIImm1_1, Feature_HasStdExtC, { MCK_GPRNoX0X2, MCK_CLUIImm }, },
  { 1158 /* c.lw */, RISCV::C_LW, Convert__Reg1_0__Reg1_3__UImm7Lsb001_1, Feature_HasStdExtC, { MCK_GPRC, MCK_UImm7Lsb00, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1163 /* c.lwsp */, RISCV::C_LWSP, Convert__Reg1_0__Reg1_3__UImm8Lsb001_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_UImm8Lsb00, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1170 /* c.mv */, RISCV::C_MV, Convert__Reg1_0__Reg1_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_GPRNoX0 }, },
  { 1175 /* c.nop */, RISCV::C_NOP, Convert_NoOperands, Feature_HasStdExtC, {  }, },
  { 1181 /* c.or */, RISCV::C_OR, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_GPRC }, },
  { 1186 /* c.sd */, RISCV::C_SD, Convert__Reg1_0__Reg1_3__UImm8Lsb0001_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRC, MCK_UImm8Lsb000, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1191 /* c.sdsp */, RISCV::C_SDSP, Convert__Reg1_0__Reg1_3__UImm9Lsb0001_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPR, MCK_UImm9Lsb000, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1198 /* c.slli */, RISCV::C_SLLI, Convert__Reg1_0__Tie0_1_1__UImmLog2XLenNonZero1_1, Feature_HasStdExtC, { MCK_GPRNoX0, MCK_UImmLog2XLenNonZero }, },
  { 1205 /* c.srai */, RISCV::C_SRAI, Convert__Reg1_0__Tie0_1_1__UImmLog2XLenNonZero1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_UImmLog2XLenNonZero }, },
  { 1212 /* c.srli */, RISCV::C_SRLI, Convert__Reg1_0__Tie0_1_1__UImmLog2XLenNonZero1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_UImmLog2XLenNonZero }, },
  { 1219 /* c.sub */, RISCV::C_SUB, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_GPRC }, },
  { 1225 /* c.subw */, RISCV::C_SUBW, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC|Feature_IsRV64, { MCK_GPRC, MCK_GPRC }, },
  { 1232 /* c.sw */, RISCV::C_SW, Convert__Reg1_0__Reg1_3__UImm7Lsb001_1, Feature_HasStdExtC, { MCK_GPRC, MCK_UImm7Lsb00, MCK__40_, MCK_GPRC, MCK__41_ }, },
  { 1237 /* c.swsp */, RISCV::C_SWSP, Convert__Reg1_0__Reg1_3__UImm8Lsb001_1, Feature_HasStdExtC, { MCK_GPR, MCK_UImm8Lsb00, MCK__40_, MCK_SP, MCK__41_ }, },
  { 1244 /* c.unimp */, RISCV::C_UNIMP, Convert_NoOperands, Feature_HasStdExtC, {  }, },
  { 1252 /* c.xor */, RISCV::C_XOR, Convert__Reg1_0__Tie0_1_1__Reg1_1, Feature_HasStdExtC, { MCK_GPRC, MCK_GPRC }, },
  { 1258 /* call */, RISCV::PseudoCALL, Convert__BareSymbol1_0, 0, { MCK_BareSymbol }, },
  { 1263 /* csrc */, RISCV::CSRRC, Convert__regX0__CSRSystemRegister1_0__Reg1_1, 0, { MCK_CSRSystemRegister, MCK_GPR }, },
  { 1263 /* csrc */, RISCV::CSRRCI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1268 /* csrci */, RISCV::CSRRCI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1274 /* csrr */, RISCV::CSRRS, Convert__Reg1_0__CSRSystemRegister1_1__regX0, 0, { MCK_GPR, MCK_CSRSystemRegister }, },
  { 1279 /* csrrc */, RISCV::CSRRC, Convert__Reg1_0__CSRSystemRegister1_1__Reg1_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_GPR }, },
  { 1279 /* csrrc */, RISCV::CSRRCI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1285 /* csrrci */, RISCV::CSRRCI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1292 /* csrrs */, RISCV::CSRRS, Convert__Reg1_0__CSRSystemRegister1_1__Reg1_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_GPR }, },
  { 1292 /* csrrs */, RISCV::CSRRSI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1298 /* csrrsi */, RISCV::CSRRSI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1305 /* csrrw */, RISCV::CSRRW, Convert__Reg1_0__CSRSystemRegister1_1__Reg1_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_GPR }, },
  { 1305 /* csrrw */, RISCV::CSRRWI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1311 /* csrrwi */, RISCV::CSRRWI, Convert__Reg1_0__CSRSystemRegister1_1__UImm51_2, 0, { MCK_GPR, MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1318 /* csrs */, RISCV::CSRRS, Convert__regX0__CSRSystemRegister1_0__Reg1_1, 0, { MCK_CSRSystemRegister, MCK_GPR }, },
  { 1318 /* csrs */, RISCV::CSRRSI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1323 /* csrsi */, RISCV::CSRRSI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1329 /* csrw */, RISCV::CSRRW, Convert__regX0__CSRSystemRegister1_0__Reg1_1, 0, { MCK_CSRSystemRegister, MCK_GPR }, },
  { 1329 /* csrw */, RISCV::CSRRWI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1334 /* csrwi */, RISCV::CSRRWI, Convert__regX0__CSRSystemRegister1_0__UImm51_1, 0, { MCK_CSRSystemRegister, MCK_UImm5 }, },
  { 1340 /* div */, RISCV::DIV, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1344 /* divu */, RISCV::DIVU, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1349 /* divuw */, RISCV::DIVUW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1355 /* divw */, RISCV::DIVW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 1360 /* ebreak */, RISCV::EBREAK, Convert_NoOperands, 0, {  }, },
  { 1367 /* ecall */, RISCV::ECALL, Convert_NoOperands, 0, {  }, },
  { 1373 /* fabs.d */, RISCV::FSGNJX_D, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64 }, },
  { 1380 /* fabs.s */, RISCV::FSGNJX_S, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32 }, },
  { 1387 /* fadd.d */, RISCV::FADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1387 /* fadd.d */, RISCV::FADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1394 /* fadd.s */, RISCV::FADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1394 /* fadd.s */, RISCV::FADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1401 /* fclass.d */, RISCV::FCLASS_D, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64 }, },
  { 1410 /* fclass.s */, RISCV::FCLASS_S, Convert__Reg1_0__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32 }, },
  { 1419 /* fcvt.d.l */, RISCV::FCVT_D_L, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD|Feature_IsRV64, { MCK_FPR64, MCK_GPR }, },
  { 1419 /* fcvt.d.l */, RISCV::FCVT_D_L, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD|Feature_IsRV64, { MCK_FPR64, MCK_GPR, MCK_FRMArg }, },
  { 1428 /* fcvt.d.lu */, RISCV::FCVT_D_LU, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD|Feature_IsRV64, { MCK_FPR64, MCK_GPR }, },
  { 1428 /* fcvt.d.lu */, RISCV::FCVT_D_LU, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD|Feature_IsRV64, { MCK_FPR64, MCK_GPR, MCK_FRMArg }, },
  { 1438 /* fcvt.d.s */, RISCV::FCVT_D_S, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR32 }, },
  { 1447 /* fcvt.d.w */, RISCV::FCVT_D_W, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_GPR }, },
  { 1456 /* fcvt.d.wu */, RISCV::FCVT_D_WU, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_GPR }, },
  { 1466 /* fcvt.l.d */, RISCV::FCVT_L_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD|Feature_IsRV64, { MCK_GPR, MCK_FPR64 }, },
  { 1466 /* fcvt.l.d */, RISCV::FCVT_L_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD|Feature_IsRV64, { MCK_GPR, MCK_FPR64, MCK_FRMArg }, },
  { 1475 /* fcvt.l.s */, RISCV::FCVT_L_S, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF|Feature_IsRV64, { MCK_GPR, MCK_FPR32 }, },
  { 1475 /* fcvt.l.s */, RISCV::FCVT_L_S, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF|Feature_IsRV64, { MCK_GPR, MCK_FPR32, MCK_FRMArg }, },
  { 1484 /* fcvt.lu.d */, RISCV::FCVT_LU_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD|Feature_IsRV64, { MCK_GPR, MCK_FPR64 }, },
  { 1484 /* fcvt.lu.d */, RISCV::FCVT_LU_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD|Feature_IsRV64, { MCK_GPR, MCK_FPR64, MCK_FRMArg }, },
  { 1494 /* fcvt.lu.s */, RISCV::FCVT_LU_S, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF|Feature_IsRV64, { MCK_GPR, MCK_FPR32 }, },
  { 1494 /* fcvt.lu.s */, RISCV::FCVT_LU_S, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF|Feature_IsRV64, { MCK_GPR, MCK_FPR32, MCK_FRMArg }, },
  { 1504 /* fcvt.s.d */, RISCV::FCVT_S_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD, { MCK_FPR32, MCK_FPR64 }, },
  { 1504 /* fcvt.s.d */, RISCV::FCVT_S_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD, { MCK_FPR32, MCK_FPR64, MCK_FRMArg }, },
  { 1513 /* fcvt.s.l */, RISCV::FCVT_S_L, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF|Feature_IsRV64, { MCK_FPR32, MCK_GPR }, },
  { 1513 /* fcvt.s.l */, RISCV::FCVT_S_L, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF|Feature_IsRV64, { MCK_FPR32, MCK_GPR, MCK_FRMArg }, },
  { 1522 /* fcvt.s.lu */, RISCV::FCVT_S_LU, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF|Feature_IsRV64, { MCK_FPR32, MCK_GPR }, },
  { 1522 /* fcvt.s.lu */, RISCV::FCVT_S_LU, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF|Feature_IsRV64, { MCK_FPR32, MCK_GPR, MCK_FRMArg }, },
  { 1532 /* fcvt.s.w */, RISCV::FCVT_S_W, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_GPR }, },
  { 1532 /* fcvt.s.w */, RISCV::FCVT_S_W, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_GPR, MCK_FRMArg }, },
  { 1541 /* fcvt.s.wu */, RISCV::FCVT_S_WU, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_GPR }, },
  { 1541 /* fcvt.s.wu */, RISCV::FCVT_S_WU, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_GPR, MCK_FRMArg }, },
  { 1551 /* fcvt.w.d */, RISCV::FCVT_W_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64 }, },
  { 1551 /* fcvt.w.d */, RISCV::FCVT_W_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FRMArg }, },
  { 1560 /* fcvt.w.s */, RISCV::FCVT_W_S, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32 }, },
  { 1560 /* fcvt.w.s */, RISCV::FCVT_W_S, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FRMArg }, },
  { 1569 /* fcvt.wu.d */, RISCV::FCVT_WU_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64 }, },
  { 1569 /* fcvt.wu.d */, RISCV::FCVT_WU_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FRMArg }, },
  { 1579 /* fcvt.wu.s */, RISCV::FCVT_WU_S, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32 }, },
  { 1579 /* fcvt.wu.s */, RISCV::FCVT_WU_S, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FRMArg }, },
  { 1589 /* fdiv.d */, RISCV::FDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1589 /* fdiv.d */, RISCV::FDIV_D, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1596 /* fdiv.s */, RISCV::FDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1596 /* fdiv.s */, RISCV::FDIV_S, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1603 /* fence */, RISCV::FENCE, Convert__imm_95_15__imm_95_15, 0, {  }, },
  { 1603 /* fence */, RISCV::FENCE, Convert__FenceArg1_0__FenceArg1_1, 0, { MCK_FenceArg, MCK_FenceArg }, },
  { 1609 /* fence.i */, RISCV::FENCE_I, Convert_NoOperands, 0, {  }, },
  { 1617 /* fence.tso */, RISCV::FENCE_TSO, Convert_NoOperands, 0, {  }, },
  { 1627 /* feq.d */, RISCV::FEQ_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FPR64 }, },
  { 1633 /* feq.s */, RISCV::FEQ_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FPR32 }, },
  { 1639 /* fge.d */, RISCV::FLE_D, Convert__Reg1_0__Reg1_2__Reg1_1, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FPR64 }, },
  { 1645 /* fge.s */, RISCV::FLE_S, Convert__Reg1_0__Reg1_2__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FPR32 }, },
  { 1651 /* fgt.d */, RISCV::FLT_D, Convert__Reg1_0__Reg1_2__Reg1_1, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FPR64 }, },
  { 1657 /* fgt.s */, RISCV::FLT_S, Convert__Reg1_0__Reg1_2__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FPR32 }, },
  { 1663 /* fld */, RISCV::FLD, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_HasStdExtD, { MCK_FPR64, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 1667 /* fle.d */, RISCV::FLE_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FPR64 }, },
  { 1673 /* fle.s */, RISCV::FLE_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FPR32 }, },
  { 1679 /* flt.d */, RISCV::FLT_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_GPR, MCK_FPR64, MCK_FPR64 }, },
  { 1685 /* flt.s */, RISCV::FLT_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32, MCK_FPR32 }, },
  { 1691 /* flw */, RISCV::FLW, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_HasStdExtF, { MCK_FPR32, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 1695 /* fmadd.d */, RISCV::FMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1695 /* fmadd.d */, RISCV::FMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1703 /* fmadd.s */, RISCV::FMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1703 /* fmadd.s */, RISCV::FMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1711 /* fmax.d */, RISCV::FMAX_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1718 /* fmax.s */, RISCV::FMAX_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1725 /* fmin.d */, RISCV::FMIN_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1732 /* fmin.s */, RISCV::FMIN_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1739 /* fmsub.d */, RISCV::FMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1739 /* fmsub.d */, RISCV::FMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1747 /* fmsub.s */, RISCV::FMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1747 /* fmsub.s */, RISCV::FMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1755 /* fmul.d */, RISCV::FMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1755 /* fmul.d */, RISCV::FMUL_D, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1762 /* fmul.s */, RISCV::FMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1762 /* fmul.s */, RISCV::FMUL_S, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1769 /* fmv.d */, RISCV::FSGNJ_D, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64 }, },
  { 1775 /* fmv.d.x */, RISCV::FMV_D_X, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD|Feature_IsRV64, { MCK_FPR64, MCK_GPR }, },
  { 1783 /* fmv.s */, RISCV::FSGNJ_S, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32 }, },
  { 1789 /* fmv.w.x */, RISCV::FMV_W_X, Convert__Reg1_0__Reg1_1, Feature_HasStdExtF, { MCK_FPR32, MCK_GPR }, },
  { 1797 /* fmv.x.d */, RISCV::FMV_X_D, Convert__Reg1_0__Reg1_1, Feature_HasStdExtD|Feature_IsRV64, { MCK_GPR, MCK_FPR64 }, },
  { 1805 /* fmv.x.w */, RISCV::FMV_X_W, Convert__Reg1_0__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_FPR32 }, },
  { 1813 /* fneg.d */, RISCV::FSGNJN_D, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64 }, },
  { 1820 /* fneg.s */, RISCV::FSGNJN_S, Convert__Reg1_0__Reg1_1__Reg1_1, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32 }, },
  { 1827 /* fnmadd.d */, RISCV::FNMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1827 /* fnmadd.d */, RISCV::FNMADD_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1836 /* fnmadd.s */, RISCV::FNMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1836 /* fnmadd.s */, RISCV::FNMADD_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1845 /* fnmsub.d */, RISCV::FNMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1845 /* fnmsub.d */, RISCV::FNMSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1854 /* fnmsub.s */, RISCV::FNMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1854 /* fnmsub.s */, RISCV::FNMSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__Reg1_3__FRMArg1_4, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1863 /* frcsr */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3__regX0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1869 /* frflags */, RISCV::CSRRS, Convert__Reg1_0__imm_95_1__regX0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1877 /* frrm */, RISCV::CSRRS, Convert__Reg1_0__imm_95_2__regX0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1882 /* fscsr */, RISCV::CSRRW, Convert__regX0__imm_95_3__Reg1_0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1882 /* fscsr */, RISCV::CSRRW, Convert__Reg1_0__imm_95_3__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_GPR }, },
  { 1888 /* fsd */, RISCV::FSD, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_HasStdExtD, { MCK_FPR64, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 1892 /* fsflags */, RISCV::CSRRW, Convert__regX0__imm_95_1__Reg1_0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1892 /* fsflags */, RISCV::CSRRW, Convert__Reg1_0__imm_95_1__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_GPR }, },
  { 1900 /* fsflagsi */, RISCV::CSRRWI, Convert__regX0__imm_95_1__UImm51_0, Feature_HasStdExtF, { MCK_UImm5 }, },
  { 1900 /* fsflagsi */, RISCV::CSRRWI, Convert__Reg1_0__imm_95_1__UImm51_1, Feature_HasStdExtF, { MCK_GPR, MCK_UImm5 }, },
  { 1909 /* fsgnj.d */, RISCV::FSGNJ_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1917 /* fsgnj.s */, RISCV::FSGNJ_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1925 /* fsgnjn.d */, RISCV::FSGNJN_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1934 /* fsgnjn.s */, RISCV::FSGNJN_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1943 /* fsgnjx.d */, RISCV::FSGNJX_D, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1952 /* fsgnjx.s */, RISCV::FSGNJX_S, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1961 /* fsqrt.d */, RISCV::FSQRT_D, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64 }, },
  { 1961 /* fsqrt.d */, RISCV::FSQRT_D, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1969 /* fsqrt.s */, RISCV::FSQRT_S, Convert__Reg1_0__Reg1_1__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32 }, },
  { 1969 /* fsqrt.s */, RISCV::FSQRT_S, Convert__Reg1_0__Reg1_1__FRMArg1_2, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 1977 /* fsrm */, RISCV::CSRRW, Convert__regX0__imm_95_2__Reg1_0, Feature_HasStdExtF, { MCK_GPR }, },
  { 1977 /* fsrm */, RISCV::CSRRW, Convert__Reg1_0__imm_95_2__Reg1_1, Feature_HasStdExtF, { MCK_GPR, MCK_GPR }, },
  { 1982 /* fsrmi */, RISCV::CSRRWI, Convert__regX0__imm_95_2__UImm51_0, Feature_HasStdExtF, { MCK_UImm5 }, },
  { 1982 /* fsrmi */, RISCV::CSRRWI, Convert__Reg1_0__imm_95_2__UImm51_1, Feature_HasStdExtF, { MCK_GPR, MCK_UImm5 }, },
  { 1988 /* fsub.d */, RISCV::FSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64 }, },
  { 1988 /* fsub.d */, RISCV::FSUB_D, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtD, { MCK_FPR64, MCK_FPR64, MCK_FPR64, MCK_FRMArg }, },
  { 1995 /* fsub.s */, RISCV::FSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__imm_95_7, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32 }, },
  { 1995 /* fsub.s */, RISCV::FSUB_S, Convert__Reg1_0__Reg1_1__Reg1_2__FRMArg1_3, Feature_HasStdExtF, { MCK_FPR32, MCK_FPR32, MCK_FPR32, MCK_FRMArg }, },
  { 2002 /* fsw */, RISCV::FSW, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_HasStdExtF, { MCK_FPR32, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2006 /* j */, RISCV::JAL, Convert__regX0__SImm21Lsb0JAL1_0, 0, { MCK_SImm21Lsb0JAL }, },
  { 2008 /* jal */, RISCV::JAL, Convert__regX1__SImm21Lsb0JAL1_0, 0, { MCK_SImm21Lsb0JAL }, },
  { 2008 /* jal */, RISCV::JAL, Convert__Reg1_0__SImm21Lsb0JAL1_1, 0, { MCK_GPR, MCK_SImm21Lsb0JAL }, },
  { 2012 /* jalr */, RISCV::JALR, Convert__regX1__Reg1_0__imm_95_0, 0, { MCK_GPR }, },
  { 2012 /* jalr */, RISCV::JALR, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2017 /* jr */, RISCV::JALR, Convert__regX0__Reg1_0__imm_95_0, 0, { MCK_GPR }, },
  { 2020 /* lb */, RISCV::LB, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2023 /* lbu */, RISCV::LBU, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2027 /* ld */, RISCV::LD, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_IsRV64, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2030 /* lh */, RISCV::LH, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2033 /* lhu */, RISCV::LHU, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2037 /* li */, RISCV::PseudoLI, Convert__Reg1_0__ImmXLen1_1, 0, { MCK_GPR, MCK_ImmXLen }, },
  { 2040 /* lla */, RISCV::PseudoLLA, Convert__Reg1_0__BareSymbol1_1, 0, { MCK_GPR, MCK_BareSymbol }, },
  { 2044 /* lr.d */, RISCV::LR_D, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2049 /* lr.d.aq */, RISCV::LR_D_AQ, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2057 /* lr.d.aqrl */, RISCV::LR_D_AQ_RL, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2067 /* lr.d.rl */, RISCV::LR_D_RL, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2075 /* lr.w */, RISCV::LR_W, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2080 /* lr.w.aq */, RISCV::LR_W_AQ, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2088 /* lr.w.aqrl */, RISCV::LR_W_AQ_RL, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2098 /* lr.w.rl */, RISCV::LR_W_RL, Convert__Reg1_0__Reg1_2, Feature_HasStdExtA, { MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2106 /* lui */, RISCV::LUI, Convert__Reg1_0__UImm20LUI1_1, 0, { MCK_GPR, MCK_UImm20LUI }, },
  { 2110 /* lw */, RISCV::LW, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2113 /* lwu */, RISCV::LWU, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_IsRV64, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2117 /* mret */, RISCV::MRET, Convert__imm_95_0__imm_95_0, 0, {  }, },
  { 2122 /* mul */, RISCV::MUL, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2126 /* mulh */, RISCV::MULH, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2131 /* mulhsu */, RISCV::MULHSU, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2138 /* mulhu */, RISCV::MULHU, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2144 /* mulw */, RISCV::MULW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2149 /* mv */, RISCV::ADDI, Convert__Reg1_0__Reg1_1__imm_95_0, 0, { MCK_GPR, MCK_GPR }, },
  { 2152 /* neg */, RISCV::SUB, Convert__Reg1_0__regX0__Reg1_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2156 /* negw */, RISCV::SUBW, Convert__Reg1_0__regX0__Reg1_1, Feature_IsRV64, { MCK_GPR, MCK_GPR }, },
  { 2161 /* nop */, RISCV::ADDI, Convert__regX0__regX0__imm_95_0, 0, {  }, },
  { 2165 /* not */, RISCV::XORI, Convert__Reg1_0__Reg1_1__imm_95__MINUS_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2169 /* or */, RISCV::OR, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2169 /* or */, RISCV::ORI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2172 /* ori */, RISCV::ORI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2176 /* rdcycle */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3072__regX0, 0, { MCK_GPR }, },
  { 2184 /* rdcycleh */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3200__regX0, Feature_IsRV32, { MCK_GPR }, },
  { 2193 /* rdinstret */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3074__regX0, 0, { MCK_GPR }, },
  { 2203 /* rdinstreth */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3202__regX0, Feature_IsRV32, { MCK_GPR }, },
  { 2214 /* rdtime */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3073__regX0, 0, { MCK_GPR }, },
  { 2221 /* rdtimeh */, RISCV::CSRRS, Convert__Reg1_0__imm_95_3201__regX0, Feature_IsRV32, { MCK_GPR }, },
  { 2229 /* rem */, RISCV::REM, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2233 /* remu */, RISCV::REMU, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2238 /* remuw */, RISCV::REMUW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2244 /* remw */, RISCV::REMW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_HasStdExtM|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2249 /* ret */, RISCV::JALR, Convert__regX0__regX1__imm_95_0, 0, {  }, },
  { 2253 /* sb */, RISCV::SB, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2256 /* sc.d */, RISCV::SC_D, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2261 /* sc.d.aq */, RISCV::SC_D_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2269 /* sc.d.aqrl */, RISCV::SC_D_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2279 /* sc.d.rl */, RISCV::SC_D_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA|Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2287 /* sc.w */, RISCV::SC_W, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2292 /* sc.w.aq */, RISCV::SC_W_AQ, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2300 /* sc.w.aqrl */, RISCV::SC_W_AQ_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2310 /* sc.w.rl */, RISCV::SC_W_RL, Convert__Reg1_0__Reg1_3__Reg1_1, Feature_HasStdExtA, { MCK_GPR, MCK_GPR, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2318 /* sd */, RISCV::SD, Convert__Reg1_0__Reg1_3__SImm121_1, Feature_IsRV64, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2321 /* seqz */, RISCV::SLTIU, Convert__Reg1_0__Reg1_1__imm_95_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2326 /* sext.w */, RISCV::ADDIW, Convert__Reg1_0__Reg1_1__imm_95_0, Feature_IsRV64, { MCK_GPR, MCK_GPR }, },
  { 2333 /* sfence.vma */, RISCV::SFENCE_VMA, Convert__regX0__regX0, 0, {  }, },
  { 2333 /* sfence.vma */, RISCV::SFENCE_VMA, Convert__Reg1_0__regX0, 0, { MCK_GPR }, },
  { 2333 /* sfence.vma */, RISCV::SFENCE_VMA, Convert__Reg1_0__Reg1_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2344 /* sgt */, RISCV::SLT, Convert__Reg1_0__Reg1_2__Reg1_1, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2348 /* sgtu */, RISCV::SLTU, Convert__Reg1_0__Reg1_2__Reg1_1, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2353 /* sgtz */, RISCV::SLT, Convert__Reg1_0__regX0__Reg1_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2358 /* sh */, RISCV::SH, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2361 /* sll */, RISCV::SLL, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2361 /* sll */, RISCV::SLLI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2365 /* slli */, RISCV::SLLI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2370 /* slliw */, RISCV::SLLIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2376 /* sllw */, RISCV::SLLW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2376 /* sllw */, RISCV::SLLIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2381 /* slt */, RISCV::SLT, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2381 /* slt */, RISCV::SLTI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2385 /* slti */, RISCV::SLTI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2390 /* sltiu */, RISCV::SLTIU, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2396 /* sltu */, RISCV::SLTU, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2396 /* sltu */, RISCV::SLTIU, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2401 /* sltz */, RISCV::SLT, Convert__Reg1_0__Reg1_1__regX0, 0, { MCK_GPR, MCK_GPR }, },
  { 2406 /* snez */, RISCV::SLTU, Convert__Reg1_0__regX0__Reg1_1, 0, { MCK_GPR, MCK_GPR }, },
  { 2411 /* sra */, RISCV::SRA, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2411 /* sra */, RISCV::SRAI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2415 /* srai */, RISCV::SRAI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2420 /* sraiw */, RISCV::SRAIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2426 /* sraw */, RISCV::SRAW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2426 /* sraw */, RISCV::SRAIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2431 /* sret */, RISCV::SRET, Convert__imm_95_0__imm_95_0, 0, {  }, },
  { 2436 /* srl */, RISCV::SRL, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2436 /* srl */, RISCV::SRLI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2440 /* srli */, RISCV::SRLI, Convert__Reg1_0__Reg1_1__UImmLog2XLen1_2, 0, { MCK_GPR, MCK_GPR, MCK_UImmLog2XLen }, },
  { 2445 /* srliw */, RISCV::SRLIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2451 /* srlw */, RISCV::SRLW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2451 /* srlw */, RISCV::SRLIW, Convert__Reg1_0__Reg1_1__UImm51_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_UImm5 }, },
  { 2456 /* sub */, RISCV::SUB, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2460 /* subw */, RISCV::SUBW, Convert__Reg1_0__Reg1_1__Reg1_2, Feature_IsRV64, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2465 /* sw */, RISCV::SW, Convert__Reg1_0__Reg1_3__SImm121_1, 0, { MCK_GPR, MCK_SImm12, MCK__40_, MCK_GPR, MCK__41_ }, },
  { 2468 /* tail */, RISCV::PseudoTAIL, Convert__BareSymbol1_0, 0, { MCK_BareSymbol }, },
  { 2473 /* unimp */, RISCV::UNIMP, Convert_NoOperands, 0, {  }, },
  { 2479 /* uret */, RISCV::URET, Convert__imm_95_0__imm_95_0, 0, {  }, },
  { 2484 /* wfi */, RISCV::WFI, Convert__imm_95_0__imm_95_0, 0, {  }, },
  { 2488 /* xor */, RISCV::XOR, Convert__Reg1_0__Reg1_1__Reg1_2, 0, { MCK_GPR, MCK_GPR, MCK_GPR }, },
  { 2488 /* xor */, RISCV::XORI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
  { 2492 /* xori */, RISCV::XORI, Convert__Reg1_0__Reg1_1__SImm121_2, 0, { MCK_GPR, MCK_GPR, MCK_SImm12 }, },
};

#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"

unsigned RISCVAsmParser::
MatchInstructionImpl(const OperandVector &Operands,
                     MCInst &Inst,
                     uint64_t &ErrorInfo,
                     bool matchingInlineAsm, unsigned VariantID) {
  // Eliminate obvious mismatches.
  if (Operands.size() > 6) {
    ErrorInfo = 6;
    return Match_InvalidOperand;
  }

  // Get the current feature set.
  uint64_t AvailableFeatures = getAvailableFeatures();

  // Get the instruction mnemonic, which is the first token.
  StringRef Mnemonic = ((RISCVOperand&)*Operands[0]).getToken();

  // Process all MnemonicAliases to remap the mnemonic.
  applyMnemonicAliases(Mnemonic, AvailableFeatures, VariantID);

  // Some state to try to produce better error messages.
  bool HadMatchOtherThanFeatures = false;
  bool HadMatchOtherThanPredicate = false;
  unsigned RetCode = Match_InvalidOperand;
  uint64_t MissingFeatures = ~0ULL;
  // Set ErrorInfo to the operand that mismatches if it is
  // wrong for all instances of the instruction.
  ErrorInfo = ~0ULL;
  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }
  // Search the table.
  auto MnemonicRange = std::equal_range(Start, End, Mnemonic, LessOpcode());

  DEBUG_WITH_TYPE("asm-matcher", dbgs() << "AsmMatcher: found " <<
  std::distance(MnemonicRange.first, MnemonicRange.second) << 
  " encodings with mnemonic '" << Mnemonic << "'\n");

  // Return a more specific error code if no mnemonics match.
  if (MnemonicRange.first == MnemonicRange.second)
    return Match_MnemonicFail;

  for (const MatchEntry *it = MnemonicRange.first, *ie = MnemonicRange.second;
       it != ie; ++it) {
    bool HasRequiredFeatures =
      (AvailableFeatures & it->RequiredFeatures) == it->RequiredFeatures;
    DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Trying to match opcode "
                                          << MII.getName(it->Opcode) << "\n");
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());
    bool OperandsValid = true;
    for (unsigned FormalIdx = 0, ActualIdx = 1; FormalIdx != 5; ++FormalIdx) {
      auto Formal = static_cast<MatchClassKind>(it->Classes[FormalIdx]);
      DEBUG_WITH_TYPE("asm-matcher",
                      dbgs() << "  Matching formal operand class " << getMatchClassName(Formal)
                             << " against actual operand at index " << ActualIdx);
      if (ActualIdx < Operands.size())
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << " (";
                        Operands[ActualIdx]->print(dbgs()); dbgs() << "): ");
      else
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << ": ");
      if (ActualIdx >= Operands.size()) {
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << "actual operand index out of range ");
        OperandsValid = (Formal == InvalidMatchClass) || isSubclass(Formal, OptionalMatchClass);
        if (!OperandsValid) ErrorInfo = ActualIdx;
        break;
      }
      MCParsedAsmOperand &Actual = *Operands[ActualIdx];
      unsigned Diag = validateOperandClass(Actual, Formal);
      if (Diag == Match_Success) {
        DEBUG_WITH_TYPE("asm-matcher",
                        dbgs() << "match success using generic matcher\n");
        ++ActualIdx;
        continue;
      }
      // If the generic handler indicates an invalid operand
      // failure, check for a special case.
      if (Diag != Match_Success) {
        unsigned TargetDiag = validateTargetOperandClass(Actual, Formal);
        if (TargetDiag == Match_Success) {
          DEBUG_WITH_TYPE("asm-matcher",
                          dbgs() << "match success using target matcher\n");
          ++ActualIdx;
          continue;
        }
        // If the target matcher returned a specific error code use
        // that, else use the one from the generic matcher.
        if (TargetDiag != Match_InvalidOperand && HasRequiredFeatures)
          Diag = TargetDiag;
      }
      // If current formal operand wasn't matched and it is optional
      // then try to match next formal operand
      if (Diag == Match_InvalidOperand && isSubclass(Formal, OptionalMatchClass)) {
        DEBUG_WITH_TYPE("asm-matcher", dbgs() << "ignoring optional operand\n");
        continue;
      }
      // If this operand is broken for all of the instances of this
      // mnemonic, keep track of it so we can report loc info.
      // If we already had a match that only failed due to a
      // target predicate, that diagnostic is preferred.
      if (!HadMatchOtherThanPredicate &&
          (it == MnemonicRange.first || ErrorInfo <= ActualIdx)) {
        if (HasRequiredFeatures && (ErrorInfo != ActualIdx || Diag != Match_InvalidOperand))
          RetCode = Diag;
        ErrorInfo = ActualIdx;
      }
      // Otherwise, just reject this instance of the mnemonic.
      OperandsValid = false;
      break;
    }

    if (!OperandsValid) {
      DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Opcode result: multiple "
                                               "operand mismatches, ignoring "
                                               "this opcode\n");
      continue;
    }
    if (!HasRequiredFeatures) {
      HadMatchOtherThanFeatures = true;
      uint64_t NewMissingFeatures = it->RequiredFeatures & ~AvailableFeatures;
      DEBUG_WITH_TYPE("asm-matcher", dbgs() << "Missing target features: "
                                            << format_hex(NewMissingFeatures, 18)
                                            << "\n");
      if (countPopulation(NewMissingFeatures) <=
          countPopulation(MissingFeatures))
        MissingFeatures = NewMissingFeatures;
      continue;
    }

    Inst.clear();

    Inst.setOpcode(it->Opcode);
    // We have a potential match but have not rendered the operands.
    // Check the target predicate to handle any context sensitive
    // constraints.
    // For example, Ties that are referenced multiple times must be
    // checked here to ensure the input is the same for each match
    // constraints. If we leave it any later the ties will have been
    // canonicalized
    unsigned MatchResult;
    if ((MatchResult = checkEarlyTargetMatchPredicate(Inst, Operands)) != Match_Success) {
      Inst.clear();
      DEBUG_WITH_TYPE(
          "asm-matcher",
          dbgs() << "Early target match predicate failed with diag code "
                 << MatchResult << "\n");
      RetCode = MatchResult;
      HadMatchOtherThanPredicate = true;
      continue;
    }

    if (matchingInlineAsm) {
      convertToMapAndConstraints(it->ConvertFn, Operands);
      if (!checkAsmTiedOperandConstraints(*this, it->ConvertFn, Operands, ErrorInfo))
        return Match_InvalidTiedOperand;

      return Match_Success;
    }

    // We have selected a definite instruction, convert the parsed
    // operands into the appropriate MCInst.
    convertToMCInst(it->ConvertFn, Inst, it->Opcode, Operands);

    // We have a potential match. Check the target predicate to
    // handle any context sensitive constraints.
    if ((MatchResult = checkTargetMatchPredicate(Inst)) != Match_Success) {
      DEBUG_WITH_TYPE("asm-matcher",
                      dbgs() << "Target match predicate failed with diag code "
                             << MatchResult << "\n");
      Inst.clear();
      RetCode = MatchResult;
      HadMatchOtherThanPredicate = true;
      continue;
    }

    if (!checkAsmTiedOperandConstraints(*this, it->ConvertFn, Operands, ErrorInfo))
      return Match_InvalidTiedOperand;

    DEBUG_WITH_TYPE(
        "asm-matcher",
        dbgs() << "Opcode result: complete match, selecting this opcode\n");
    return Match_Success;
  }

  // Okay, we had no match.  Try to return a useful error code.
  if (HadMatchOtherThanPredicate || !HadMatchOtherThanFeatures)
    return RetCode;

  // Missing feature matches return which features were missing
  ErrorInfo = MissingFeatures;
  return Match_MissingFeature;
}

namespace {
  struct OperandMatchEntry {
    uint8_t RequiredFeatures;
    uint16_t Mnemonic;
    uint8_t Class;
    uint8_t OperandMask;

    StringRef getMnemonic() const {
      return StringRef(MnemonicTable + Mnemonic + 1,
                       MnemonicTable[Mnemonic]);
    }
  };

  // Predicate for searching for an opcode.
  struct LessOpcodeOperand {
    bool operator()(const OperandMatchEntry &LHS, StringRef RHS) {
      return LHS.getMnemonic()  < RHS;
    }
    bool operator()(StringRef LHS, const OperandMatchEntry &RHS) {
      return LHS < RHS.getMnemonic();
    }
    bool operator()(const OperandMatchEntry &LHS, const OperandMatchEntry &RHS) {
      return LHS.getMnemonic() < RHS.getMnemonic();
    }
  };
} // end anonymous namespace.

static const OperandMatchEntry OperandMatchTable[25] = {
  /* Operand List Mask, Mnemonic, Operand Class, Features */
  { 0, 1258 /* call */, MCK_BareSymbol, 1 /* 0 */ },
  { 0, 1263 /* csrc */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1263 /* csrc */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1268 /* csrci */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1274 /* csrr */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1279 /* csrrc */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1279 /* csrrc */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1285 /* csrrci */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1292 /* csrrs */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1292 /* csrrs */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1298 /* csrrsi */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1305 /* csrrw */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1305 /* csrrw */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1311 /* csrrwi */, MCK_CSRSystemRegister, 2 /* 1 */ },
  { 0, 1318 /* csrs */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1318 /* csrs */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1323 /* csrsi */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1329 /* csrw */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1329 /* csrw */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 1334 /* csrwi */, MCK_CSRSystemRegister, 1 /* 0 */ },
  { 0, 2006 /* j */, MCK_SImm21Lsb0JAL, 1 /* 0 */ },
  { 0, 2008 /* jal */, MCK_SImm21Lsb0JAL, 1 /* 0 */ },
  { 0, 2008 /* jal */, MCK_SImm21Lsb0JAL, 2 /* 1 */ },
  { 0, 2040 /* lla */, MCK_BareSymbol, 2 /* 1 */ },
  { 0, 2468 /* tail */, MCK_BareSymbol, 1 /* 0 */ },
};

OperandMatchResultTy RISCVAsmParser::
tryCustomParseOperand(OperandVector &Operands,
                      unsigned MCK) {

  switch(MCK) {
  case MCK_BareSymbol:
    return parseBareSymbol(Operands);
  case MCK_CSRSystemRegister:
    return parseCSRSystemRegister(Operands);
  case MCK_SImm21Lsb0JAL:
    return parseJALOffset(Operands);
  default:
    return MatchOperand_NoMatch;
  }
  return MatchOperand_NoMatch;
}

OperandMatchResultTy RISCVAsmParser::
MatchOperandParserImpl(OperandVector &Operands,
                       StringRef Mnemonic,
                       bool ParseForAllFeatures) {
  // Get the current feature set.
  uint64_t AvailableFeatures = getAvailableFeatures();

  // Get the next operand index.
  unsigned NextOpNum = Operands.size() - 1;
  // Search the table.
  auto MnemonicRange =
    std::equal_range(std::begin(OperandMatchTable), std::end(OperandMatchTable),
                     Mnemonic, LessOpcodeOperand());

  if (MnemonicRange.first == MnemonicRange.second)
    return MatchOperand_NoMatch;

  for (const OperandMatchEntry *it = MnemonicRange.first,
       *ie = MnemonicRange.second; it != ie; ++it) {
    // equal_range guarantees that instruction mnemonic matches.
    assert(Mnemonic == it->getMnemonic());

    // check if the available features match
    if (!ParseForAllFeatures && (AvailableFeatures & it->RequiredFeatures) != it->RequiredFeatures)
        continue;

    // check if the operand in question has a custom parser.
    if (!(it->OperandMask & (1 << NextOpNum)))
      continue;

    // call custom parse method to handle the operand
    OperandMatchResultTy Result = tryCustomParseOperand(Operands, it->Class);
    if (Result != MatchOperand_NoMatch)
      return Result;
  }

  // Okay, we had no match.
  return MatchOperand_NoMatch;
}

#endif // GET_MATCHER_IMPLEMENTATION


#ifdef GET_MNEMONIC_SPELL_CHECKER
#undef GET_MNEMONIC_SPELL_CHECKER

static std::string RISCVMnemonicSpellCheck(StringRef S, uint64_t FBS, unsigned VariantID) {
  const unsigned MaxEditDist = 2;
  std::vector<StringRef> Candidates;
  StringRef Prev = "";

  // Find the appropriate table for this asm variant.
  const MatchEntry *Start, *End;
  switch (VariantID) {
  default: llvm_unreachable("invalid variant!");
  case 0: Start = std::begin(MatchTable0); End = std::end(MatchTable0); break;
  }

  for (auto I = Start; I < End; I++) {
    // Ignore unsupported instructions.
    if ((FBS & I->RequiredFeatures) != I->RequiredFeatures)
      continue;

    StringRef T = I->getMnemonic();
    // Avoid recomputing the edit distance for the same string.
    if (T.equals(Prev))
      continue;

    Prev = T;
    unsigned Dist = S.edit_distance(T, false, MaxEditDist);
    if (Dist <= MaxEditDist)
      Candidates.push_back(T);
  }

  if (Candidates.empty())
    return "";

  std::string Res = ", did you mean: ";
  unsigned i = 0;
  for( ; i < Candidates.size() - 1; i++)
    Res += Candidates[i].str() + ", ";
  return Res + Candidates[i].str() + "?";
}

#endif // GET_MNEMONIC_SPELL_CHECKER

