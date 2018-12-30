/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t RISCVMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(51),	// ADD
    UINT64_C(19),	// ADDI
    UINT64_C(27),	// ADDIW
    UINT64_C(59),	// ADDW
    UINT64_C(12335),	// AMOADD_D
    UINT64_C(67121199),	// AMOADD_D_AQ
    UINT64_C(100675631),	// AMOADD_D_AQ_RL
    UINT64_C(33566767),	// AMOADD_D_RL
    UINT64_C(8239),	// AMOADD_W
    UINT64_C(67117103),	// AMOADD_W_AQ
    UINT64_C(100671535),	// AMOADD_W_AQ_RL
    UINT64_C(33562671),	// AMOADD_W_RL
    UINT64_C(1610625071),	// AMOAND_D
    UINT64_C(1677733935),	// AMOAND_D_AQ
    UINT64_C(1711288367),	// AMOAND_D_AQ_RL
    UINT64_C(1644179503),	// AMOAND_D_RL
    UINT64_C(1610620975),	// AMOAND_W
    UINT64_C(1677729839),	// AMOAND_W_AQ
    UINT64_C(1711284271),	// AMOAND_W_AQ_RL
    UINT64_C(1644175407),	// AMOAND_W_RL
    UINT64_C(3758108719),	// AMOMAXU_D
    UINT64_C(3825217583),	// AMOMAXU_D_AQ
    UINT64_C(3858772015),	// AMOMAXU_D_AQ_RL
    UINT64_C(3791663151),	// AMOMAXU_D_RL
    UINT64_C(3758104623),	// AMOMAXU_W
    UINT64_C(3825213487),	// AMOMAXU_W_AQ
    UINT64_C(3858767919),	// AMOMAXU_W_AQ_RL
    UINT64_C(3791659055),	// AMOMAXU_W_RL
    UINT64_C(2684366895),	// AMOMAX_D
    UINT64_C(2751475759),	// AMOMAX_D_AQ
    UINT64_C(2785030191),	// AMOMAX_D_AQ_RL
    UINT64_C(2717921327),	// AMOMAX_D_RL
    UINT64_C(2684362799),	// AMOMAX_W
    UINT64_C(2751471663),	// AMOMAX_W_AQ
    UINT64_C(2785026095),	// AMOMAX_W_AQ_RL
    UINT64_C(2717917231),	// AMOMAX_W_RL
    UINT64_C(3221237807),	// AMOMINU_D
    UINT64_C(3288346671),	// AMOMINU_D_AQ
    UINT64_C(3321901103),	// AMOMINU_D_AQ_RL
    UINT64_C(3254792239),	// AMOMINU_D_RL
    UINT64_C(3221233711),	// AMOMINU_W
    UINT64_C(3288342575),	// AMOMINU_W_AQ
    UINT64_C(3321897007),	// AMOMINU_W_AQ_RL
    UINT64_C(3254788143),	// AMOMINU_W_RL
    UINT64_C(2147495983),	// AMOMIN_D
    UINT64_C(2214604847),	// AMOMIN_D_AQ
    UINT64_C(2248159279),	// AMOMIN_D_AQ_RL
    UINT64_C(2181050415),	// AMOMIN_D_RL
    UINT64_C(2147491887),	// AMOMIN_W
    UINT64_C(2214600751),	// AMOMIN_W_AQ
    UINT64_C(2248155183),	// AMOMIN_W_AQ_RL
    UINT64_C(2181046319),	// AMOMIN_W_RL
    UINT64_C(1073754159),	// AMOOR_D
    UINT64_C(1140863023),	// AMOOR_D_AQ
    UINT64_C(1174417455),	// AMOOR_D_AQ_RL
    UINT64_C(1107308591),	// AMOOR_D_RL
    UINT64_C(1073750063),	// AMOOR_W
    UINT64_C(1140858927),	// AMOOR_W_AQ
    UINT64_C(1174413359),	// AMOOR_W_AQ_RL
    UINT64_C(1107304495),	// AMOOR_W_RL
    UINT64_C(134230063),	// AMOSWAP_D
    UINT64_C(201338927),	// AMOSWAP_D_AQ
    UINT64_C(234893359),	// AMOSWAP_D_AQ_RL
    UINT64_C(167784495),	// AMOSWAP_D_RL
    UINT64_C(134225967),	// AMOSWAP_W
    UINT64_C(201334831),	// AMOSWAP_W_AQ
    UINT64_C(234889263),	// AMOSWAP_W_AQ_RL
    UINT64_C(167780399),	// AMOSWAP_W_RL
    UINT64_C(536883247),	// AMOXOR_D
    UINT64_C(603992111),	// AMOXOR_D_AQ
    UINT64_C(637546543),	// AMOXOR_D_AQ_RL
    UINT64_C(570437679),	// AMOXOR_D_RL
    UINT64_C(536879151),	// AMOXOR_W
    UINT64_C(603988015),	// AMOXOR_W_AQ
    UINT64_C(637542447),	// AMOXOR_W_AQ_RL
    UINT64_C(570433583),	// AMOXOR_W_RL
    UINT64_C(28723),	// AND
    UINT64_C(28691),	// ANDI
    UINT64_C(23),	// AUIPC
    UINT64_C(99),	// BEQ
    UINT64_C(20579),	// BGE
    UINT64_C(28771),	// BGEU
    UINT64_C(16483),	// BLT
    UINT64_C(24675),	// BLTU
    UINT64_C(4195),	// BNE
    UINT64_C(12403),	// CSRRC
    UINT64_C(28787),	// CSRRCI
    UINT64_C(8307),	// CSRRS
    UINT64_C(24691),	// CSRRSI
    UINT64_C(4211),	// CSRRW
    UINT64_C(20595),	// CSRRWI
    UINT64_C(36866),	// C_ADD
    UINT64_C(1),	// C_ADDI
    UINT64_C(24833),	// C_ADDI16SP
    UINT64_C(0),	// C_ADDI4SPN
    UINT64_C(8193),	// C_ADDIW
    UINT64_C(39969),	// C_ADDW
    UINT64_C(35937),	// C_AND
    UINT64_C(34817),	// C_ANDI
    UINT64_C(49153),	// C_BEQZ
    UINT64_C(57345),	// C_BNEZ
    UINT64_C(36866),	// C_EBREAK
    UINT64_C(8192),	// C_FLD
    UINT64_C(8194),	// C_FLDSP
    UINT64_C(24576),	// C_FLW
    UINT64_C(24578),	// C_FLWSP
    UINT64_C(40960),	// C_FSD
    UINT64_C(40962),	// C_FSDSP
    UINT64_C(57344),	// C_FSW
    UINT64_C(57346),	// C_FSWSP
    UINT64_C(40961),	// C_J
    UINT64_C(8193),	// C_JAL
    UINT64_C(36866),	// C_JALR
    UINT64_C(32770),	// C_JR
    UINT64_C(24576),	// C_LD
    UINT64_C(24578),	// C_LDSP
    UINT64_C(16385),	// C_LI
    UINT64_C(24577),	// C_LUI
    UINT64_C(16384),	// C_LW
    UINT64_C(16386),	// C_LWSP
    UINT64_C(32770),	// C_MV
    UINT64_C(1),	// C_NOP
    UINT64_C(35905),	// C_OR
    UINT64_C(57344),	// C_SD
    UINT64_C(57346),	// C_SDSP
    UINT64_C(2),	// C_SLLI
    UINT64_C(33793),	// C_SRAI
    UINT64_C(32769),	// C_SRLI
    UINT64_C(35841),	// C_SUB
    UINT64_C(39937),	// C_SUBW
    UINT64_C(49152),	// C_SW
    UINT64_C(49154),	// C_SWSP
    UINT64_C(0),	// C_UNIMP
    UINT64_C(35873),	// C_XOR
    UINT64_C(33570867),	// DIV
    UINT64_C(33574963),	// DIVU
    UINT64_C(33574971),	// DIVUW
    UINT64_C(33570875),	// DIVW
    UINT64_C(1048691),	// EBREAK
    UINT64_C(115),	// ECALL
    UINT64_C(33554515),	// FADD_D
    UINT64_C(83),	// FADD_S
    UINT64_C(3791654995),	// FCLASS_D
    UINT64_C(3758100563),	// FCLASS_S
    UINT64_C(3525312595),	// FCVT_D_L
    UINT64_C(3526361171),	// FCVT_D_LU
    UINT64_C(1107296339),	// FCVT_D_S
    UINT64_C(3523215443),	// FCVT_D_W
    UINT64_C(3524264019),	// FCVT_D_WU
    UINT64_C(3257925715),	// FCVT_LU_D
    UINT64_C(3224371283),	// FCVT_LU_S
    UINT64_C(3256877139),	// FCVT_L_D
    UINT64_C(3223322707),	// FCVT_L_S
    UINT64_C(1074790483),	// FCVT_S_D
    UINT64_C(3491758163),	// FCVT_S_L
    UINT64_C(3492806739),	// FCVT_S_LU
    UINT64_C(3489661011),	// FCVT_S_W
    UINT64_C(3490709587),	// FCVT_S_WU
    UINT64_C(3255828563),	// FCVT_WU_D
    UINT64_C(3222274131),	// FCVT_WU_S
    UINT64_C(3254779987),	// FCVT_W_D
    UINT64_C(3221225555),	// FCVT_W_S
    UINT64_C(436207699),	// FDIV_D
    UINT64_C(402653267),	// FDIV_S
    UINT64_C(15),	// FENCE
    UINT64_C(4111),	// FENCE_I
    UINT64_C(2200961039),	// FENCE_TSO
    UINT64_C(2717917267),	// FEQ_D
    UINT64_C(2684362835),	// FEQ_S
    UINT64_C(12295),	// FLD
    UINT64_C(2717909075),	// FLE_D
    UINT64_C(2684354643),	// FLE_S
    UINT64_C(2717913171),	// FLT_D
    UINT64_C(2684358739),	// FLT_S
    UINT64_C(8199),	// FLW
    UINT64_C(33554499),	// FMADD_D
    UINT64_C(67),	// FMADD_S
    UINT64_C(704647251),	// FMAX_D
    UINT64_C(671092819),	// FMAX_S
    UINT64_C(704643155),	// FMIN_D
    UINT64_C(671088723),	// FMIN_S
    UINT64_C(33554503),	// FMSUB_D
    UINT64_C(71),	// FMSUB_S
    UINT64_C(301989971),	// FMUL_D
    UINT64_C(268435539),	// FMUL_S
    UINT64_C(4060086355),	// FMV_D_X
    UINT64_C(4026531923),	// FMV_W_X
    UINT64_C(3791650899),	// FMV_X_D
    UINT64_C(3758096467),	// FMV_X_W
    UINT64_C(33554511),	// FNMADD_D
    UINT64_C(79),	// FNMADD_S
    UINT64_C(33554507),	// FNMSUB_D
    UINT64_C(75),	// FNMSUB_S
    UINT64_C(12327),	// FSD
    UINT64_C(570429523),	// FSGNJN_D
    UINT64_C(536875091),	// FSGNJN_S
    UINT64_C(570433619),	// FSGNJX_D
    UINT64_C(536879187),	// FSGNJX_S
    UINT64_C(570425427),	// FSGNJ_D
    UINT64_C(536870995),	// FSGNJ_S
    UINT64_C(1509949523),	// FSQRT_D
    UINT64_C(1476395091),	// FSQRT_S
    UINT64_C(167772243),	// FSUB_D
    UINT64_C(134217811),	// FSUB_S
    UINT64_C(8231),	// FSW
    UINT64_C(111),	// JAL
    UINT64_C(103),	// JALR
    UINT64_C(3),	// LB
    UINT64_C(16387),	// LBU
    UINT64_C(12291),	// LD
    UINT64_C(4099),	// LH
    UINT64_C(20483),	// LHU
    UINT64_C(268447791),	// LR_D
    UINT64_C(335556655),	// LR_D_AQ
    UINT64_C(369111087),	// LR_D_AQ_RL
    UINT64_C(302002223),	// LR_D_RL
    UINT64_C(268443695),	// LR_W
    UINT64_C(335552559),	// LR_W_AQ
    UINT64_C(369106991),	// LR_W_AQ_RL
    UINT64_C(301998127),	// LR_W_RL
    UINT64_C(55),	// LUI
    UINT64_C(8195),	// LW
    UINT64_C(24579),	// LWU
    UINT64_C(807403635),	// MRET
    UINT64_C(33554483),	// MUL
    UINT64_C(33558579),	// MULH
    UINT64_C(33562675),	// MULHSU
    UINT64_C(33566771),	// MULHU
    UINT64_C(33554491),	// MULW
    UINT64_C(24627),	// OR
    UINT64_C(24595),	// ORI
    UINT64_C(33579059),	// REM
    UINT64_C(33583155),	// REMU
    UINT64_C(33583163),	// REMUW
    UINT64_C(33579067),	// REMW
    UINT64_C(35),	// SB
    UINT64_C(402665519),	// SC_D
    UINT64_C(469774383),	// SC_D_AQ
    UINT64_C(503328815),	// SC_D_AQ_RL
    UINT64_C(436219951),	// SC_D_RL
    UINT64_C(402661423),	// SC_W
    UINT64_C(469770287),	// SC_W_AQ
    UINT64_C(503324719),	// SC_W_AQ_RL
    UINT64_C(436215855),	// SC_W_RL
    UINT64_C(12323),	// SD
    UINT64_C(301990003),	// SFENCE_VMA
    UINT64_C(4131),	// SH
    UINT64_C(4147),	// SLL
    UINT64_C(4115),	// SLLI
    UINT64_C(4123),	// SLLIW
    UINT64_C(4155),	// SLLW
    UINT64_C(8243),	// SLT
    UINT64_C(8211),	// SLTI
    UINT64_C(12307),	// SLTIU
    UINT64_C(12339),	// SLTU
    UINT64_C(1073762355),	// SRA
    UINT64_C(1073762323),	// SRAI
    UINT64_C(1073762331),	// SRAIW
    UINT64_C(1073762363),	// SRAW
    UINT64_C(270532723),	// SRET
    UINT64_C(20531),	// SRL
    UINT64_C(20499),	// SRLI
    UINT64_C(20507),	// SRLIW
    UINT64_C(20539),	// SRLW
    UINT64_C(1073741875),	// SUB
    UINT64_C(1073741883),	// SUBW
    UINT64_C(8227),	// SW
    UINT64_C(3221229683),	// UNIMP
    UINT64_C(2097267),	// URET
    UINT64_C(273678451),	// WFI
    UINT64_C(16435),	// XOR
    UINT64_C(16403),	// XORI
    UINT64_C(0)
  };
  const unsigned opcode = MI.getOpcode();
  uint64_t Value = InstBits[opcode];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case RISCV::C_EBREAK:
    case RISCV::C_NOP:
    case RISCV::C_UNIMP:
    case RISCV::EBREAK:
    case RISCV::ECALL:
    case RISCV::FENCE_I:
    case RISCV::FENCE_TSO:
    case RISCV::MRET:
    case RISCV::SRET:
    case RISCV::UNIMP:
    case RISCV::URET:
    case RISCV::WFI: {
      break;
    }
    case RISCV::C_LI:
    case RISCV::C_LUI: {
      // op: imm
      op = getImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_FLDSP:
    case RISCV::C_LDSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(24)) << 2;
      Value |= (op & UINT64_C(448)) >> 4;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_FLWSP:
    case RISCV::C_LWSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(28)) << 2;
      Value |= (op & UINT64_C(192)) >> 4;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADDI:
    case RISCV::C_ADDIW: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ANDI: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::C_ADDI4SPN: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(48)) << 7;
      Value |= (op & UINT64_C(960)) << 1;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(8)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      break;
    }
    case RISCV::C_ADDI16SP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(512)) << 3;
      Value |= (op & UINT64_C(16)) << 2;
      Value |= (op & UINT64_C(64)) >> 1;
      Value |= (op & UINT64_C(384)) >> 4;
      Value |= (op & UINT64_C(32)) >> 3;
      break;
    }
    case RISCV::C_FSDSP:
    case RISCV::C_SDSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(448)) << 1;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_FSWSP:
    case RISCV::C_SWSP: {
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(60)) << 7;
      Value |= (op & UINT64_C(192)) << 1;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_BEQZ:
    case RISCV::C_BNEZ: {
      // op: imm
      op = getImmOpValueAsr1(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(128)) << 5;
      Value |= (op & UINT64_C(12)) << 8;
      Value |= op & UINT64_C(96);
      Value |= (op & UINT64_C(3)) << 3;
      Value |= (op & UINT64_C(16)) >> 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::C_SLLI: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_SRAI:
    case RISCV::C_SRLI: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 7;
      Value |= (op & UINT64_C(31)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::FSD:
    case RISCV::FSW:
    case RISCV::SB:
    case RISCV::SD:
    case RISCV::SH:
    case RISCV::SW: {
      // op: imm12
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(4064)) << 20;
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::ADDI:
    case RISCV::ADDIW:
    case RISCV::ANDI:
    case RISCV::FLD:
    case RISCV::FLW:
    case RISCV::JALR:
    case RISCV::LB:
    case RISCV::LBU:
    case RISCV::LD:
    case RISCV::LH:
    case RISCV::LHU:
    case RISCV::LW:
    case RISCV::LWU:
    case RISCV::ORI:
    case RISCV::SLTI:
    case RISCV::SLTIU:
    case RISCV::XORI: {
      // op: imm12
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(4095)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::BEQ:
    case RISCV::BGE:
    case RISCV::BGEU:
    case RISCV::BLT:
    case RISCV::BLTU:
    case RISCV::BNE: {
      // op: imm12
      op = getImmOpValueAsr1(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(2048)) << 20;
      Value |= (op & UINT64_C(1008)) << 21;
      Value |= (op & UINT64_C(15)) << 8;
      Value |= (op & UINT64_C(1024)) >> 3;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::CSRRC:
    case RISCV::CSRRCI:
    case RISCV::CSRRS:
    case RISCV::CSRRSI:
    case RISCV::CSRRW:
    case RISCV::CSRRWI: {
      // op: imm12
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(4095)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::AUIPC:
    case RISCV::LUI: {
      // op: imm20
      op = getImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(1048575)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::JAL: {
      // op: imm20
      op = getImmOpValueAsr1(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(524288)) << 12;
      Value |= (op & UINT64_C(1023)) << 21;
      Value |= (op & UINT64_C(1024)) << 10;
      Value |= (op & UINT64_C(522240)) << 1;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_J:
    case RISCV::C_JAL: {
      // op: offset
      op = getImmOpValueAsr1(MI, 0, Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 2;
      Value |= (op & UINT64_C(8)) << 8;
      Value |= (op & UINT64_C(384)) << 2;
      Value |= (op & UINT64_C(512)) >> 1;
      Value |= (op & UINT64_C(32)) << 2;
      Value |= op & UINT64_C(64);
      Value |= (op & UINT64_C(7)) << 3;
      Value |= (op & UINT64_C(16)) >> 2;
      break;
    }
    case RISCV::FENCE: {
      // op: pred
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 24;
      // op: succ
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 20;
      break;
    }
    case RISCV::C_FLD:
    case RISCV::C_LD: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(192)) >> 1;
      break;
    }
    case RISCV::C_FLW:
    case RISCV::C_LW: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(64)) >> 1;
      break;
    }
    case RISCV::C_JALR:
    case RISCV::C_JR: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_MV: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::FCVT_D_L:
    case RISCV::FCVT_D_LU:
    case RISCV::FCVT_LU_D:
    case RISCV::FCVT_LU_S:
    case RISCV::FCVT_L_D:
    case RISCV::FCVT_L_S:
    case RISCV::FCVT_S_D:
    case RISCV::FCVT_S_L:
    case RISCV::FCVT_S_LU:
    case RISCV::FCVT_S_W:
    case RISCV::FCVT_S_WU:
    case RISCV::FCVT_WU_D:
    case RISCV::FCVT_WU_S:
    case RISCV::FCVT_W_D:
    case RISCV::FCVT_W_S:
    case RISCV::FSQRT_D:
    case RISCV::FSQRT_S: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::FCLASS_D:
    case RISCV::FCLASS_S:
    case RISCV::FCVT_D_S:
    case RISCV::FCVT_D_W:
    case RISCV::FCVT_D_WU:
    case RISCV::FMV_D_X:
    case RISCV::FMV_W_X:
    case RISCV::FMV_X_D:
    case RISCV::FMV_X_W:
    case RISCV::LR_D:
    case RISCV::LR_D_AQ:
    case RISCV::LR_D_AQ_RL:
    case RISCV::LR_D_RL:
    case RISCV::LR_W:
    case RISCV::LR_W_AQ:
    case RISCV::LR_W_AQ_RL:
    case RISCV::LR_W_RL: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADD: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 2;
      break;
    }
    case RISCV::C_FSD:
    case RISCV::C_SD: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(192)) >> 1;
      break;
    }
    case RISCV::C_FSW:
    case RISCV::C_SW: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      // op: imm
      op = getImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & UINT64_C(56)) << 7;
      Value |= (op & UINT64_C(4)) << 4;
      Value |= (op & UINT64_C(64)) >> 1;
      break;
    }
    case RISCV::SFENCE_VMA: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      break;
    }
    case RISCV::FADD_D:
    case RISCV::FADD_S:
    case RISCV::FDIV_D:
    case RISCV::FDIV_S:
    case RISCV::FMUL_D:
    case RISCV::FMUL_S:
    case RISCV::FSUB_D:
    case RISCV::FSUB_S: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::ADD:
    case RISCV::ADDW:
    case RISCV::AMOADD_D:
    case RISCV::AMOADD_D_AQ:
    case RISCV::AMOADD_D_AQ_RL:
    case RISCV::AMOADD_D_RL:
    case RISCV::AMOADD_W:
    case RISCV::AMOADD_W_AQ:
    case RISCV::AMOADD_W_AQ_RL:
    case RISCV::AMOADD_W_RL:
    case RISCV::AMOAND_D:
    case RISCV::AMOAND_D_AQ:
    case RISCV::AMOAND_D_AQ_RL:
    case RISCV::AMOAND_D_RL:
    case RISCV::AMOAND_W:
    case RISCV::AMOAND_W_AQ:
    case RISCV::AMOAND_W_AQ_RL:
    case RISCV::AMOAND_W_RL:
    case RISCV::AMOMAXU_D:
    case RISCV::AMOMAXU_D_AQ:
    case RISCV::AMOMAXU_D_AQ_RL:
    case RISCV::AMOMAXU_D_RL:
    case RISCV::AMOMAXU_W:
    case RISCV::AMOMAXU_W_AQ:
    case RISCV::AMOMAXU_W_AQ_RL:
    case RISCV::AMOMAXU_W_RL:
    case RISCV::AMOMAX_D:
    case RISCV::AMOMAX_D_AQ:
    case RISCV::AMOMAX_D_AQ_RL:
    case RISCV::AMOMAX_D_RL:
    case RISCV::AMOMAX_W:
    case RISCV::AMOMAX_W_AQ:
    case RISCV::AMOMAX_W_AQ_RL:
    case RISCV::AMOMAX_W_RL:
    case RISCV::AMOMINU_D:
    case RISCV::AMOMINU_D_AQ:
    case RISCV::AMOMINU_D_AQ_RL:
    case RISCV::AMOMINU_D_RL:
    case RISCV::AMOMINU_W:
    case RISCV::AMOMINU_W_AQ:
    case RISCV::AMOMINU_W_AQ_RL:
    case RISCV::AMOMINU_W_RL:
    case RISCV::AMOMIN_D:
    case RISCV::AMOMIN_D_AQ:
    case RISCV::AMOMIN_D_AQ_RL:
    case RISCV::AMOMIN_D_RL:
    case RISCV::AMOMIN_W:
    case RISCV::AMOMIN_W_AQ:
    case RISCV::AMOMIN_W_AQ_RL:
    case RISCV::AMOMIN_W_RL:
    case RISCV::AMOOR_D:
    case RISCV::AMOOR_D_AQ:
    case RISCV::AMOOR_D_AQ_RL:
    case RISCV::AMOOR_D_RL:
    case RISCV::AMOOR_W:
    case RISCV::AMOOR_W_AQ:
    case RISCV::AMOOR_W_AQ_RL:
    case RISCV::AMOOR_W_RL:
    case RISCV::AMOSWAP_D:
    case RISCV::AMOSWAP_D_AQ:
    case RISCV::AMOSWAP_D_AQ_RL:
    case RISCV::AMOSWAP_D_RL:
    case RISCV::AMOSWAP_W:
    case RISCV::AMOSWAP_W_AQ:
    case RISCV::AMOSWAP_W_AQ_RL:
    case RISCV::AMOSWAP_W_RL:
    case RISCV::AMOXOR_D:
    case RISCV::AMOXOR_D_AQ:
    case RISCV::AMOXOR_D_AQ_RL:
    case RISCV::AMOXOR_D_RL:
    case RISCV::AMOXOR_W:
    case RISCV::AMOXOR_W_AQ:
    case RISCV::AMOXOR_W_AQ_RL:
    case RISCV::AMOXOR_W_RL:
    case RISCV::AND:
    case RISCV::DIV:
    case RISCV::DIVU:
    case RISCV::DIVUW:
    case RISCV::DIVW:
    case RISCV::FEQ_D:
    case RISCV::FEQ_S:
    case RISCV::FLE_D:
    case RISCV::FLE_S:
    case RISCV::FLT_D:
    case RISCV::FLT_S:
    case RISCV::FMAX_D:
    case RISCV::FMAX_S:
    case RISCV::FMIN_D:
    case RISCV::FMIN_S:
    case RISCV::FSGNJN_D:
    case RISCV::FSGNJN_S:
    case RISCV::FSGNJX_D:
    case RISCV::FSGNJX_S:
    case RISCV::FSGNJ_D:
    case RISCV::FSGNJ_S:
    case RISCV::MUL:
    case RISCV::MULH:
    case RISCV::MULHSU:
    case RISCV::MULHU:
    case RISCV::MULW:
    case RISCV::OR:
    case RISCV::REM:
    case RISCV::REMU:
    case RISCV::REMUW:
    case RISCV::REMW:
    case RISCV::SC_D:
    case RISCV::SC_D_AQ:
    case RISCV::SC_D_AQ_RL:
    case RISCV::SC_D_RL:
    case RISCV::SC_W:
    case RISCV::SC_W_AQ:
    case RISCV::SC_W_AQ_RL:
    case RISCV::SC_W_RL:
    case RISCV::SLL:
    case RISCV::SLLW:
    case RISCV::SLT:
    case RISCV::SLTU:
    case RISCV::SRA:
    case RISCV::SRAW:
    case RISCV::SRL:
    case RISCV::SRLW:
    case RISCV::SUB:
    case RISCV::SUBW:
    case RISCV::XOR: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::C_ADDW:
    case RISCV::C_AND:
    case RISCV::C_OR:
    case RISCV::C_SUB:
    case RISCV::C_SUBW:
    case RISCV::C_XOR: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 2;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 7;
      break;
    }
    case RISCV::FMADD_D:
    case RISCV::FMADD_S:
    case RISCV::FMSUB_D:
    case RISCV::FMSUB_S:
    case RISCV::FNMADD_D:
    case RISCV::FNMADD_S:
    case RISCV::FNMSUB_D:
    case RISCV::FNMSUB_S: {
      // op: rs3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 27;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: funct3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 12;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::SLLIW:
    case RISCV::SRAIW:
    case RISCV::SRLIW: {
      // op: shamt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
    case RISCV::SLLI:
    case RISCV::SRAI:
    case RISCV::SRLI: {
      // op: shamt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 20;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 15;
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 7;
      break;
    }
  default:
    std::string msg;
    raw_string_ostream Msg(msg);
    Msg << "Not supported instr: " << MI;
    report_fatal_error(Msg.str());
  }
  return Value;
}

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER
#include <sstream>

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

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasStdExtA",
  "Feature_HasStdExtC",
  "Feature_HasStdExtD",
  "Feature_HasStdExtF",
  "Feature_HasStdExtM",
  "Feature_IsRV32",
  "Feature_IsRV64",
  nullptr
};

#endif // NDEBUG
uint64_t RISCVMCCodeEmitter::
computeAvailableFeatures(const FeatureBitset& FB) const {
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

void RISCVMCCodeEmitter::verifyInstructionPredicates(
    const MCInst &Inst, uint64_t AvailableFeatures) const {
#ifndef NDEBUG
  static uint64_t RequiredFeatures[] = {
    0, // PHI = 0
    0, // INLINEASM = 1
    0, // CFI_INSTRUCTION = 2
    0, // EH_LABEL = 3
    0, // GC_LABEL = 4
    0, // ANNOTATION_LABEL = 5
    0, // KILL = 6
    0, // EXTRACT_SUBREG = 7
    0, // INSERT_SUBREG = 8
    0, // IMPLICIT_DEF = 9
    0, // SUBREG_TO_REG = 10
    0, // COPY_TO_REGCLASS = 11
    0, // DBG_VALUE = 12
    0, // DBG_LABEL = 13
    0, // REG_SEQUENCE = 14
    0, // COPY = 15
    0, // BUNDLE = 16
    0, // LIFETIME_START = 17
    0, // LIFETIME_END = 18
    0, // STACKMAP = 19
    0, // FENTRY_CALL = 20
    0, // PATCHPOINT = 21
    0, // LOAD_STACK_GUARD = 22
    0, // STATEPOINT = 23
    0, // LOCAL_ESCAPE = 24
    0, // FAULTING_OP = 25
    0, // PATCHABLE_OP = 26
    0, // PATCHABLE_FUNCTION_ENTER = 27
    0, // PATCHABLE_RET = 28
    0, // PATCHABLE_FUNCTION_EXIT = 29
    0, // PATCHABLE_TAIL_CALL = 30
    0, // PATCHABLE_EVENT_CALL = 31
    0, // PATCHABLE_TYPED_EVENT_CALL = 32
    0, // ICALL_BRANCH_FUNNEL = 33
    0, // G_ADD = 34
    0, // G_SUB = 35
    0, // G_MUL = 36
    0, // G_SDIV = 37
    0, // G_UDIV = 38
    0, // G_SREM = 39
    0, // G_UREM = 40
    0, // G_AND = 41
    0, // G_OR = 42
    0, // G_XOR = 43
    0, // G_IMPLICIT_DEF = 44
    0, // G_PHI = 45
    0, // G_FRAME_INDEX = 46
    0, // G_GLOBAL_VALUE = 47
    0, // G_EXTRACT = 48
    0, // G_UNMERGE_VALUES = 49
    0, // G_INSERT = 50
    0, // G_MERGE_VALUES = 51
    0, // G_BUILD_VECTOR = 52
    0, // G_BUILD_VECTOR_TRUNC = 53
    0, // G_CONCAT_VECTORS = 54
    0, // G_PTRTOINT = 55
    0, // G_INTTOPTR = 56
    0, // G_BITCAST = 57
    0, // G_INTRINSIC_TRUNC = 58
    0, // G_INTRINSIC_ROUND = 59
    0, // G_LOAD = 60
    0, // G_SEXTLOAD = 61
    0, // G_ZEXTLOAD = 62
    0, // G_STORE = 63
    0, // G_ATOMIC_CMPXCHG_WITH_SUCCESS = 64
    0, // G_ATOMIC_CMPXCHG = 65
    0, // G_ATOMICRMW_XCHG = 66
    0, // G_ATOMICRMW_ADD = 67
    0, // G_ATOMICRMW_SUB = 68
    0, // G_ATOMICRMW_AND = 69
    0, // G_ATOMICRMW_NAND = 70
    0, // G_ATOMICRMW_OR = 71
    0, // G_ATOMICRMW_XOR = 72
    0, // G_ATOMICRMW_MAX = 73
    0, // G_ATOMICRMW_MIN = 74
    0, // G_ATOMICRMW_UMAX = 75
    0, // G_ATOMICRMW_UMIN = 76
    0, // G_BRCOND = 77
    0, // G_BRINDIRECT = 78
    0, // G_INTRINSIC = 79
    0, // G_INTRINSIC_W_SIDE_EFFECTS = 80
    0, // G_ANYEXT = 81
    0, // G_TRUNC = 82
    0, // G_CONSTANT = 83
    0, // G_FCONSTANT = 84
    0, // G_VASTART = 85
    0, // G_VAARG = 86
    0, // G_SEXT = 87
    0, // G_ZEXT = 88
    0, // G_SHL = 89
    0, // G_LSHR = 90
    0, // G_ASHR = 91
    0, // G_ICMP = 92
    0, // G_FCMP = 93
    0, // G_SELECT = 94
    0, // G_UADDO = 95
    0, // G_UADDE = 96
    0, // G_USUBO = 97
    0, // G_USUBE = 98
    0, // G_SADDO = 99
    0, // G_SADDE = 100
    0, // G_SSUBO = 101
    0, // G_SSUBE = 102
    0, // G_UMULO = 103
    0, // G_SMULO = 104
    0, // G_UMULH = 105
    0, // G_SMULH = 106
    0, // G_FADD = 107
    0, // G_FSUB = 108
    0, // G_FMUL = 109
    0, // G_FMA = 110
    0, // G_FDIV = 111
    0, // G_FREM = 112
    0, // G_FPOW = 113
    0, // G_FEXP = 114
    0, // G_FEXP2 = 115
    0, // G_FLOG = 116
    0, // G_FLOG2 = 117
    0, // G_FLOG10 = 118
    0, // G_FNEG = 119
    0, // G_FPEXT = 120
    0, // G_FPTRUNC = 121
    0, // G_FPTOSI = 122
    0, // G_FPTOUI = 123
    0, // G_SITOFP = 124
    0, // G_UITOFP = 125
    0, // G_FABS = 126
    0, // G_GEP = 127
    0, // G_PTR_MASK = 128
    0, // G_BR = 129
    0, // G_INSERT_VECTOR_ELT = 130
    0, // G_EXTRACT_VECTOR_ELT = 131
    0, // G_SHUFFLE_VECTOR = 132
    0, // G_CTTZ = 133
    0, // G_CTTZ_ZERO_UNDEF = 134
    0, // G_CTLZ = 135
    0, // G_CTLZ_ZERO_UNDEF = 136
    0, // G_CTPOP = 137
    0, // G_BSWAP = 138
    0, // G_FCEIL = 139
    0, // G_ADDRSPACE_CAST = 140
    0, // G_BLOCK_ADDR = 141
    0, // ADJCALLSTACKDOWN = 142
    0, // ADJCALLSTACKUP = 143
    Feature_HasStdExtD | 0, // BuildPairF64Pseudo = 144
    Feature_HasStdExtA | 0, // PseudoAtomicLoadNand32 = 145
    0, // PseudoBR = 146
    0, // PseudoBRIND = 147
    0, // PseudoCALL = 148
    0, // PseudoCALLIndirect = 149
    Feature_HasStdExtA | 0, // PseudoCmpXchg32 = 150
    0, // PseudoLI = 151
    0, // PseudoLLA = 152
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadAdd32 = 153
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadMax32 = 154
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadMin32 = 155
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadNand32 = 156
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadSub32 = 157
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadUMax32 = 158
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicLoadUMin32 = 159
    Feature_HasStdExtA | 0, // PseudoMaskedAtomicSwap32 = 160
    Feature_HasStdExtA | 0, // PseudoMaskedCmpXchg32 = 161
    0, // PseudoRET = 162
    0, // PseudoTAIL = 163
    0, // PseudoTAILIndirect = 164
    Feature_HasStdExtF | 0, // Select_FPR32_Using_CC_GPR = 165
    Feature_HasStdExtD | 0, // Select_FPR64_Using_CC_GPR = 166
    0, // Select_GPR_Using_CC_GPR = 167
    Feature_HasStdExtD | 0, // SplitF64Pseudo = 168
    0, // ADD = 169
    0, // ADDI = 170
    Feature_IsRV64 | 0, // ADDIW = 171
    Feature_IsRV64 | 0, // ADDW = 172
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOADD_D = 173
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOADD_D_AQ = 174
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOADD_D_AQ_RL = 175
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOADD_D_RL = 176
    Feature_HasStdExtA | 0, // AMOADD_W = 177
    Feature_HasStdExtA | 0, // AMOADD_W_AQ = 178
    Feature_HasStdExtA | 0, // AMOADD_W_AQ_RL = 179
    Feature_HasStdExtA | 0, // AMOADD_W_RL = 180
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOAND_D = 181
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOAND_D_AQ = 182
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOAND_D_AQ_RL = 183
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOAND_D_RL = 184
    Feature_HasStdExtA | 0, // AMOAND_W = 185
    Feature_HasStdExtA | 0, // AMOAND_W_AQ = 186
    Feature_HasStdExtA | 0, // AMOAND_W_AQ_RL = 187
    Feature_HasStdExtA | 0, // AMOAND_W_RL = 188
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAXU_D = 189
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAXU_D_AQ = 190
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAXU_D_AQ_RL = 191
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAXU_D_RL = 192
    Feature_HasStdExtA | 0, // AMOMAXU_W = 193
    Feature_HasStdExtA | 0, // AMOMAXU_W_AQ = 194
    Feature_HasStdExtA | 0, // AMOMAXU_W_AQ_RL = 195
    Feature_HasStdExtA | 0, // AMOMAXU_W_RL = 196
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAX_D = 197
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAX_D_AQ = 198
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAX_D_AQ_RL = 199
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMAX_D_RL = 200
    Feature_HasStdExtA | 0, // AMOMAX_W = 201
    Feature_HasStdExtA | 0, // AMOMAX_W_AQ = 202
    Feature_HasStdExtA | 0, // AMOMAX_W_AQ_RL = 203
    Feature_HasStdExtA | 0, // AMOMAX_W_RL = 204
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMINU_D = 205
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMINU_D_AQ = 206
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMINU_D_AQ_RL = 207
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMINU_D_RL = 208
    Feature_HasStdExtA | 0, // AMOMINU_W = 209
    Feature_HasStdExtA | 0, // AMOMINU_W_AQ = 210
    Feature_HasStdExtA | 0, // AMOMINU_W_AQ_RL = 211
    Feature_HasStdExtA | 0, // AMOMINU_W_RL = 212
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMIN_D = 213
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMIN_D_AQ = 214
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMIN_D_AQ_RL = 215
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOMIN_D_RL = 216
    Feature_HasStdExtA | 0, // AMOMIN_W = 217
    Feature_HasStdExtA | 0, // AMOMIN_W_AQ = 218
    Feature_HasStdExtA | 0, // AMOMIN_W_AQ_RL = 219
    Feature_HasStdExtA | 0, // AMOMIN_W_RL = 220
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOOR_D = 221
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOOR_D_AQ = 222
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOOR_D_AQ_RL = 223
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOOR_D_RL = 224
    Feature_HasStdExtA | 0, // AMOOR_W = 225
    Feature_HasStdExtA | 0, // AMOOR_W_AQ = 226
    Feature_HasStdExtA | 0, // AMOOR_W_AQ_RL = 227
    Feature_HasStdExtA | 0, // AMOOR_W_RL = 228
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOSWAP_D = 229
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOSWAP_D_AQ = 230
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOSWAP_D_AQ_RL = 231
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOSWAP_D_RL = 232
    Feature_HasStdExtA | 0, // AMOSWAP_W = 233
    Feature_HasStdExtA | 0, // AMOSWAP_W_AQ = 234
    Feature_HasStdExtA | 0, // AMOSWAP_W_AQ_RL = 235
    Feature_HasStdExtA | 0, // AMOSWAP_W_RL = 236
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOXOR_D = 237
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOXOR_D_AQ = 238
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOXOR_D_AQ_RL = 239
    Feature_HasStdExtA | Feature_IsRV64 | 0, // AMOXOR_D_RL = 240
    Feature_HasStdExtA | 0, // AMOXOR_W = 241
    Feature_HasStdExtA | 0, // AMOXOR_W_AQ = 242
    Feature_HasStdExtA | 0, // AMOXOR_W_AQ_RL = 243
    Feature_HasStdExtA | 0, // AMOXOR_W_RL = 244
    0, // AND = 245
    0, // ANDI = 246
    0, // AUIPC = 247
    0, // BEQ = 248
    0, // BGE = 249
    0, // BGEU = 250
    0, // BLT = 251
    0, // BLTU = 252
    0, // BNE = 253
    0, // CSRRC = 254
    0, // CSRRCI = 255
    0, // CSRRS = 256
    0, // CSRRSI = 257
    0, // CSRRW = 258
    0, // CSRRWI = 259
    Feature_HasStdExtC | 0, // C_ADD = 260
    Feature_HasStdExtC | 0, // C_ADDI = 261
    Feature_HasStdExtC | 0, // C_ADDI16SP = 262
    Feature_HasStdExtC | 0, // C_ADDI4SPN = 263
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_ADDIW = 264
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_ADDW = 265
    Feature_HasStdExtC | 0, // C_AND = 266
    Feature_HasStdExtC | 0, // C_ANDI = 267
    Feature_HasStdExtC | 0, // C_BEQZ = 268
    Feature_HasStdExtC | 0, // C_BNEZ = 269
    Feature_HasStdExtC | 0, // C_EBREAK = 270
    Feature_HasStdExtC | Feature_HasStdExtD | 0, // C_FLD = 271
    Feature_HasStdExtC | Feature_HasStdExtD | 0, // C_FLDSP = 272
    Feature_HasStdExtC | Feature_HasStdExtF | Feature_IsRV32 | 0, // C_FLW = 273
    Feature_HasStdExtC | Feature_HasStdExtF | Feature_IsRV32 | 0, // C_FLWSP = 274
    Feature_HasStdExtC | Feature_HasStdExtD | 0, // C_FSD = 275
    Feature_HasStdExtC | Feature_HasStdExtD | 0, // C_FSDSP = 276
    Feature_HasStdExtC | Feature_HasStdExtF | Feature_IsRV32 | 0, // C_FSW = 277
    Feature_HasStdExtC | Feature_HasStdExtF | Feature_IsRV32 | 0, // C_FSWSP = 278
    Feature_HasStdExtC | 0, // C_J = 279
    Feature_HasStdExtC | Feature_IsRV32 | 0, // C_JAL = 280
    Feature_HasStdExtC | 0, // C_JALR = 281
    Feature_HasStdExtC | 0, // C_JR = 282
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_LD = 283
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_LDSP = 284
    Feature_HasStdExtC | 0, // C_LI = 285
    Feature_HasStdExtC | 0, // C_LUI = 286
    Feature_HasStdExtC | 0, // C_LW = 287
    Feature_HasStdExtC | 0, // C_LWSP = 288
    Feature_HasStdExtC | 0, // C_MV = 289
    Feature_HasStdExtC | 0, // C_NOP = 290
    Feature_HasStdExtC | 0, // C_OR = 291
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_SD = 292
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_SDSP = 293
    Feature_HasStdExtC | 0, // C_SLLI = 294
    Feature_HasStdExtC | 0, // C_SRAI = 295
    Feature_HasStdExtC | 0, // C_SRLI = 296
    Feature_HasStdExtC | 0, // C_SUB = 297
    Feature_HasStdExtC | Feature_IsRV64 | 0, // C_SUBW = 298
    Feature_HasStdExtC | 0, // C_SW = 299
    Feature_HasStdExtC | 0, // C_SWSP = 300
    Feature_HasStdExtC | 0, // C_UNIMP = 301
    Feature_HasStdExtC | 0, // C_XOR = 302
    Feature_HasStdExtM | 0, // DIV = 303
    Feature_HasStdExtM | 0, // DIVU = 304
    Feature_HasStdExtM | Feature_IsRV64 | 0, // DIVUW = 305
    Feature_HasStdExtM | Feature_IsRV64 | 0, // DIVW = 306
    0, // EBREAK = 307
    0, // ECALL = 308
    Feature_HasStdExtD | 0, // FADD_D = 309
    Feature_HasStdExtF | 0, // FADD_S = 310
    Feature_HasStdExtD | 0, // FCLASS_D = 311
    Feature_HasStdExtF | 0, // FCLASS_S = 312
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FCVT_D_L = 313
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FCVT_D_LU = 314
    Feature_HasStdExtD | 0, // FCVT_D_S = 315
    Feature_HasStdExtD | 0, // FCVT_D_W = 316
    Feature_HasStdExtD | 0, // FCVT_D_WU = 317
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FCVT_LU_D = 318
    Feature_HasStdExtF | Feature_IsRV64 | 0, // FCVT_LU_S = 319
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FCVT_L_D = 320
    Feature_HasStdExtF | Feature_IsRV64 | 0, // FCVT_L_S = 321
    Feature_HasStdExtD | 0, // FCVT_S_D = 322
    Feature_HasStdExtF | Feature_IsRV64 | 0, // FCVT_S_L = 323
    Feature_HasStdExtF | Feature_IsRV64 | 0, // FCVT_S_LU = 324
    Feature_HasStdExtF | 0, // FCVT_S_W = 325
    Feature_HasStdExtF | 0, // FCVT_S_WU = 326
    Feature_HasStdExtD | 0, // FCVT_WU_D = 327
    Feature_HasStdExtF | 0, // FCVT_WU_S = 328
    Feature_HasStdExtD | 0, // FCVT_W_D = 329
    Feature_HasStdExtF | 0, // FCVT_W_S = 330
    Feature_HasStdExtD | 0, // FDIV_D = 331
    Feature_HasStdExtF | 0, // FDIV_S = 332
    0, // FENCE = 333
    0, // FENCE_I = 334
    0, // FENCE_TSO = 335
    Feature_HasStdExtD | 0, // FEQ_D = 336
    Feature_HasStdExtF | 0, // FEQ_S = 337
    Feature_HasStdExtD | 0, // FLD = 338
    Feature_HasStdExtD | 0, // FLE_D = 339
    Feature_HasStdExtF | 0, // FLE_S = 340
    Feature_HasStdExtD | 0, // FLT_D = 341
    Feature_HasStdExtF | 0, // FLT_S = 342
    Feature_HasStdExtF | 0, // FLW = 343
    Feature_HasStdExtD | 0, // FMADD_D = 344
    Feature_HasStdExtF | 0, // FMADD_S = 345
    Feature_HasStdExtD | 0, // FMAX_D = 346
    Feature_HasStdExtF | 0, // FMAX_S = 347
    Feature_HasStdExtD | 0, // FMIN_D = 348
    Feature_HasStdExtF | 0, // FMIN_S = 349
    Feature_HasStdExtD | 0, // FMSUB_D = 350
    Feature_HasStdExtF | 0, // FMSUB_S = 351
    Feature_HasStdExtD | 0, // FMUL_D = 352
    Feature_HasStdExtF | 0, // FMUL_S = 353
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FMV_D_X = 354
    Feature_HasStdExtF | 0, // FMV_W_X = 355
    Feature_HasStdExtD | Feature_IsRV64 | 0, // FMV_X_D = 356
    Feature_HasStdExtF | 0, // FMV_X_W = 357
    Feature_HasStdExtD | 0, // FNMADD_D = 358
    Feature_HasStdExtF | 0, // FNMADD_S = 359
    Feature_HasStdExtD | 0, // FNMSUB_D = 360
    Feature_HasStdExtF | 0, // FNMSUB_S = 361
    Feature_HasStdExtD | 0, // FSD = 362
    Feature_HasStdExtD | 0, // FSGNJN_D = 363
    Feature_HasStdExtF | 0, // FSGNJN_S = 364
    Feature_HasStdExtD | 0, // FSGNJX_D = 365
    Feature_HasStdExtF | 0, // FSGNJX_S = 366
    Feature_HasStdExtD | 0, // FSGNJ_D = 367
    Feature_HasStdExtF | 0, // FSGNJ_S = 368
    Feature_HasStdExtD | 0, // FSQRT_D = 369
    Feature_HasStdExtF | 0, // FSQRT_S = 370
    Feature_HasStdExtD | 0, // FSUB_D = 371
    Feature_HasStdExtF | 0, // FSUB_S = 372
    Feature_HasStdExtF | 0, // FSW = 373
    0, // JAL = 374
    0, // JALR = 375
    0, // LB = 376
    0, // LBU = 377
    Feature_IsRV64 | 0, // LD = 378
    0, // LH = 379
    0, // LHU = 380
    Feature_HasStdExtA | Feature_IsRV64 | 0, // LR_D = 381
    Feature_HasStdExtA | Feature_IsRV64 | 0, // LR_D_AQ = 382
    Feature_HasStdExtA | Feature_IsRV64 | 0, // LR_D_AQ_RL = 383
    Feature_HasStdExtA | Feature_IsRV64 | 0, // LR_D_RL = 384
    Feature_HasStdExtA | 0, // LR_W = 385
    Feature_HasStdExtA | 0, // LR_W_AQ = 386
    Feature_HasStdExtA | 0, // LR_W_AQ_RL = 387
    Feature_HasStdExtA | 0, // LR_W_RL = 388
    0, // LUI = 389
    0, // LW = 390
    Feature_IsRV64 | 0, // LWU = 391
    0, // MRET = 392
    Feature_HasStdExtM | 0, // MUL = 393
    Feature_HasStdExtM | 0, // MULH = 394
    Feature_HasStdExtM | 0, // MULHSU = 395
    Feature_HasStdExtM | 0, // MULHU = 396
    Feature_HasStdExtM | Feature_IsRV64 | 0, // MULW = 397
    0, // OR = 398
    0, // ORI = 399
    Feature_HasStdExtM | 0, // REM = 400
    Feature_HasStdExtM | 0, // REMU = 401
    Feature_HasStdExtM | Feature_IsRV64 | 0, // REMUW = 402
    Feature_HasStdExtM | Feature_IsRV64 | 0, // REMW = 403
    0, // SB = 404
    Feature_HasStdExtA | Feature_IsRV64 | 0, // SC_D = 405
    Feature_HasStdExtA | Feature_IsRV64 | 0, // SC_D_AQ = 406
    Feature_HasStdExtA | Feature_IsRV64 | 0, // SC_D_AQ_RL = 407
    Feature_HasStdExtA | Feature_IsRV64 | 0, // SC_D_RL = 408
    Feature_HasStdExtA | 0, // SC_W = 409
    Feature_HasStdExtA | 0, // SC_W_AQ = 410
    Feature_HasStdExtA | 0, // SC_W_AQ_RL = 411
    Feature_HasStdExtA | 0, // SC_W_RL = 412
    Feature_IsRV64 | 0, // SD = 413
    0, // SFENCE_VMA = 414
    0, // SH = 415
    0, // SLL = 416
    0, // SLLI = 417
    Feature_IsRV64 | 0, // SLLIW = 418
    Feature_IsRV64 | 0, // SLLW = 419
    0, // SLT = 420
    0, // SLTI = 421
    0, // SLTIU = 422
    0, // SLTU = 423
    0, // SRA = 424
    0, // SRAI = 425
    Feature_IsRV64 | 0, // SRAIW = 426
    Feature_IsRV64 | 0, // SRAW = 427
    0, // SRET = 428
    0, // SRL = 429
    0, // SRLI = 430
    Feature_IsRV64 | 0, // SRLIW = 431
    Feature_IsRV64 | 0, // SRLW = 432
    0, // SUB = 433
    Feature_IsRV64 | 0, // SUBW = 434
    0, // SW = 435
    0, // UNIMP = 436
    0, // URET = 437
    0, // WFI = 438
    0, // XOR = 439
    0, // XORI = 440
  };

  assert(Inst.getOpcode() < 441);
  uint64_t MissingFeatures =
      (AvailableFeatures & RequiredFeatures[Inst.getOpcode()]) ^
      RequiredFeatures[Inst.getOpcode()];
  if (MissingFeatures) {
    std::ostringstream Msg;
    Msg << "Attempting to emit " << MCII.getName(Inst.getOpcode()).str()
        << " instruction but the ";
    for (unsigned i = 0; i < 8 * sizeof(MissingFeatures); ++i)
      if (MissingFeatures & (1ULL << i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str());
  }
#else
// Silence unused variable warning on targets that don't use MCII for other purposes (e.g. BPF).
(void)MCII;
#endif // NDEBUG
}
#endif
