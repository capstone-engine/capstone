// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.Union;
import com.sun.jna.NativeLong;

import java.util.List;
import java.util.Arrays;

class Arm {

  // ARM operand shift type
  public static final int ARM_SFT_INVALID = 0;
  public static final int ARM_SFT_ASR = 1;
  public static final int ARM_SFT_LSL = 2;
  public static final int ARM_SFT_LSR = 3;
  public static final int ARM_SFT_ROR = 4;
  public static final int ARM_SFT_RRX = 5;
  public static final int ARM_SFT_ASR_REG = 6;
  public static final int ARM_SFT_LSL_REG = 7;
  public static final int ARM_SFT_LSR_REG = 8;
  public static final int ARM_SFT_ROR_REG = 9;
  public static final int ARM_SFT_RRX_REG = 10;

  // ARM code condition type
  public static final int ARM_CC_INVALID = 0;
  public static final int ARM_CC_EQ = 1;
  public static final int ARM_CC_NE = 2;
  public static final int ARM_CC_HS = 3;
  public static final int ARM_CC_LO = 4;
  public static final int ARM_CC_MI = 5;
  public static final int ARM_CC_PL = 6;
  public static final int ARM_CC_VS = 7;
  public static final int ARM_CC_VC = 8;
  public static final int ARM_CC_HI = 9;
  public static final int ARM_CC_LS = 10;
  public static final int ARM_CC_GE = 11;
  public static final int ARM_CC_LT = 12;
  public static final int ARM_CC_GT = 13;
  public static final int ARM_CC_LE = 14;
  public static final int ARM_CC_AL = 15;

  // Operand type
  public static final int ARM_OP_INVALID = 0;  // Uninitialized.
  public static final int ARM_OP_REG = 1 ;  // Register operand.
  public static final int ARM_OP_CIMM = 2;   // C-Immediate operand.
  public static final int ARM_OP_PIMM = 3;   // C-Immediate operand.
  public static final int ARM_OP_IMM = 4 ;  // Immediate operand.
  public static final int ARM_OP_FP = 5  ;  // Floating-Point immediate operand.
  public static final int ARM_OP_MEM = 6 ;  // Memory operand

  public static class MemType extends Structure {
    public int base;
    public int index;
    public int scale;
    public long disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "scale", "disp");
    }
  }

  public static class OpValue extends Union implements Union.ByReference {
    public int reg;
    public long imm;
    public double fp;
    public MemType mem;

    public OpValue(Pointer p) {
      super(p);
      read();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem");
    }
  }

  public static class OpShift extends Structure implements Structure.ByReference {
    public int type;
    public int value;

    public OpShift(Pointer p) {
      super(p);
      read();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type","value");
    }
  }

  public static class Operand extends Structure {
    public OpShift shift;
    public int type;
    public OpValue value;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("shift", "type", "value");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {

    public Operand [] op;

    public OpInfo(Pointer p) {
      cc = p.getInt(0);
      update_flags = (boolean) (p.getByte(4) > 0);
      writeback = (boolean) (p.getByte(5) > 0);
      int op_count = p.getShort(6);
      if (op_count == 0) {
        op = null;
        return;
      }

      op = new Operand[op_count];
      for (int i=0; i<op_count; i++) {
        Pointer p1 = p.share(8 + i*40);
        op[i] = new Operand();
        op[i].shift = new OpShift(p1);
        op[i].type = p1.getInt(8);
        op[i].value = new OpValue(p1.share(16));
        if (op[i].type == ARM_OP_MEM) {
          op[i].value.setType(MemType.class);
          op[i].value.read();
        }
      }
    }
  }

  // ARM registers
  public static final int ARM_REG_INVALID = 0;
  public static final int ARM_REG_APSR = 1;
  public static final int ARM_REG_APSR_NZCV = 2;
  public static final int ARM_REG_CPSR = 3;
  public static final int ARM_REG_FPEXC = 4;
  public static final int ARM_REG_FPINST = 5;
  public static final int ARM_REG_FPSCR = 6;
  public static final int ARM_REG_FPSCR_NZCV = 7;
  public static final int ARM_REG_FPSID = 8;
  public static final int ARM_REG_ITSTATE = 9;
  public static final int ARM_REG_LR = 10;
  public static final int ARM_REG_PC = 11;
  public static final int ARM_REG_SP = 12;
  public static final int ARM_REG_SPSR = 13;
  public static final int ARM_REG_D0 = 14;
  public static final int ARM_REG_D1 = 15;
  public static final int ARM_REG_D2 = 16;
  public static final int ARM_REG_D3 = 17;
  public static final int ARM_REG_D4 = 18;
  public static final int ARM_REG_D5 = 19;
  public static final int ARM_REG_D6 = 20;
  public static final int ARM_REG_D7 = 21;
  public static final int ARM_REG_D8 = 22;
  public static final int ARM_REG_D9 = 23;
  public static final int ARM_REG_D10 = 24;
  public static final int ARM_REG_D11 = 25;
  public static final int ARM_REG_D12 = 26;
  public static final int ARM_REG_D13 = 27;
  public static final int ARM_REG_D14 = 28;
  public static final int ARM_REG_D15 = 29;
  public static final int ARM_REG_D16 = 30;
  public static final int ARM_REG_D17 = 31;
  public static final int ARM_REG_D18 = 32;
  public static final int ARM_REG_D19 = 33;
  public static final int ARM_REG_D20 = 34;
  public static final int ARM_REG_D21 = 35;
  public static final int ARM_REG_D22 = 36;
  public static final int ARM_REG_D23 = 37;
  public static final int ARM_REG_D24 = 38;
  public static final int ARM_REG_D25 = 39;
  public static final int ARM_REG_D26 = 40;
  public static final int ARM_REG_D27 = 41;
  public static final int ARM_REG_D28 = 42;
  public static final int ARM_REG_D29 = 43;
  public static final int ARM_REG_D30 = 44;
  public static final int ARM_REG_D31 = 45;
  public static final int ARM_REG_FPINST2 = 46;
  public static final int ARM_REG_MVFR0 = 47;
  public static final int ARM_REG_MVFR1 = 48;
  public static final int ARM_REG_Q0 = 49;
  public static final int ARM_REG_Q1 = 50;
  public static final int ARM_REG_Q2 = 51;
  public static final int ARM_REG_Q3 = 52;
  public static final int ARM_REG_Q4 = 53;
  public static final int ARM_REG_Q5 = 54;
  public static final int ARM_REG_Q6 = 55;
  public static final int ARM_REG_Q7 = 56;
  public static final int ARM_REG_Q8 = 57;
  public static final int ARM_REG_Q9 = 58;
  public static final int ARM_REG_Q10 = 59;
  public static final int ARM_REG_Q11 = 60;
  public static final int ARM_REG_Q12 = 61;
  public static final int ARM_REG_Q13 = 62;
  public static final int ARM_REG_Q14 = 63;
  public static final int ARM_REG_Q15 = 64;
  public static final int ARM_REG_R0 = 65;
  public static final int ARM_REG_R1 = 66;
  public static final int ARM_REG_R2 = 67;
  public static final int ARM_REG_R3 = 68;
  public static final int ARM_REG_R4 = 69;
  public static final int ARM_REG_R5 = 70;
  public static final int ARM_REG_R6 = 71;
  public static final int ARM_REG_R7 = 72;
  public static final int ARM_REG_R8 = 73;
  public static final int ARM_REG_R9 = 74;
  public static final int ARM_REG_R10 = 75;
  public static final int ARM_REG_R11 = 76;
  public static final int ARM_REG_R12 = 77;
  public static final int ARM_REG_S0 = 78;
  public static final int ARM_REG_S1 = 79;
  public static final int ARM_REG_S2 = 80;
  public static final int ARM_REG_S3 = 81;
  public static final int ARM_REG_S4 = 82;
  public static final int ARM_REG_S5 = 83;
  public static final int ARM_REG_S6 = 84;
  public static final int ARM_REG_S7 = 85;
  public static final int ARM_REG_S8 = 86;
  public static final int ARM_REG_S9 = 87;
  public static final int ARM_REG_S10 = 88;
  public static final int ARM_REG_S11 = 89;
  public static final int ARM_REG_S12 = 90;
  public static final int ARM_REG_S13 = 91;
  public static final int ARM_REG_S14 = 92;
  public static final int ARM_REG_S15 = 93;
  public static final int ARM_REG_S16 = 94;
  public static final int ARM_REG_S17 = 95;
  public static final int ARM_REG_S18 = 96;
  public static final int ARM_REG_S19 = 97;
  public static final int ARM_REG_S20 = 98;
  public static final int ARM_REG_S21 = 99;
  public static final int ARM_REG_S22 = 100;
  public static final int ARM_REG_S23 = 101;
  public static final int ARM_REG_S24 = 102;
  public static final int ARM_REG_S25 = 103;
  public static final int ARM_REG_S26 = 104;
  public static final int ARM_REG_S27 = 105;
  public static final int ARM_REG_S28 = 106;
  public static final int ARM_REG_S29 = 107;
  public static final int ARM_REG_S30 = 108;
  public static final int ARM_REG_S31 = 109;

  // ARM instructions
  public static final int ARM_INS_INVALID = 0;
  public static final int ARM_INS_ADC = 1;
  public static final int ARM_INS_ADD = 2;
  public static final int ARM_INS_ADR = 3;
  public static final int ARM_INS_AESD_8 = 4;
  public static final int ARM_INS_AESE_8 = 5;
  public static final int ARM_INS_AESIMC_8 = 6;
  public static final int ARM_INS_AESMC_8 = 7;
  public static final int ARM_INS_AND = 8;
  public static final int ARM_INS_BFC = 9;
  public static final int ARM_INS_BFI = 10;
  public static final int ARM_INS_BIC = 11;
  public static final int ARM_INS_BKPT = 12;
  public static final int ARM_INS_BL = 13;
  public static final int ARM_INS_BLX = 14;
  public static final int ARM_INS_BX = 15;
  public static final int ARM_INS_BXJ = 16;
  public static final int ARM_INS_B = 17;
  public static final int ARM_INS_CDP = 18;
  public static final int ARM_INS_CDP2 = 19;
  public static final int ARM_INS_CLREX = 20;
  public static final int ARM_INS_CLZ = 21;
  public static final int ARM_INS_CMN = 22;
  public static final int ARM_INS_CMP = 23;
  public static final int ARM_INS_CPS = 24;
  public static final int ARM_INS_CRC32B = 25;
  public static final int ARM_INS_CRC32CB = 26;
  public static final int ARM_INS_CRC32CH = 27;
  public static final int ARM_INS_CRC32CW = 28;
  public static final int ARM_INS_CRC32H = 29;
  public static final int ARM_INS_CRC32W = 30;
  public static final int ARM_INS_DBG = 31;
  public static final int ARM_INS_DMB = 32;
  public static final int ARM_INS_DSB = 33;
  public static final int ARM_INS_EOR = 34;
  public static final int ARM_INS_VMOV = 35;
  public static final int ARM_INS_FLDMDBX = 36;
  public static final int ARM_INS_FLDMIAX = 37;
  public static final int ARM_INS_VMRS = 38;
  public static final int ARM_INS_FSTMDBX = 39;
  public static final int ARM_INS_FSTMIAX = 40;
  public static final int ARM_INS_HINT = 41;
  public static final int ARM_INS_HLT = 42;
  public static final int ARM_INS_ISB = 43;
  public static final int ARM_INS_LDA = 44;
  public static final int ARM_INS_LDAB = 45;
  public static final int ARM_INS_LDAEX = 46;
  public static final int ARM_INS_LDAEXB = 47;
  public static final int ARM_INS_LDAEXD = 48;
  public static final int ARM_INS_LDAEXH = 49;
  public static final int ARM_INS_LDAH = 50;
  public static final int ARM_INS_LDC2L = 51;
  public static final int ARM_INS_LDC2 = 52;
  public static final int ARM_INS_LDCL = 53;
  public static final int ARM_INS_LDC = 54;
  public static final int ARM_INS_LDMDA = 55;
  public static final int ARM_INS_LDMDB = 56;
  public static final int ARM_INS_LDM = 57;
  public static final int ARM_INS_LDMIB = 58;
  public static final int ARM_INS_LDRBT = 59;
  public static final int ARM_INS_LDRB = 60;
  public static final int ARM_INS_LDRD = 61;
  public static final int ARM_INS_LDREX = 62;
  public static final int ARM_INS_LDREXB = 63;
  public static final int ARM_INS_LDREXD = 64;
  public static final int ARM_INS_LDREXH = 65;
  public static final int ARM_INS_LDRH = 66;
  public static final int ARM_INS_LDRHT = 67;
  public static final int ARM_INS_LDRSB = 68;
  public static final int ARM_INS_LDRSBT = 69;
  public static final int ARM_INS_LDRSH = 70;
  public static final int ARM_INS_LDRSHT = 71;
  public static final int ARM_INS_LDRT = 72;
  public static final int ARM_INS_LDR = 73;
  public static final int ARM_INS_MCR = 74;
  public static final int ARM_INS_MCR2 = 75;
  public static final int ARM_INS_MCRR = 76;
  public static final int ARM_INS_MCRR2 = 77;
  public static final int ARM_INS_MLA = 78;
  public static final int ARM_INS_MLS = 79;
  public static final int ARM_INS_MOV = 80;
  public static final int ARM_INS_MOVT = 81;
  public static final int ARM_INS_MOVW = 82;
  public static final int ARM_INS_MRC = 83;
  public static final int ARM_INS_MRC2 = 84;
  public static final int ARM_INS_MRRC = 85;
  public static final int ARM_INS_MRRC2 = 86;
  public static final int ARM_INS_MRS = 87;
  public static final int ARM_INS_MSR = 88;
  public static final int ARM_INS_MUL = 89;
  public static final int ARM_INS_MVN = 90;
  public static final int ARM_INS_ORR = 91;
  public static final int ARM_INS_PKHBT = 92;
  public static final int ARM_INS_PKHTB = 93;
  public static final int ARM_INS_PLDW = 94;
  public static final int ARM_INS_PLD = 95;
  public static final int ARM_INS_PLI = 96;
  public static final int ARM_INS_QADD = 97;
  public static final int ARM_INS_QADD16 = 98;
  public static final int ARM_INS_QADD8 = 99;
  public static final int ARM_INS_QASX = 100;
  public static final int ARM_INS_QDADD = 101;
  public static final int ARM_INS_QDSUB = 102;
  public static final int ARM_INS_QSAX = 103;
  public static final int ARM_INS_QSUB = 104;
  public static final int ARM_INS_QSUB16 = 105;
  public static final int ARM_INS_QSUB8 = 106;
  public static final int ARM_INS_RBIT = 107;
  public static final int ARM_INS_REV = 108;
  public static final int ARM_INS_REV16 = 109;
  public static final int ARM_INS_REVSH = 110;
  public static final int ARM_INS_RFEDA = 111;
  public static final int ARM_INS_RFEDB = 112;
  public static final int ARM_INS_RFEIA = 113;
  public static final int ARM_INS_RFEIB = 114;
  public static final int ARM_INS_RSB = 115;
  public static final int ARM_INS_RSC = 116;
  public static final int ARM_INS_SADD16 = 117;
  public static final int ARM_INS_SADD8 = 118;
  public static final int ARM_INS_SASX = 119;
  public static final int ARM_INS_SBC = 120;
  public static final int ARM_INS_SBFX = 121;
  public static final int ARM_INS_SDIV = 122;
  public static final int ARM_INS_SEL = 123;
  public static final int ARM_INS_SETEND = 124;
  public static final int ARM_INS_SHA1C_32 = 125;
  public static final int ARM_INS_SHA1H_32 = 126;
  public static final int ARM_INS_SHA1M_32 = 127;
  public static final int ARM_INS_SHA1P_32 = 128;
  public static final int ARM_INS_SHA1SU0_32 = 129;
  public static final int ARM_INS_SHA1SU1_32 = 130;
  public static final int ARM_INS_SHA256H_32 = 131;
  public static final int ARM_INS_SHA256H2_32 = 132;
  public static final int ARM_INS_SHA256SU0_32 = 133;
  public static final int ARM_INS_SHA256SU1_32 = 134;
  public static final int ARM_INS_SHADD16 = 135;
  public static final int ARM_INS_SHADD8 = 136;
  public static final int ARM_INS_SHASX = 137;
  public static final int ARM_INS_SHSAX = 138;
  public static final int ARM_INS_SHSUB16 = 139;
  public static final int ARM_INS_SHSUB8 = 140;
  public static final int ARM_INS_SMC = 141;
  public static final int ARM_INS_SMLABB = 142;
  public static final int ARM_INS_SMLABT = 143;
  public static final int ARM_INS_SMLAD = 144;
  public static final int ARM_INS_SMLADX = 145;
  public static final int ARM_INS_SMLAL = 146;
  public static final int ARM_INS_SMLALBB = 147;
  public static final int ARM_INS_SMLALBT = 148;
  public static final int ARM_INS_SMLALD = 149;
  public static final int ARM_INS_SMLALDX = 150;
  public static final int ARM_INS_SMLALTB = 151;
  public static final int ARM_INS_SMLALTT = 152;
  public static final int ARM_INS_SMLATB = 153;
  public static final int ARM_INS_SMLATT = 154;
  public static final int ARM_INS_SMLAWB = 155;
  public static final int ARM_INS_SMLAWT = 156;
  public static final int ARM_INS_SMLSD = 157;
  public static final int ARM_INS_SMLSDX = 158;
  public static final int ARM_INS_SMLSLD = 159;
  public static final int ARM_INS_SMLSLDX = 160;
  public static final int ARM_INS_SMMLA = 161;
  public static final int ARM_INS_SMMLAR = 162;
  public static final int ARM_INS_SMMLS = 163;
  public static final int ARM_INS_SMMLSR = 164;
  public static final int ARM_INS_SMMUL = 165;
  public static final int ARM_INS_SMMULR = 166;
  public static final int ARM_INS_SMUAD = 167;
  public static final int ARM_INS_SMUADX = 168;
  public static final int ARM_INS_SMULBB = 169;
  public static final int ARM_INS_SMULBT = 170;
  public static final int ARM_INS_SMULL = 171;
  public static final int ARM_INS_SMULTB = 172;
  public static final int ARM_INS_SMULTT = 173;
  public static final int ARM_INS_SMULWB = 174;
  public static final int ARM_INS_SMULWT = 175;
  public static final int ARM_INS_SMUSD = 176;
  public static final int ARM_INS_SMUSDX = 177;
  public static final int ARM_INS_SRSDA = 178;
  public static final int ARM_INS_SRSDB = 179;
  public static final int ARM_INS_SRSIA = 180;
  public static final int ARM_INS_SRSIB = 181;
  public static final int ARM_INS_SSAT = 182;
  public static final int ARM_INS_SSAT16 = 183;
  public static final int ARM_INS_SSAX = 184;
  public static final int ARM_INS_SSUB16 = 185;
  public static final int ARM_INS_SSUB8 = 186;
  public static final int ARM_INS_STC2L = 187;
  public static final int ARM_INS_STC2 = 188;
  public static final int ARM_INS_STCL = 189;
  public static final int ARM_INS_STC = 190;
  public static final int ARM_INS_STL = 191;
  public static final int ARM_INS_STLB = 192;
  public static final int ARM_INS_STLEX = 193;
  public static final int ARM_INS_STLEXB = 194;
  public static final int ARM_INS_STLEXD = 195;
  public static final int ARM_INS_STLEXH = 196;
  public static final int ARM_INS_STLH = 197;
  public static final int ARM_INS_STMDA = 198;
  public static final int ARM_INS_STMDB = 199;
  public static final int ARM_INS_STM = 200;
  public static final int ARM_INS_STMIB = 201;
  public static final int ARM_INS_STRBT = 202;
  public static final int ARM_INS_STRB = 203;
  public static final int ARM_INS_STRD = 204;
  public static final int ARM_INS_STREX = 205;
  public static final int ARM_INS_STREXB = 206;
  public static final int ARM_INS_STREXD = 207;
  public static final int ARM_INS_STREXH = 208;
  public static final int ARM_INS_STRH = 209;
  public static final int ARM_INS_STRHT = 210;
  public static final int ARM_INS_STRT = 211;
  public static final int ARM_INS_STR = 212;
  public static final int ARM_INS_SUB = 213;
  public static final int ARM_INS_SVC = 214;
  public static final int ARM_INS_SWP = 215;
  public static final int ARM_INS_SWPB = 216;
  public static final int ARM_INS_SXTAB = 217;
  public static final int ARM_INS_SXTAB16 = 218;
  public static final int ARM_INS_SXTAH = 219;
  public static final int ARM_INS_SXTB = 220;
  public static final int ARM_INS_SXTB16 = 221;
  public static final int ARM_INS_SXTH = 222;
  public static final int ARM_INS_TEQ = 223;
  public static final int ARM_INS_TRAP = 224;
  public static final int ARM_INS_TST = 225;
  public static final int ARM_INS_UADD16 = 226;
  public static final int ARM_INS_UADD8 = 227;
  public static final int ARM_INS_UASX = 228;
  public static final int ARM_INS_UBFX = 229;
  public static final int ARM_INS_UDIV = 230;
  public static final int ARM_INS_UHADD16 = 231;
  public static final int ARM_INS_UHADD8 = 232;
  public static final int ARM_INS_UHASX = 233;
  public static final int ARM_INS_UHSAX = 234;
  public static final int ARM_INS_UHSUB16 = 235;
  public static final int ARM_INS_UHSUB8 = 236;
  public static final int ARM_INS_UMAAL = 237;
  public static final int ARM_INS_UMLAL = 238;
  public static final int ARM_INS_UMULL = 239;
  public static final int ARM_INS_UQADD16 = 240;
  public static final int ARM_INS_UQADD8 = 241;
  public static final int ARM_INS_UQASX = 242;
  public static final int ARM_INS_UQSAX = 243;
  public static final int ARM_INS_UQSUB16 = 244;
  public static final int ARM_INS_UQSUB8 = 245;
  public static final int ARM_INS_USAD8 = 246;
  public static final int ARM_INS_USADA8 = 247;
  public static final int ARM_INS_USAT = 248;
  public static final int ARM_INS_USAT16 = 249;
  public static final int ARM_INS_USAX = 250;
  public static final int ARM_INS_USUB16 = 251;
  public static final int ARM_INS_USUB8 = 252;
  public static final int ARM_INS_UXTAB = 253;
  public static final int ARM_INS_UXTAB16 = 254;
  public static final int ARM_INS_UXTAH = 255;
  public static final int ARM_INS_UXTB = 256;
  public static final int ARM_INS_UXTB16 = 257;
  public static final int ARM_INS_UXTH = 258;
  public static final int ARM_INS_VABAL = 259;
  public static final int ARM_INS_VABA = 260;
  public static final int ARM_INS_VABDL = 261;
  public static final int ARM_INS_VABD = 262;
  public static final int ARM_INS_VABS = 263;
  public static final int ARM_INS_VACGE = 264;
  public static final int ARM_INS_VACGT = 265;
  public static final int ARM_INS_VADD = 266;
  public static final int ARM_INS_VADDHN = 267;
  public static final int ARM_INS_VADDL = 268;
  public static final int ARM_INS_VADDW = 269;
  public static final int ARM_INS_VAND = 270;
  public static final int ARM_INS_VBIC = 271;
  public static final int ARM_INS_VBIF = 272;
  public static final int ARM_INS_VBIT = 273;
  public static final int ARM_INS_VBSL = 274;
  public static final int ARM_INS_VCEQ = 275;
  public static final int ARM_INS_VCGE = 276;
  public static final int ARM_INS_VCGT = 277;
  public static final int ARM_INS_VCLE = 278;
  public static final int ARM_INS_VCLS = 279;
  public static final int ARM_INS_VCLT = 280;
  public static final int ARM_INS_VCLZ = 281;
  public static final int ARM_INS_VCMP = 282;
  public static final int ARM_INS_VCMPE = 283;
  public static final int ARM_INS_VCNT = 284;
  public static final int ARM_INS_VCVTA_S32_F32 = 285;
  public static final int ARM_INS_VCVTA_U32_F32 = 286;
  public static final int ARM_INS_VCVTA_S32_F64 = 287;
  public static final int ARM_INS_VCVTA_U32_F64 = 288;
  public static final int ARM_INS_VCVTB = 289;
  public static final int ARM_INS_VCVT = 290;
  public static final int ARM_INS_VCVTM_S32_F32 = 291;
  public static final int ARM_INS_VCVTM_U32_F32 = 292;
  public static final int ARM_INS_VCVTM_S32_F64 = 293;
  public static final int ARM_INS_VCVTM_U32_F64 = 294;
  public static final int ARM_INS_VCVTN_S32_F32 = 295;
  public static final int ARM_INS_VCVTN_U32_F32 = 296;
  public static final int ARM_INS_VCVTN_S32_F64 = 297;
  public static final int ARM_INS_VCVTN_U32_F64 = 298;
  public static final int ARM_INS_VCVTP_S32_F32 = 299;
  public static final int ARM_INS_VCVTP_U32_F32 = 300;
  public static final int ARM_INS_VCVTP_S32_F64 = 301;
  public static final int ARM_INS_VCVTP_U32_F64 = 302;
  public static final int ARM_INS_VCVTT = 303;
  public static final int ARM_INS_VDIV = 304;
  public static final int ARM_INS_VDUP = 305;
  public static final int ARM_INS_VEOR = 306;
  public static final int ARM_INS_VEXT = 307;
  public static final int ARM_INS_VFMA = 308;
  public static final int ARM_INS_VFMS = 309;
  public static final int ARM_INS_VFNMA = 310;
  public static final int ARM_INS_VFNMS = 311;
  public static final int ARM_INS_VHADD = 312;
  public static final int ARM_INS_VHSUB = 313;
  public static final int ARM_INS_VLD1 = 314;
  public static final int ARM_INS_VLD2 = 315;
  public static final int ARM_INS_VLD3 = 316;
  public static final int ARM_INS_VLD4 = 317;
  public static final int ARM_INS_VLDMDB = 318;
  public static final int ARM_INS_VLDMIA = 319;
  public static final int ARM_INS_VLDR = 320;
  public static final int ARM_INS_VMAXNM_F64 = 321;
  public static final int ARM_INS_VMAXNM_F32 = 322;
  public static final int ARM_INS_VMAX = 323;
  public static final int ARM_INS_VMINNM_F64 = 324;
  public static final int ARM_INS_VMINNM_F32 = 325;
  public static final int ARM_INS_VMIN = 326;
  public static final int ARM_INS_VMLA = 327;
  public static final int ARM_INS_VMLAL = 328;
  public static final int ARM_INS_VMLS = 329;
  public static final int ARM_INS_VMLSL = 330;
  public static final int ARM_INS_VMOVL = 331;
  public static final int ARM_INS_VMOVN = 332;
  public static final int ARM_INS_VMSR = 333;
  public static final int ARM_INS_VMUL = 334;
  public static final int ARM_INS_VMULL_P64 = 335;
  public static final int ARM_INS_VMULL = 336;
  public static final int ARM_INS_VMVN = 337;
  public static final int ARM_INS_VNEG = 338;
  public static final int ARM_INS_VNMLA = 339;
  public static final int ARM_INS_VNMLS = 340;
  public static final int ARM_INS_VNMUL = 341;
  public static final int ARM_INS_VORN = 342;
  public static final int ARM_INS_VORR = 343;
  public static final int ARM_INS_VPADAL = 344;
  public static final int ARM_INS_VPADDL = 345;
  public static final int ARM_INS_VPADD = 346;
  public static final int ARM_INS_VPMAX = 347;
  public static final int ARM_INS_VPMIN = 348;
  public static final int ARM_INS_VQABS = 349;
  public static final int ARM_INS_VQADD = 350;
  public static final int ARM_INS_VQDMLAL = 351;
  public static final int ARM_INS_VQDMLSL = 352;
  public static final int ARM_INS_VQDMULH = 353;
  public static final int ARM_INS_VQDMULL = 354;
  public static final int ARM_INS_VQMOVUN = 355;
  public static final int ARM_INS_VQMOVN = 356;
  public static final int ARM_INS_VQNEG = 357;
  public static final int ARM_INS_VQRDMULH = 358;
  public static final int ARM_INS_VQRSHL = 359;
  public static final int ARM_INS_VQRSHRN = 360;
  public static final int ARM_INS_VQRSHRUN = 361;
  public static final int ARM_INS_VQSHL = 362;
  public static final int ARM_INS_VQSHLU = 363;
  public static final int ARM_INS_VQSHRN = 364;
  public static final int ARM_INS_VQSHRUN = 365;
  public static final int ARM_INS_VQSUB = 366;
  public static final int ARM_INS_VRADDHN = 367;
  public static final int ARM_INS_VRECPE = 368;
  public static final int ARM_INS_VRECPS = 369;
  public static final int ARM_INS_VREV16 = 370;
  public static final int ARM_INS_VREV32 = 371;
  public static final int ARM_INS_VREV64 = 372;
  public static final int ARM_INS_VRHADD = 373;
  public static final int ARM_INS_VRINTA_F64 = 374;
  public static final int ARM_INS_VRINTA_F32 = 375;
  public static final int ARM_INS_VRINTM_F64 = 376;
  public static final int ARM_INS_VRINTM_F32 = 377;
  public static final int ARM_INS_VRINTN_F64 = 378;
  public static final int ARM_INS_VRINTN_F32 = 379;
  public static final int ARM_INS_VRINTP_F64 = 380;
  public static final int ARM_INS_VRINTP_F32 = 381;
  public static final int ARM_INS_VRINTR = 382;
  public static final int ARM_INS_VRINTX = 383;
  public static final int ARM_INS_VRINTX_F32 = 384;
  public static final int ARM_INS_VRINTZ = 385;
  public static final int ARM_INS_VRINTZ_F32 = 386;
  public static final int ARM_INS_VRSHL = 387;
  public static final int ARM_INS_VRSHRN = 388;
  public static final int ARM_INS_VRSHR = 389;
  public static final int ARM_INS_VRSQRTE = 390;
  public static final int ARM_INS_VRSQRTS = 391;
  public static final int ARM_INS_VRSRA = 392;
  public static final int ARM_INS_VRSUBHN = 393;
  public static final int ARM_INS_VSELEQ_F64 = 394;
  public static final int ARM_INS_VSELEQ_F32 = 395;
  public static final int ARM_INS_VSELGE_F64 = 396;
  public static final int ARM_INS_VSELGE_F32 = 397;
  public static final int ARM_INS_VSELGT_F64 = 398;
  public static final int ARM_INS_VSELGT_F32 = 399;
  public static final int ARM_INS_VSELVS_F64 = 400;
  public static final int ARM_INS_VSELVS_F32 = 401;
  public static final int ARM_INS_VSHLL = 402;
  public static final int ARM_INS_VSHL = 403;
  public static final int ARM_INS_VSHRN = 404;
  public static final int ARM_INS_VSHR = 405;
  public static final int ARM_INS_VSLI = 406;
  public static final int ARM_INS_VSQRT = 407;
  public static final int ARM_INS_VSRA = 408;
  public static final int ARM_INS_VSRI = 409;
  public static final int ARM_INS_VST1 = 410;
  public static final int ARM_INS_VST2 = 411;
  public static final int ARM_INS_VST3 = 412;
  public static final int ARM_INS_VST4 = 413;
  public static final int ARM_INS_VSTMDB = 414;
  public static final int ARM_INS_VSTMIA = 415;
  public static final int ARM_INS_VSTR = 416;
  public static final int ARM_INS_VSUB = 417;
  public static final int ARM_INS_VSUBHN = 418;
  public static final int ARM_INS_VSUBL = 419;
  public static final int ARM_INS_VSUBW = 420;
  public static final int ARM_INS_VSWP = 421;
  public static final int ARM_INS_VTBL = 422;
  public static final int ARM_INS_VTBX = 423;
  public static final int ARM_INS_VCVTR = 424;
  public static final int ARM_INS_VTRN = 425;
  public static final int ARM_INS_VTST = 426;
  public static final int ARM_INS_VUZP = 427;
  public static final int ARM_INS_VZIP = 428;
  public static final int ARM_INS_ADDW = 429;
  public static final int ARM_INS_ADR_W = 430;
  public static final int ARM_INS_ASR = 431;
  public static final int ARM_INS_DCPS1 = 432;
  public static final int ARM_INS_DCPS2 = 433;
  public static final int ARM_INS_DCPS3 = 434;
  public static final int ARM_INS_IT = 435;
  public static final int ARM_INS_LSL = 436;
  public static final int ARM_INS_LSR = 437;
  public static final int ARM_INS_ORN = 438;
  public static final int ARM_INS_ROR = 439;
  public static final int ARM_INS_RRX = 440;
  public static final int ARM_INS_SUBW = 441;
  public static final int ARM_INS_TBB = 442;
  public static final int ARM_INS_TBH = 443;
  public static final int ARM_INS_CBNZ = 444;
  public static final int ARM_INS_CBZ = 445;
  public static final int ARM_INS_NOP = 446;
  public static final int ARM_INS_POP = 447;
  public static final int ARM_INS_PUSH = 448;
  public static final int ARM_INS_SEV = 449;
  public static final int ARM_INS_SEVL = 450;
  public static final int ARM_INS_WFE = 451;
  public static final int ARM_INS_WFI = 452;
  public static final int ARM_INS_YIELD = 453;

  // ARM group of instructions
  public static final int ARM_GRP_INVALID = 0;
  public static final int ARM_GRP_CRYPTO = 1;
  public static final int ARM_GRP_DATABARRIER = 2;
  public static final int ARM_GRP_DIVIDE = 3;
  public static final int ARM_GRP_FPARMV8 = 4;
  public static final int ARM_GRP_MULTPRO = 5;
  public static final int ARM_GRP_NEON = 6;
  public static final int ARM_GRP_T2EXTRACTPACK = 7;
  public static final int ARM_GRP_THUMB2DSP = 8;
  public static final int ARM_GRP_TRUSTZONE = 9;
  public static final int ARM_GRP_V4T = 10;
  public static final int ARM_GRP_V5T = 11;
  public static final int ARM_GRP_V5TE = 12;
  public static final int ARM_GRP_V6 = 13;
  public static final int ARM_GRP_V6T2 = 14;
  public static final int ARM_GRP_V7 = 15;
  public static final int ARM_GRP_V8 = 16;
  public static final int ARM_GRP_VFP2 = 17;
  public static final int ARM_GRP_VFP3 = 18;
  public static final int ARM_GRP_VFP4 = 19;
  public static final int ARM_GRP_ARM = 20;
  public static final int ARM_GRP_MCLASS = 21;
  public static final int ARM_GRP_NOTMCLASS = 22;
  public static final int ARM_GRP_THUMB = 23;
  public static final int ARM_GRP_THUMB1ONLY = 24;
  public static final int ARM_GRP_THUMB2 = 25;
  public static final int ARM_GRP_PREV8 = 26;
  public static final int ARM_GRP_FPVMLX = 27;
  public static final int ARM_GRP_MULOPS = 28;
}
