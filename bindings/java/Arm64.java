// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.Union;
import com.sun.jna.NativeLong;

import java.util.List;
import java.util.Arrays;

class Arm64 {

// ARM64 operand shift type
public static final int ARM64_SFT_INVALID = 0;
public static final int ARM64_SFT_LSL = 1;
public static final int ARM64_SFT_MSL = 2;
public static final int ARM64_SFT_LSR = 3;
public static final int ARM64_SFT_ASR = 4;
public static final int ARM64_SFT_ROR = 5;

// ARM64 extension type (for operands)
public static final int ARM64_EXT_INVALID = 0;
public static final int ARM64_EXT_UXTB = 1;
public static final int ARM64_EXT_UXTH = 2;
public static final int ARM64_EXT_UXTW = 3;
public static final int ARM64_EXT_UXTX = 4;
public static final int ARM64_EXT_SXTB = 5;
public static final int ARM64_EXT_SXTH = 6;
public static final int ARM64_EXT_SXTW = 7;
public static final int ARM64_EXT_SXTX = 8;

// ARM64 code condition type
public static final int ARM64_CC_INVALID = 0;
public static final int ARM64_CC_EQ = 1;
public static final int ARM64_CC_NE = 2;
public static final int ARM64_CC_HS = 3;
public static final int ARM64_CC_LO = 4;
public static final int ARM64_CC_MI = 5;
public static final int ARM64_CC_PL = 6;
public static final int ARM64_CC_VS = 7;
public static final int ARM64_CC_VC = 8;
public static final int ARM64_CC_HI = 9;
public static final int ARM64_CC_LS = 10;
public static final int ARM64_CC_GE = 11;
public static final int ARM64_CC_LT = 12;
public static final int ARM64_CC_GT = 13;
public static final int ARM64_CC_LE = 14;
public static final int ARM64_CC_AL = 15;
public static final int ARM64_CC_NV = 16;

// Operand type
public static final int ARM64_OP_INVALID = 0;  // Uninitialized.
public static final int ARM64_OP_REG = 1;   // Register operand.
public static final int ARM64_OP_CIMM = 2;   // C-Immediate operand.
public static final int ARM64_OP_IMM = 3;   // Immediate operand.
public static final int ARM64_OP_FP = 4;    // Floating-Point immediate operand.
public static final int ARM64_OP_MEM = 5;   // Memory operand

  public static class MemType extends Structure {
    public int base;
    public int index;
    public long disp;

    @Override
		public List getFieldOrder() {
		  return Arrays.asList("base", "index", "disp");
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
    public int ext;
    public int type;
    public OpValue value;

    @Override
		public List getFieldOrder() {
		  return Arrays.asList("shift", "ext", "type", "value");
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
		    Pointer p1 = p.share(8 + i*32);
		    op[i] = new Operand();
		    op[i].shift = new OpShift(p1);
		    op[i].ext = p1.getInt(8);
		    op[i].type = p1.getInt(12);
		    op[i].value = new OpValue(p1.share(16));
		    if (op[i].type == ARM64_OP_MEM) {
		      op[i].value.setType(MemType.class);
		      op[i].value.read();
        }
      }
    }
  }

// ARM registers
public static final int ARM64_REG_INVALID = 0;
public static final int ARM64_REG_NZCV = 1;
public static final int ARM64_REG_WSP = 2;
public static final int ARM64_REG_WZR = 3;
public static final int ARM64_REG_SP = 4;
public static final int ARM64_REG_XZR = 5;
public static final int ARM64_REG_B0 = 6;
public static final int ARM64_REG_B1 = 7;
public static final int ARM64_REG_B2 = 8;
public static final int ARM64_REG_B3 = 9;
public static final int ARM64_REG_B4 = 10;
public static final int ARM64_REG_B5 = 11;
public static final int ARM64_REG_B6 = 12;
public static final int ARM64_REG_B7 = 13;
public static final int ARM64_REG_B8 = 14;
public static final int ARM64_REG_B9 = 15;
public static final int ARM64_REG_B10 = 16;
public static final int ARM64_REG_B11 = 17;
public static final int ARM64_REG_B12 = 18;
public static final int ARM64_REG_B13 = 19;
public static final int ARM64_REG_B14 = 20;
public static final int ARM64_REG_B15 = 21;
public static final int ARM64_REG_B16 = 22;
public static final int ARM64_REG_B17 = 23;
public static final int ARM64_REG_B18 = 24;
public static final int ARM64_REG_B19 = 25;
public static final int ARM64_REG_B20 = 26;
public static final int ARM64_REG_B21 = 27;
public static final int ARM64_REG_B22 = 28;
public static final int ARM64_REG_B23 = 29;
public static final int ARM64_REG_B24 = 30;
public static final int ARM64_REG_B25 = 31;
public static final int ARM64_REG_B26 = 32;
public static final int ARM64_REG_B27 = 33;
public static final int ARM64_REG_B28 = 34;
public static final int ARM64_REG_B29 = 35;
public static final int ARM64_REG_B30 = 36;
public static final int ARM64_REG_B31 = 37;
public static final int ARM64_REG_D0 = 38;
public static final int ARM64_REG_D1 = 39;
public static final int ARM64_REG_D2 = 40;
public static final int ARM64_REG_D3 = 41;
public static final int ARM64_REG_D4 = 42;
public static final int ARM64_REG_D5 = 43;
public static final int ARM64_REG_D6 = 44;
public static final int ARM64_REG_D7 = 45;
public static final int ARM64_REG_D8 = 46;
public static final int ARM64_REG_D9 = 47;
public static final int ARM64_REG_D10 = 48;
public static final int ARM64_REG_D11 = 49;
public static final int ARM64_REG_D12 = 50;
public static final int ARM64_REG_D13 = 51;
public static final int ARM64_REG_D14 = 52;
public static final int ARM64_REG_D15 = 53;
public static final int ARM64_REG_D16 = 54;
public static final int ARM64_REG_D17 = 55;
public static final int ARM64_REG_D18 = 56;
public static final int ARM64_REG_D19 = 57;
public static final int ARM64_REG_D20 = 58;
public static final int ARM64_REG_D21 = 59;
public static final int ARM64_REG_D22 = 60;
public static final int ARM64_REG_D23 = 61;
public static final int ARM64_REG_D24 = 62;
public static final int ARM64_REG_D25 = 63;
public static final int ARM64_REG_D26 = 64;
public static final int ARM64_REG_D27 = 65;
public static final int ARM64_REG_D28 = 66;
public static final int ARM64_REG_D29 = 67;
public static final int ARM64_REG_D30 = 68;
public static final int ARM64_REG_D31 = 69;
public static final int ARM64_REG_H0 = 70;
public static final int ARM64_REG_H1 = 71;
public static final int ARM64_REG_H2 = 72;
public static final int ARM64_REG_H3 = 73;
public static final int ARM64_REG_H4 = 74;
public static final int ARM64_REG_H5 = 75;
public static final int ARM64_REG_H6 = 76;
public static final int ARM64_REG_H7 = 77;
public static final int ARM64_REG_H8 = 78;
public static final int ARM64_REG_H9 = 79;
public static final int ARM64_REG_H10 = 80;
public static final int ARM64_REG_H11 = 81;
public static final int ARM64_REG_H12 = 82;
public static final int ARM64_REG_H13 = 83;
public static final int ARM64_REG_H14 = 84;
public static final int ARM64_REG_H15 = 85;
public static final int ARM64_REG_H16 = 86;
public static final int ARM64_REG_H17 = 87;
public static final int ARM64_REG_H18 = 88;
public static final int ARM64_REG_H19 = 89;
public static final int ARM64_REG_H20 = 90;
public static final int ARM64_REG_H21 = 91;
public static final int ARM64_REG_H22 = 92;
public static final int ARM64_REG_H23 = 93;
public static final int ARM64_REG_H24 = 94;
public static final int ARM64_REG_H25 = 95;
public static final int ARM64_REG_H26 = 96;
public static final int ARM64_REG_H27 = 97;
public static final int ARM64_REG_H28 = 98;
public static final int ARM64_REG_H29 = 99;
public static final int ARM64_REG_H30 = 100;
public static final int ARM64_REG_H31 = 101;
public static final int ARM64_REG_Q0 = 102;
public static final int ARM64_REG_Q1 = 103;
public static final int ARM64_REG_Q2 = 104;
public static final int ARM64_REG_Q3 = 105;
public static final int ARM64_REG_Q4 = 106;
public static final int ARM64_REG_Q5 = 107;
public static final int ARM64_REG_Q6 = 108;
public static final int ARM64_REG_Q7 = 109;
public static final int ARM64_REG_Q8 = 110;
public static final int ARM64_REG_Q9 = 111;
public static final int ARM64_REG_Q10 = 112;
public static final int ARM64_REG_Q11 = 113;
public static final int ARM64_REG_Q12 = 114;
public static final int ARM64_REG_Q13 = 115;
public static final int ARM64_REG_Q14 = 116;
public static final int ARM64_REG_Q15 = 117;
public static final int ARM64_REG_Q16 = 118;
public static final int ARM64_REG_Q17 = 119;
public static final int ARM64_REG_Q18 = 120;
public static final int ARM64_REG_Q19 = 121;
public static final int ARM64_REG_Q20 = 122;
public static final int ARM64_REG_Q21 = 123;
public static final int ARM64_REG_Q22 = 124;
public static final int ARM64_REG_Q23 = 125;
public static final int ARM64_REG_Q24 = 126;
public static final int ARM64_REG_Q25 = 127;
public static final int ARM64_REG_Q26 = 128;
public static final int ARM64_REG_Q27 = 129;
public static final int ARM64_REG_Q28 = 130;
public static final int ARM64_REG_Q29 = 131;
public static final int ARM64_REG_Q30 = 132;
public static final int ARM64_REG_Q31 = 133;
public static final int ARM64_REG_S0 = 134;
public static final int ARM64_REG_S1 = 135;
public static final int ARM64_REG_S2 = 136;
public static final int ARM64_REG_S3 = 137;
public static final int ARM64_REG_S4 = 138;
public static final int ARM64_REG_S5 = 139;
public static final int ARM64_REG_S6 = 140;
public static final int ARM64_REG_S7 = 141;
public static final int ARM64_REG_S8 = 142;
public static final int ARM64_REG_S9 = 143;
public static final int ARM64_REG_S10 = 144;
public static final int ARM64_REG_S11 = 145;
public static final int ARM64_REG_S12 = 146;
public static final int ARM64_REG_S13 = 147;
public static final int ARM64_REG_S14 = 148;
public static final int ARM64_REG_S15 = 149;
public static final int ARM64_REG_S16 = 150;
public static final int ARM64_REG_S17 = 151;
public static final int ARM64_REG_S18 = 152;
public static final int ARM64_REG_S19 = 153;
public static final int ARM64_REG_S20 = 154;
public static final int ARM64_REG_S21 = 155;
public static final int ARM64_REG_S22 = 156;
public static final int ARM64_REG_S23 = 157;
public static final int ARM64_REG_S24 = 158;
public static final int ARM64_REG_S25 = 159;
public static final int ARM64_REG_S26 = 160;
public static final int ARM64_REG_S27 = 161;
public static final int ARM64_REG_S28 = 162;
public static final int ARM64_REG_S29 = 163;
public static final int ARM64_REG_S30 = 164;
public static final int ARM64_REG_S31 = 165;
public static final int ARM64_REG_W0 = 166;
public static final int ARM64_REG_W1 = 167;
public static final int ARM64_REG_W2 = 168;
public static final int ARM64_REG_W3 = 169;
public static final int ARM64_REG_W4 = 170;
public static final int ARM64_REG_W5 = 171;
public static final int ARM64_REG_W6 = 172;
public static final int ARM64_REG_W7 = 173;
public static final int ARM64_REG_W8 = 174;
public static final int ARM64_REG_W9 = 175;
public static final int ARM64_REG_W10 = 176;
public static final int ARM64_REG_W11 = 177;
public static final int ARM64_REG_W12 = 178;
public static final int ARM64_REG_W13 = 179;
public static final int ARM64_REG_W14 = 180;
public static final int ARM64_REG_W15 = 181;
public static final int ARM64_REG_W16 = 182;
public static final int ARM64_REG_W17 = 183;
public static final int ARM64_REG_W18 = 184;
public static final int ARM64_REG_W19 = 185;
public static final int ARM64_REG_W20 = 186;
public static final int ARM64_REG_W21 = 187;
public static final int ARM64_REG_W22 = 188;
public static final int ARM64_REG_W23 = 189;
public static final int ARM64_REG_W24 = 190;
public static final int ARM64_REG_W25 = 191;
public static final int ARM64_REG_W26 = 192;
public static final int ARM64_REG_W27 = 193;
public static final int ARM64_REG_W28 = 194;
public static final int ARM64_REG_W29 = 195;
public static final int ARM64_REG_W30 = 196;
public static final int ARM64_REG_X0 = 197;
public static final int ARM64_REG_X1 = 198;
public static final int ARM64_REG_X2 = 199;
public static final int ARM64_REG_X3 = 200;
public static final int ARM64_REG_X4 = 201;
public static final int ARM64_REG_X5 = 202;
public static final int ARM64_REG_X6 = 203;
public static final int ARM64_REG_X7 = 204;
public static final int ARM64_REG_X8 = 205;
public static final int ARM64_REG_X9 = 206;
public static final int ARM64_REG_X10 = 207;
public static final int ARM64_REG_X11 = 208;
public static final int ARM64_REG_X12 = 209;
public static final int ARM64_REG_X13 = 210;
public static final int ARM64_REG_X14 = 211;
public static final int ARM64_REG_X15 = 212;
public static final int ARM64_REG_X16 = 213;
public static final int ARM64_REG_X17 = 214;
public static final int ARM64_REG_X18 = 215;
public static final int ARM64_REG_X19 = 216;
public static final int ARM64_REG_X20 = 217;
public static final int ARM64_REG_X21 = 218;
public static final int ARM64_REG_X22 = 219;
public static final int ARM64_REG_X23 = 220;
public static final int ARM64_REG_X24 = 221;
public static final int ARM64_REG_X25 = 222;
public static final int ARM64_REG_X26 = 223;
public static final int ARM64_REG_X27 = 224;
public static final int ARM64_REG_X28 = 225;
public static final int ARM64_REG_X29 = 226;
public static final int ARM64_REG_X30 = 227;

// ARM64 instructions
public static final int ARM64_INS_INVALID = 0;
public static final int ARM64_INS_ADC = 1;
public static final int ARM64_INS_ADDHN2 = 2;
public static final int ARM64_INS_ADDHN = 3;
public static final int ARM64_INS_ADDP = 4;
public static final int ARM64_INS_ADD = 5;
public static final int ARM64_INS_CMN = 6;
public static final int ARM64_INS_ADRP = 7;
public static final int ARM64_INS_ADR = 8;
public static final int ARM64_INS_AND = 9;
public static final int ARM64_INS_ASR = 10;
public static final int ARM64_INS_AT = 11;
public static final int ARM64_INS_BFI = 12;
public static final int ARM64_INS_BFM = 13;
public static final int ARM64_INS_BFXIL = 14;
public static final int ARM64_INS_BIC = 15;
public static final int ARM64_INS_BIF = 16;
public static final int ARM64_INS_BIT = 17;
public static final int ARM64_INS_BLR = 18;
public static final int ARM64_INS_BL = 19;
public static final int ARM64_INS_BRK = 20;
public static final int ARM64_INS_BR = 21;
public static final int ARM64_INS_BSL = 22;
public static final int ARM64_INS_B = 23;
public static final int ARM64_INS_CBNZ = 24;
public static final int ARM64_INS_CBZ = 25;
public static final int ARM64_INS_CCMN = 26;
public static final int ARM64_INS_CCMP = 27;
public static final int ARM64_INS_CLREX = 28;
public static final int ARM64_INS_CLS = 29;
public static final int ARM64_INS_CLZ = 30;
public static final int ARM64_INS_CMEQ = 31;
public static final int ARM64_INS_CMGE = 32;
public static final int ARM64_INS_CMGT = 33;
public static final int ARM64_INS_CMHI = 34;
public static final int ARM64_INS_CMHS = 35;
public static final int ARM64_INS_CMLE = 36;
public static final int ARM64_INS_CMLT = 37;
public static final int ARM64_INS_CMP = 38;
public static final int ARM64_INS_CMTST = 39;
public static final int ARM64_INS_CRC32B = 40;
public static final int ARM64_INS_CRC32CB = 41;
public static final int ARM64_INS_CRC32CH = 42;
public static final int ARM64_INS_CRC32CW = 43;
public static final int ARM64_INS_CRC32CX = 44;
public static final int ARM64_INS_CRC32H = 45;
public static final int ARM64_INS_CRC32W = 46;
public static final int ARM64_INS_CRC32X = 47;
public static final int ARM64_INS_CSEL = 48;
public static final int ARM64_INS_CSINC = 49;
public static final int ARM64_INS_CSINV = 50;
public static final int ARM64_INS_CSNEG = 51;
public static final int ARM64_INS_DCPS1 = 52;
public static final int ARM64_INS_DCPS2 = 53;
public static final int ARM64_INS_DCPS3 = 54;
public static final int ARM64_INS_DC = 55;
public static final int ARM64_INS_DMB = 56;
public static final int ARM64_INS_DRPS = 57;
public static final int ARM64_INS_DSB = 58;
public static final int ARM64_INS_EON = 59;
public static final int ARM64_INS_EOR = 60;
public static final int ARM64_INS_ERET = 61;
public static final int ARM64_INS_EXTR = 62;
public static final int ARM64_INS_FABD = 63;
public static final int ARM64_INS_FABS = 64;
public static final int ARM64_INS_FACGE = 65;
public static final int ARM64_INS_FACGT = 66;
public static final int ARM64_INS_FADDP = 67;
public static final int ARM64_INS_FADD = 68;
public static final int ARM64_INS_FCCMPE = 69;
public static final int ARM64_INS_FCCMP = 70;
public static final int ARM64_INS_FCMEQ = 71;
public static final int ARM64_INS_FCMGE = 72;
public static final int ARM64_INS_FCMGT = 73;
public static final int ARM64_INS_FCMLE = 74;
public static final int ARM64_INS_FCMLT = 75;
public static final int ARM64_INS_FCMP = 76;
public static final int ARM64_INS_FCMPE = 77;
public static final int ARM64_INS_FCSEL = 78;
public static final int ARM64_INS_FCVTAS = 79;
public static final int ARM64_INS_FCVTAU = 80;
public static final int ARM64_INS_FCVTMS = 81;
public static final int ARM64_INS_FCVTMU = 82;
public static final int ARM64_INS_FCVTNS = 83;
public static final int ARM64_INS_FCVTNU = 84;
public static final int ARM64_INS_FCVTPS = 85;
public static final int ARM64_INS_FCVTPU = 86;
public static final int ARM64_INS_FCVTZS = 87;
public static final int ARM64_INS_FCVTZU = 88;
public static final int ARM64_INS_FCVT = 89;
public static final int ARM64_INS_FDIV = 90;
public static final int ARM64_INS_FMADD = 91;
public static final int ARM64_INS_FMAXNMP = 92;
public static final int ARM64_INS_FMAXNM = 93;
public static final int ARM64_INS_FMAXP = 94;
public static final int ARM64_INS_FMAX = 95;
public static final int ARM64_INS_FMINNMP = 96;
public static final int ARM64_INS_FMINNM = 97;
public static final int ARM64_INS_FMINP = 98;
public static final int ARM64_INS_FMIN = 99;
public static final int ARM64_INS_FMLA = 100;
public static final int ARM64_INS_FMLS = 101;
public static final int ARM64_INS_FMOV = 102;
public static final int ARM64_INS_FMSUB = 103;
public static final int ARM64_INS_FMULX = 104;
public static final int ARM64_INS_FMUL = 105;
public static final int ARM64_INS_FNEG = 106;
public static final int ARM64_INS_FNMADD = 107;
public static final int ARM64_INS_FNMSUB = 108;
public static final int ARM64_INS_FNMUL = 109;
public static final int ARM64_INS_FRECPS = 110;
public static final int ARM64_INS_FRINTA = 111;
public static final int ARM64_INS_FRINTI = 112;
public static final int ARM64_INS_FRINTM = 113;
public static final int ARM64_INS_FRINTN = 114;
public static final int ARM64_INS_FRINTP = 115;
public static final int ARM64_INS_FRINTX = 116;
public static final int ARM64_INS_FRINTZ = 117;
public static final int ARM64_INS_FRSQRTS = 118;
public static final int ARM64_INS_FSQRT = 119;
public static final int ARM64_INS_FSUB = 120;
public static final int ARM64_INS_HINT = 121;
public static final int ARM64_INS_HLT = 122;
public static final int ARM64_INS_HVC = 123;
public static final int ARM64_INS_IC = 124;
public static final int ARM64_INS_INS = 125;
public static final int ARM64_INS_ISB = 126;
public static final int ARM64_INS_LDARB = 127;
public static final int ARM64_INS_LDAR = 128;
public static final int ARM64_INS_LDARH = 129;
public static final int ARM64_INS_LDAXP = 130;
public static final int ARM64_INS_LDAXRB = 131;
public static final int ARM64_INS_LDAXR = 132;
public static final int ARM64_INS_LDAXRH = 133;
public static final int ARM64_INS_LDPSW = 134;
public static final int ARM64_INS_LDRSB = 135;
public static final int ARM64_INS_LDURSB = 136;
public static final int ARM64_INS_LDRSH = 137;
public static final int ARM64_INS_LDURSH = 138;
public static final int ARM64_INS_LDRSW = 139;
public static final int ARM64_INS_LDR = 140;
public static final int ARM64_INS_LDTRSB = 141;
public static final int ARM64_INS_LDTRSH = 142;
public static final int ARM64_INS_LDTRSW = 143;
public static final int ARM64_INS_LDURSW = 144;
public static final int ARM64_INS_LDXP = 145;
public static final int ARM64_INS_LDXRB = 146;
public static final int ARM64_INS_LDXR = 147;
public static final int ARM64_INS_LDXRH = 148;
public static final int ARM64_INS_LDRH = 149;
public static final int ARM64_INS_LDURH = 150;
public static final int ARM64_INS_STRH = 151;
public static final int ARM64_INS_STURH = 152;
public static final int ARM64_INS_LDTRH = 153;
public static final int ARM64_INS_STTRH = 154;
public static final int ARM64_INS_LDUR = 155;
public static final int ARM64_INS_STR = 156;
public static final int ARM64_INS_STUR = 157;
public static final int ARM64_INS_LDTR = 158;
public static final int ARM64_INS_STTR = 159;
public static final int ARM64_INS_LDRB = 160;
public static final int ARM64_INS_LDURB = 161;
public static final int ARM64_INS_STRB = 162;
public static final int ARM64_INS_STURB = 163;
public static final int ARM64_INS_LDTRB = 164;
public static final int ARM64_INS_STTRB = 165;
public static final int ARM64_INS_LDP = 166;
public static final int ARM64_INS_LDNP = 167;
public static final int ARM64_INS_STNP = 168;
public static final int ARM64_INS_STP = 169;
public static final int ARM64_INS_LSL = 170;
public static final int ARM64_INS_LSR = 171;
public static final int ARM64_INS_MADD = 172;
public static final int ARM64_INS_MLA = 173;
public static final int ARM64_INS_MLS = 174;
public static final int ARM64_INS_MOVI = 175;
public static final int ARM64_INS_MOVK = 176;
public static final int ARM64_INS_MOVN = 177;
public static final int ARM64_INS_MOVZ = 178;
public static final int ARM64_INS_MRS = 179;
public static final int ARM64_INS_MSR = 180;
public static final int ARM64_INS_MSUB = 181;
public static final int ARM64_INS_MUL = 182;
public static final int ARM64_INS_MVNI = 183;
public static final int ARM64_INS_MVN = 184;
public static final int ARM64_INS_ORN = 185;
public static final int ARM64_INS_ORR = 186;
public static final int ARM64_INS_PMULL2 = 187;
public static final int ARM64_INS_PMULL = 188;
public static final int ARM64_INS_PMUL = 189;
public static final int ARM64_INS_PRFM = 190;
public static final int ARM64_INS_PRFUM = 191;
public static final int ARM64_INS_SQRSHRUN2 = 192;
public static final int ARM64_INS_SQRSHRUN = 193;
public static final int ARM64_INS_SQSHRUN2 = 194;
public static final int ARM64_INS_SQSHRUN = 195;
public static final int ARM64_INS_RADDHN2 = 196;
public static final int ARM64_INS_RADDHN = 197;
public static final int ARM64_INS_RBIT = 198;
public static final int ARM64_INS_RET = 199;
public static final int ARM64_INS_REV16 = 200;
public static final int ARM64_INS_REV32 = 201;
public static final int ARM64_INS_REV = 202;
public static final int ARM64_INS_ROR = 203;
public static final int ARM64_INS_RSHRN2 = 204;
public static final int ARM64_INS_RSHRN = 205;
public static final int ARM64_INS_RSUBHN2 = 206;
public static final int ARM64_INS_RSUBHN = 207;
public static final int ARM64_INS_SABAL2 = 208;
public static final int ARM64_INS_SABAL = 209;
public static final int ARM64_INS_SABA = 210;
public static final int ARM64_INS_SABDL2 = 211;
public static final int ARM64_INS_SABDL = 212;
public static final int ARM64_INS_SABD = 213;
public static final int ARM64_INS_SADDL2 = 214;
public static final int ARM64_INS_SADDL = 215;
public static final int ARM64_INS_SADDW2 = 216;
public static final int ARM64_INS_SADDW = 217;
public static final int ARM64_INS_SBC = 218;
public static final int ARM64_INS_SBFIZ = 219;
public static final int ARM64_INS_SBFM = 220;
public static final int ARM64_INS_SBFX = 221;
public static final int ARM64_INS_SCVTF = 222;
public static final int ARM64_INS_SDIV = 223;
public static final int ARM64_INS_SHADD = 224;
public static final int ARM64_INS_SHL = 225;
public static final int ARM64_INS_SHRN2 = 226;
public static final int ARM64_INS_SHRN = 227;
public static final int ARM64_INS_SHSUB = 228;
public static final int ARM64_INS_SLI = 229;
public static final int ARM64_INS_SMADDL = 230;
public static final int ARM64_INS_SMAXP = 231;
public static final int ARM64_INS_SMAX = 232;
public static final int ARM64_INS_SMC = 233;
public static final int ARM64_INS_SMINP = 234;
public static final int ARM64_INS_SMIN = 235;
public static final int ARM64_INS_SMLAL2 = 236;
public static final int ARM64_INS_SMLAL = 237;
public static final int ARM64_INS_SMLSL2 = 238;
public static final int ARM64_INS_SMLSL = 239;
public static final int ARM64_INS_SMOV = 240;
public static final int ARM64_INS_SMSUBL = 241;
public static final int ARM64_INS_SMULH = 242;
public static final int ARM64_INS_SMULL2 = 243;
public static final int ARM64_INS_SMULL = 244;
public static final int ARM64_INS_SQADD = 245;
public static final int ARM64_INS_SQDMLAL2 = 246;
public static final int ARM64_INS_SQDMLAL = 247;
public static final int ARM64_INS_SQDMLSL2 = 248;
public static final int ARM64_INS_SQDMLSL = 249;
public static final int ARM64_INS_SQDMULH = 250;
public static final int ARM64_INS_SQDMULL2 = 251;
public static final int ARM64_INS_SQDMULL = 252;
public static final int ARM64_INS_SQRDMULH = 253;
public static final int ARM64_INS_SQRSHL = 254;
public static final int ARM64_INS_SQRSHRN2 = 255;
public static final int ARM64_INS_SQRSHRN = 256;
public static final int ARM64_INS_SQSHLU = 257;
public static final int ARM64_INS_SQSHL = 258;
public static final int ARM64_INS_SQSHRN2 = 259;
public static final int ARM64_INS_SQSHRN = 260;
public static final int ARM64_INS_SQSUB = 261;
public static final int ARM64_INS_SRHADD = 262;
public static final int ARM64_INS_SRI = 263;
public static final int ARM64_INS_SRSHL = 264;
public static final int ARM64_INS_SRSHR = 265;
public static final int ARM64_INS_SRSRA = 266;
public static final int ARM64_INS_SSHLL2 = 267;
public static final int ARM64_INS_SSHLL = 268;
public static final int ARM64_INS_SSHL = 269;
public static final int ARM64_INS_SSHR = 270;
public static final int ARM64_INS_SSRA = 271;
public static final int ARM64_INS_SSUBL2 = 272;
public static final int ARM64_INS_SSUBL = 273;
public static final int ARM64_INS_SSUBW2 = 274;
public static final int ARM64_INS_SSUBW = 275;
public static final int ARM64_INS_STLRB = 276;
public static final int ARM64_INS_STLR = 277;
public static final int ARM64_INS_STLRH = 278;
public static final int ARM64_INS_STLXP = 279;
public static final int ARM64_INS_STLXRB = 280;
public static final int ARM64_INS_STLXR = 281;
public static final int ARM64_INS_STLXRH = 282;
public static final int ARM64_INS_STXP = 283;
public static final int ARM64_INS_STXRB = 284;
public static final int ARM64_INS_STXR = 285;
public static final int ARM64_INS_STXRH = 286;
public static final int ARM64_INS_SUBHN2 = 287;
public static final int ARM64_INS_SUBHN = 288;
public static final int ARM64_INS_SUB = 289;
public static final int ARM64_INS_SVC = 290;
public static final int ARM64_INS_SXTB = 291;
public static final int ARM64_INS_SXTH = 292;
public static final int ARM64_INS_SXTW = 293;
public static final int ARM64_INS_SYSL = 294;
public static final int ARM64_INS_SYS = 295;
public static final int ARM64_INS_TBNZ = 296;
public static final int ARM64_INS_TBZ = 297;
public static final int ARM64_INS_TLBI = 298;
public static final int ARM64_INS_TST = 299;
public static final int ARM64_INS_UABAL2 = 300;
public static final int ARM64_INS_UABAL = 301;
public static final int ARM64_INS_UABA = 302;
public static final int ARM64_INS_UABDL2 = 303;
public static final int ARM64_INS_UABDL = 304;
public static final int ARM64_INS_UABD = 305;
public static final int ARM64_INS_UADDL2 = 306;
public static final int ARM64_INS_UADDL = 307;
public static final int ARM64_INS_UADDW2 = 308;
public static final int ARM64_INS_UADDW = 309;
public static final int ARM64_INS_UBFIZ = 310;
public static final int ARM64_INS_UBFM = 311;
public static final int ARM64_INS_UBFX = 312;
public static final int ARM64_INS_UCVTF = 313;
public static final int ARM64_INS_UDIV = 314;
public static final int ARM64_INS_UHADD = 315;
public static final int ARM64_INS_UHSUB = 316;
public static final int ARM64_INS_UMADDL = 317;
public static final int ARM64_INS_UMAXP = 318;
public static final int ARM64_INS_UMAX = 319;
public static final int ARM64_INS_UMINP = 320;
public static final int ARM64_INS_UMIN = 321;
public static final int ARM64_INS_UMLAL2 = 322;
public static final int ARM64_INS_UMLAL = 323;
public static final int ARM64_INS_UMLSL2 = 324;
public static final int ARM64_INS_UMLSL = 325;
public static final int ARM64_INS_UMOV = 326;
public static final int ARM64_INS_UMSUBL = 327;
public static final int ARM64_INS_UMULH = 328;
public static final int ARM64_INS_UMULL2 = 329;
public static final int ARM64_INS_UMULL = 330;
public static final int ARM64_INS_UQADD = 331;
public static final int ARM64_INS_UQRSHL = 332;
public static final int ARM64_INS_UQRSHRN2 = 333;
public static final int ARM64_INS_UQRSHRN = 334;
public static final int ARM64_INS_UQSHL = 335;
public static final int ARM64_INS_UQSHRN2 = 336;
public static final int ARM64_INS_UQSHRN = 337;
public static final int ARM64_INS_UQSUB = 338;
public static final int ARM64_INS_URHADD = 339;
public static final int ARM64_INS_URSHL = 340;
public static final int ARM64_INS_URSHR = 341;
public static final int ARM64_INS_URSRA = 342;
public static final int ARM64_INS_USHLL2 = 343;
public static final int ARM64_INS_USHLL = 344;
public static final int ARM64_INS_USHL = 345;
public static final int ARM64_INS_USHR = 346;
public static final int ARM64_INS_USRA = 347;
public static final int ARM64_INS_USUBL2 = 348;
public static final int ARM64_INS_USUBL = 349;
public static final int ARM64_INS_USUBW2 = 350;
public static final int ARM64_INS_USUBW = 351;
public static final int ARM64_INS_UXTB = 352;
public static final int ARM64_INS_UXTH = 353;

// ARM64 group of instructions
public static final int ARM64_GRP_INVALID = 0;
public static final int ARM64_GRP_NEON = 1;

}
