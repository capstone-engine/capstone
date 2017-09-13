// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT
package capstone;

public class M680x_const {
	public static final int M680X_OPERAND_COUNT = 9;

	// M680X registers and special registers

	public static final int M680X_REG_INVALID = 0;
	public static final int M680X_REG_A = 1;
	public static final int M680X_REG_B = 2;
	public static final int M680X_REG_E = 3;
	public static final int M680X_REG_F = 4;
	public static final int M680X_REG_0 = 5;
	public static final int M680X_REG_D = 6;
	public static final int M680X_REG_W = 7;
	public static final int M680X_REG_CC = 8;
	public static final int M680X_REG_DP = 9;
	public static final int M680X_REG_MD = 10;
	public static final int M680X_REG_X = 11;
	public static final int M680X_REG_Y = 12;
	public static final int M680X_REG_S = 13;
	public static final int M680X_REG_U = 14;
	public static final int M680X_REG_V = 15;
	public static final int M680X_REG_Q = 16;
	public static final int M680X_REG_PC = 17;
	public static final int M680X_REG_ENDING = 18;

	// M680X Addressing Modes

	public static final int M680X_AM_NONE = 0;
	public static final int M680X_AM_INHERENT = 1;
	public static final int M680X_AM_REGISTER = 2;
	public static final int M680X_AM_IMMEDIATE = 3;
	public static final int M680X_AM_INDEXED = 4;
	public static final int M680X_AM_EXTENDED = 5;
	public static final int M680X_AM_DIRECT = 6;
	public static final int M680X_AM_RELATIVE = 7;
	public static final int M680X_AM_IMM_DIRECT = 8;
	public static final int M680X_AM_IMM_INDEXED = 9;
	public static final int M680X_AM_ENDING = 10;

	// Operand type for instruction's operands

	public static final int M680X_OP_INVALID = 0;
	public static final int M680X_OP_REGISTER = 1;
	public static final int M680X_OP_IMMEDIATE = 2;
	public static final int M680X_OP_INDEXED_00 = 3;
	public static final int M680X_OP_INDEXED_09 = 4;
	public static final int M680X_OP_EXTENDED = 5;
	public static final int M680X_OP_DIRECT = 6;
	public static final int M680X_OP_RELATIVE = 7;

	// Supported values for mem.idx.inc_dec
	public static final int M680X_POST_INC_2 = +2;
	public static final int M680X_POST_INC_1 = +1;

	public static final int M680X_NO_INC_DEC = 0;
	public static final int M680X_PRE_DEC_1 = -1;
	public static final int M680X_PRE_DEC_2 = -2;

	// Supported bit values for mem.idx.offset_bits

	public static final int M680X_OFFSET_NONE = 0;
	public static final int M680X_OFFSET_BITS_5 = 5;
	public static final int M680X_OFFSET_BITS_8 = 8;
	public static final int M680X_OFFSET_BITS_16 = 16;

	// Group of M680X instructions

	public static final int M680X_GRP_INVALID = 0;

	// Generic groups
	public static final int M680X_GRP_JUMP = 1;
	public static final int M680X_GRP_CALL = 2;
	public static final int M680X_GRP_RET = 3;
	public static final int M680X_GRP_INT = 4;
	public static final int M680X_GRP_IRET = 5;
	public static final int M680X_GRP_PRIV = 6;
	public static final int M680X_GRP_BRAREL = 7;

	// Architecture-specific groups
	public static final int M680X_GRP_ENDING = 8;

	// M680X instruction flags:
	public static final int M680X_FIRST_OP_IN_MNEM = 1;

	// M680X instruction IDs

	public static final int M680X_INS_INVLD = 0;
	public static final int M680X_INS_ABA = 1;
	public static final int M680X_INS_ABX = 2;
	public static final int M680X_INS_ADCA = 3;
	public static final int M680X_INS_ADCB = 4;
	public static final int M680X_INS_ADCD = 5;
	public static final int M680X_INS_ADDA = 6;
	public static final int M680X_INS_ADDB = 7;
	public static final int M680X_INS_ADDD = 8;
	public static final int M680X_INS_ADDE = 9;
	public static final int M680X_INS_ADDF = 10;
	public static final int M680X_INS_ADDR = 11;
	public static final int M680X_INS_ADDW = 12;
	public static final int M680X_INS_AIM = 13;
	public static final int M680X_INS_ANDA = 14;
	public static final int M680X_INS_ANDB = 15;
	public static final int M680X_INS_ANDCC = 16;
	public static final int M680X_INS_ANDD = 17;
	public static final int M680X_INS_ANDR = 18;
	public static final int M680X_INS_ASL = 19;
	public static final int M680X_INS_ASLA = 20;
	public static final int M680X_INS_ASLB = 21;
	public static final int M680X_INS_ASLD = 22;
	public static final int M680X_INS_ASR = 23;
	public static final int M680X_INS_ASRA = 24;
	public static final int M680X_INS_ASRB = 25;
	public static final int M680X_INS_BAND = 26;
	public static final int M680X_INS_BCC = 27;
	public static final int M680X_INS_BCS = 28;
	public static final int M680X_INS_BEOR = 29;
	public static final int M680X_INS_BEQ = 30;
	public static final int M680X_INS_BGE = 31;
	public static final int M680X_INS_BGT = 32;
	public static final int M680X_INS_BHI = 33;
	public static final int M680X_INS_BIAND = 34;
	public static final int M680X_INS_BIEOR = 35;
	public static final int M680X_INS_BIOR = 36;
	public static final int M680X_INS_BITA = 37;
	public static final int M680X_INS_BITB = 38;
	public static final int M680X_INS_BITD = 39;
	public static final int M680X_INS_BITMD = 40;
	public static final int M680X_INS_BLE = 41;
	public static final int M680X_INS_BLS = 42;
	public static final int M680X_INS_BLT = 43;
	public static final int M680X_INS_BMI = 44;
	public static final int M680X_INS_BNE = 45;
	public static final int M680X_INS_BOR = 46;
	public static final int M680X_INS_BPL = 47;
	public static final int M680X_INS_BRA = 48;
	public static final int M680X_INS_BRN = 49;
	public static final int M680X_INS_BSR = 50;
	public static final int M680X_INS_BVC = 51;
	public static final int M680X_INS_BVS = 52;
	public static final int M680X_INS_CBA = 53;
	public static final int M680X_INS_CLC = 54;
	public static final int M680X_INS_CLI = 55;
	public static final int M680X_INS_CLR = 56;
	public static final int M680X_INS_CLRA = 57;
	public static final int M680X_INS_CLRB = 58;
	public static final int M680X_INS_CLRD = 59;
	public static final int M680X_INS_CLRE = 60;
	public static final int M680X_INS_CLRF = 61;
	public static final int M680X_INS_CLRW = 62;
	public static final int M680X_INS_CLV = 63;
	public static final int M680X_INS_CMPA = 64;
	public static final int M680X_INS_CMPB = 65;
	public static final int M680X_INS_CMPD = 66;
	public static final int M680X_INS_CMPE = 67;
	public static final int M680X_INS_CMPF = 68;
	public static final int M680X_INS_CMPR = 69;
	public static final int M680X_INS_CMPS = 70;
	public static final int M680X_INS_CMPU = 71;
	public static final int M680X_INS_CMPW = 72;
	public static final int M680X_INS_CMPX = 73;
	public static final int M680X_INS_CMPY = 74;
	public static final int M680X_INS_COM = 75;
	public static final int M680X_INS_COMA = 76;
	public static final int M680X_INS_COMB = 77;
	public static final int M680X_INS_COMD = 78;
	public static final int M680X_INS_COME = 79;
	public static final int M680X_INS_COMF = 80;
	public static final int M680X_INS_COMW = 81;
	public static final int M680X_INS_CPX = 82;
	public static final int M680X_INS_CWAI = 83;
	public static final int M680X_INS_DAA = 84;
	public static final int M680X_INS_DEC = 85;
	public static final int M680X_INS_DECA = 86;
	public static final int M680X_INS_DECB = 87;
	public static final int M680X_INS_DECD = 88;
	public static final int M680X_INS_DECE = 89;
	public static final int M680X_INS_DECF = 90;
	public static final int M680X_INS_DECW = 91;
	public static final int M680X_INS_DES = 92;
	public static final int M680X_INS_DEX = 93;
	public static final int M680X_INS_DIVD = 94;
	public static final int M680X_INS_DIVQ = 95;
	public static final int M680X_INS_EIM = 96;
	public static final int M680X_INS_EORA = 97;
	public static final int M680X_INS_EORB = 98;
	public static final int M680X_INS_EORD = 99;
	public static final int M680X_INS_EORR = 100;
	public static final int M680X_INS_EXG = 101;
	public static final int M680X_INS_ILLGL = 102;
	public static final int M680X_INS_INC = 103;
	public static final int M680X_INS_INCA = 104;
	public static final int M680X_INS_INCB = 105;
	public static final int M680X_INS_INCD = 106;
	public static final int M680X_INS_INCE = 107;
	public static final int M680X_INS_INCF = 108;
	public static final int M680X_INS_INCW = 109;
	public static final int M680X_INS_INS = 110;
	public static final int M680X_INS_INX = 111;
	public static final int M680X_INS_JMP = 112;
	public static final int M680X_INS_JSR = 113;
	public static final int M680X_INS_LBCC = 114;
	public static final int M680X_INS_LBCS = 115;
	public static final int M680X_INS_LBEQ = 116;
	public static final int M680X_INS_LBGE = 117;
	public static final int M680X_INS_LBGT = 118;
	public static final int M680X_INS_LBHI = 119;
	public static final int M680X_INS_LBLE = 120;
	public static final int M680X_INS_LBLS = 121;
	public static final int M680X_INS_LBLT = 122;
	public static final int M680X_INS_LBMI = 123;
	public static final int M680X_INS_LBNE = 124;
	public static final int M680X_INS_LBPL = 125;
	public static final int M680X_INS_LBRA = 126;
	public static final int M680X_INS_LBRN = 127;
	public static final int M680X_INS_LBSR = 128;
	public static final int M680X_INS_LBVC = 129;
	public static final int M680X_INS_LBVS = 130;
	public static final int M680X_INS_LDA = 131;
	public static final int M680X_INS_LDAA = 132;
	public static final int M680X_INS_LDAB = 133;
	public static final int M680X_INS_LDB = 134;
	public static final int M680X_INS_LDBT = 135;
	public static final int M680X_INS_LDD = 136;
	public static final int M680X_INS_LDE = 137;
	public static final int M680X_INS_LDF = 138;
	public static final int M680X_INS_LDMD = 139;
	public static final int M680X_INS_LDQ = 140;
	public static final int M680X_INS_LDS = 141;
	public static final int M680X_INS_LDU = 142;
	public static final int M680X_INS_LDW = 143;
	public static final int M680X_INS_LDX = 144;
	public static final int M680X_INS_LDY = 145;
	public static final int M680X_INS_LEAS = 146;
	public static final int M680X_INS_LEAU = 147;
	public static final int M680X_INS_LEAX = 148;
	public static final int M680X_INS_LEAY = 149;
	public static final int M680X_INS_LSL = 150;
	public static final int M680X_INS_LSLA = 151;
	public static final int M680X_INS_LSLB = 152;
	public static final int M680X_INS_LSR = 153;
	public static final int M680X_INS_LSRA = 154;
	public static final int M680X_INS_LSRB = 155;
	public static final int M680X_INS_LSRD = 156;
	public static final int M680X_INS_LSRW = 157;
	public static final int M680X_INS_MUL = 158;
	public static final int M680X_INS_MULD = 159;
	public static final int M680X_INS_NEG = 160;
	public static final int M680X_INS_NEGA = 161;
	public static final int M680X_INS_NEGB = 162;
	public static final int M680X_INS_NEGD = 163;
	public static final int M680X_INS_NOP = 164;
	public static final int M680X_INS_OIM = 165;
	public static final int M680X_INS_ORA = 166;
	public static final int M680X_INS_ORAA = 167;
	public static final int M680X_INS_ORAB = 168;
	public static final int M680X_INS_ORB = 169;
	public static final int M680X_INS_ORCC = 170;
	public static final int M680X_INS_ORD = 171;
	public static final int M680X_INS_ORR = 172;
	public static final int M680X_INS_PSHA = 173;
	public static final int M680X_INS_PSHB = 174;
	public static final int M680X_INS_PSHS = 175;
	public static final int M680X_INS_PSHSW = 176;
	public static final int M680X_INS_PSHU = 177;
	public static final int M680X_INS_PSHUW = 178;
	public static final int M680X_INS_PSHX = 179;
	public static final int M680X_INS_PULA = 180;
	public static final int M680X_INS_PULB = 181;
	public static final int M680X_INS_PULS = 182;
	public static final int M680X_INS_PULSW = 183;
	public static final int M680X_INS_PULU = 184;
	public static final int M680X_INS_PULUW = 185;
	public static final int M680X_INS_PULX = 186;
	public static final int M680X_INS_ROL = 187;
	public static final int M680X_INS_ROLA = 188;
	public static final int M680X_INS_ROLB = 189;
	public static final int M680X_INS_ROLD = 190;
	public static final int M680X_INS_ROLW = 191;
	public static final int M680X_INS_ROR = 192;
	public static final int M680X_INS_RORA = 193;
	public static final int M680X_INS_RORB = 194;
	public static final int M680X_INS_RORD = 195;
	public static final int M680X_INS_RORW = 196;
	public static final int M680X_INS_RTI = 197;
	public static final int M680X_INS_RTS = 198;
	public static final int M680X_INS_SBA = 199;
	public static final int M680X_INS_SBCA = 200;
	public static final int M680X_INS_SBCB = 201;
	public static final int M680X_INS_SBCD = 202;
	public static final int M680X_INS_SBCR = 203;
	public static final int M680X_INS_SEC = 204;
	public static final int M680X_INS_SEI = 205;
	public static final int M680X_INS_SEV = 206;
	public static final int M680X_INS_SEX = 207;
	public static final int M680X_INS_SEXW = 208;
	public static final int M680X_INS_STA = 209;
	public static final int M680X_INS_STAA = 210;
	public static final int M680X_INS_STAB = 211;
	public static final int M680X_INS_STB = 212;
	public static final int M680X_INS_STBT = 213;
	public static final int M680X_INS_STD = 214;
	public static final int M680X_INS_STE = 215;
	public static final int M680X_INS_STF = 216;
	public static final int M680X_INS_STQ = 217;
	public static final int M680X_INS_STS = 218;
	public static final int M680X_INS_STU = 219;
	public static final int M680X_INS_STW = 220;
	public static final int M680X_INS_STX = 221;
	public static final int M680X_INS_STY = 222;
	public static final int M680X_INS_SUBA = 223;
	public static final int M680X_INS_SUBB = 224;
	public static final int M680X_INS_SUBD = 225;
	public static final int M680X_INS_SUBE = 226;
	public static final int M680X_INS_SUBF = 227;
	public static final int M680X_INS_SUBR = 228;
	public static final int M680X_INS_SUBW = 229;
	public static final int M680X_INS_SWI = 230;
	public static final int M680X_INS_SWI2 = 231;
	public static final int M680X_INS_SWI3 = 232;
	public static final int M680X_INS_SYNC = 233;
	public static final int M680X_INS_TAB = 234;
	public static final int M680X_INS_TAP = 235;
	public static final int M680X_INS_TBA = 236;
	public static final int M680X_INS_TPA = 237;
	public static final int M680X_INS_TFM = 238;
	public static final int M680X_INS_TFR = 239;
	public static final int M680X_INS_TIM = 240;
	public static final int M680X_INS_TST = 241;
	public static final int M680X_INS_TSTA = 242;
	public static final int M680X_INS_TSTB = 243;
	public static final int M680X_INS_TSTD = 244;
	public static final int M680X_INS_TSTE = 245;
	public static final int M680X_INS_TSTF = 246;
	public static final int M680X_INS_TSTW = 247;
	public static final int M680X_INS_TSX = 248;
	public static final int M680X_INS_TXS = 249;
	public static final int M680X_INS_WAI = 250;
	public static final int M680X_INS_XGDX = 251;
	public static final int M680X_INS_ENDING = 252;
}