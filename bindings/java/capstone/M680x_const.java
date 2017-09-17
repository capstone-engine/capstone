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
	public static final int M680X_AM_IMM_EXTENDED = 10;
	public static final int M680X_AM_BIT_MOVE = 11;
	public static final int M680X_AM_INDEXED2 = 12;
	public static final int M680X_AM_ENDING = 13;

	// Operand type for instruction's operands

	public static final int M680X_OP_INVALID = 0;
	public static final int M680X_OP_REGISTER = 1;
	public static final int M680X_OP_IMMEDIATE = 2;
	public static final int M680X_OP_INDEXED_00 = 3;
	public static final int M680X_OP_INDEXED_09 = 4;
	public static final int M680X_OP_EXTENDED = 5;
	public static final int M680X_OP_DIRECT = 6;
	public static final int M680X_OP_RELATIVE = 7;
	public static final int M680X_OP_INDEX = 8;

	// Supported values for mem.idx.inc_dec

	public static final int M680X_NO_INC_DEC = 0;
	public static final int M680X_PRE_DEC_1 = 1;
	public static final int M680X_PRE_DEC_2 = 2;
	public static final int M680X_POST_INC_1 = 3;
	public static final int M680X_POST_INC_2 = 4;
	public static final int M680X_POST_DEC_1 = 5;

	// Supported bit values for mem.idx.offset_bits

	public static final int M680X_OFFSET_NONE = 0;
	public static final int M680X_OFFSET_BITS_5 = 5;
	public static final int M680X_OFFSET_BITS_8 = 8;
	public static final int M680X_OFFSET_BITS_16 = 16;

	// Supported bit flags for mem.idx.flags

	// These flags can be comined
	public static final int M680X_IDX_INDIRECT = 1;
	public static final int M680X_IDX_NO_COMMA = 2;

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
	public static final int M680X_SECOND_OP_IN_MNEM = 2;

	// M680X instruction IDs

	public static final int M680X_INS_INVLD = 0;
	public static final int M680X_INS_ABA = 1;
	public static final int M680X_INS_ABX = 2;
	public static final int M680X_INS_ADCA = 3;
	public static final int M680X_INS_ADCB = 4;
	public static final int M680X_INS_ADCD = 5;
	public static final int M680X_INS_ADCR = 6;
	public static final int M680X_INS_ADDA = 7;
	public static final int M680X_INS_ADDB = 8;
	public static final int M680X_INS_ADDD = 9;
	public static final int M680X_INS_ADDE = 10;
	public static final int M680X_INS_ADDF = 11;
	public static final int M680X_INS_ADDR = 12;
	public static final int M680X_INS_ADDW = 13;
	public static final int M680X_INS_AIM = 14;
	public static final int M680X_INS_ANDA = 15;
	public static final int M680X_INS_ANDB = 16;
	public static final int M680X_INS_ANDCC = 17;
	public static final int M680X_INS_ANDD = 18;
	public static final int M680X_INS_ANDR = 19;
	public static final int M680X_INS_ASL = 20;
	public static final int M680X_INS_ASLA = 21;
	public static final int M680X_INS_ASLB = 22;
	public static final int M680X_INS_ASLD = 23;
	public static final int M680X_INS_ASR = 24;
	public static final int M680X_INS_ASRA = 25;
	public static final int M680X_INS_ASRB = 26;
	public static final int M680X_INS_ASRD = 27;
	public static final int M680X_INS_BAND = 28;
	public static final int M680X_INS_BCC = 29;
	public static final int M680X_INS_BCS = 30;
	public static final int M680X_INS_BEOR = 31;
	public static final int M680X_INS_BEQ = 32;
	public static final int M680X_INS_BGE = 33;
	public static final int M680X_INS_BGT = 34;
	public static final int M680X_INS_BHI = 35;
	public static final int M680X_INS_BIAND = 36;
	public static final int M680X_INS_BIEOR = 37;
	public static final int M680X_INS_BIOR = 38;
	public static final int M680X_INS_BITA = 39;
	public static final int M680X_INS_BITB = 40;
	public static final int M680X_INS_BITD = 41;
	public static final int M680X_INS_BITMD = 42;
	public static final int M680X_INS_BLE = 43;
	public static final int M680X_INS_BLS = 44;
	public static final int M680X_INS_BLT = 45;
	public static final int M680X_INS_BMI = 46;
	public static final int M680X_INS_BNE = 47;
	public static final int M680X_INS_BOR = 48;
	public static final int M680X_INS_BPL = 49;
	public static final int M680X_INS_BRA = 50;
	public static final int M680X_INS_BRN = 51;
	public static final int M680X_INS_BSR = 52;
	public static final int M680X_INS_BVC = 53;
	public static final int M680X_INS_BVS = 54;
	public static final int M680X_INS_CBA = 55;
	public static final int M680X_INS_CLC = 56;
	public static final int M680X_INS_CLI = 57;
	public static final int M680X_INS_CLR = 58;
	public static final int M680X_INS_CLRA = 59;
	public static final int M680X_INS_CLRB = 60;
	public static final int M680X_INS_CLRD = 61;
	public static final int M680X_INS_CLRE = 62;
	public static final int M680X_INS_CLRF = 63;
	public static final int M680X_INS_CLRW = 64;
	public static final int M680X_INS_CLV = 65;
	public static final int M680X_INS_CMPA = 66;
	public static final int M680X_INS_CMPB = 67;
	public static final int M680X_INS_CMPD = 68;
	public static final int M680X_INS_CMPE = 69;
	public static final int M680X_INS_CMPF = 70;
	public static final int M680X_INS_CMPR = 71;
	public static final int M680X_INS_CMPS = 72;
	public static final int M680X_INS_CMPU = 73;
	public static final int M680X_INS_CMPW = 74;
	public static final int M680X_INS_CMPX = 75;
	public static final int M680X_INS_CMPY = 76;
	public static final int M680X_INS_COM = 77;
	public static final int M680X_INS_COMA = 78;
	public static final int M680X_INS_COMB = 79;
	public static final int M680X_INS_COMD = 80;
	public static final int M680X_INS_COME = 81;
	public static final int M680X_INS_COMF = 82;
	public static final int M680X_INS_COMW = 83;
	public static final int M680X_INS_CPX = 84;
	public static final int M680X_INS_CWAI = 85;
	public static final int M680X_INS_DAA = 86;
	public static final int M680X_INS_DEC = 87;
	public static final int M680X_INS_DECA = 88;
	public static final int M680X_INS_DECB = 89;
	public static final int M680X_INS_DECD = 90;
	public static final int M680X_INS_DECE = 91;
	public static final int M680X_INS_DECF = 92;
	public static final int M680X_INS_DECW = 93;
	public static final int M680X_INS_DES = 94;
	public static final int M680X_INS_DEX = 95;
	public static final int M680X_INS_DIVD = 96;
	public static final int M680X_INS_DIVQ = 97;
	public static final int M680X_INS_EIM = 98;
	public static final int M680X_INS_EORA = 99;
	public static final int M680X_INS_EORB = 100;
	public static final int M680X_INS_EORD = 101;
	public static final int M680X_INS_EORR = 102;
	public static final int M680X_INS_EXG = 103;
	public static final int M680X_INS_ILLGL = 104;
	public static final int M680X_INS_INC = 105;
	public static final int M680X_INS_INCA = 106;
	public static final int M680X_INS_INCB = 107;
	public static final int M680X_INS_INCD = 108;
	public static final int M680X_INS_INCE = 109;
	public static final int M680X_INS_INCF = 110;
	public static final int M680X_INS_INCW = 111;
	public static final int M680X_INS_INS = 112;
	public static final int M680X_INS_INX = 113;
	public static final int M680X_INS_JMP = 114;
	public static final int M680X_INS_JSR = 115;
	public static final int M680X_INS_LBCC = 116;
	public static final int M680X_INS_LBCS = 117;
	public static final int M680X_INS_LBEQ = 118;
	public static final int M680X_INS_LBGE = 119;
	public static final int M680X_INS_LBGT = 120;
	public static final int M680X_INS_LBHI = 121;
	public static final int M680X_INS_LBLE = 122;
	public static final int M680X_INS_LBLS = 123;
	public static final int M680X_INS_LBLT = 124;
	public static final int M680X_INS_LBMI = 125;
	public static final int M680X_INS_LBNE = 126;
	public static final int M680X_INS_LBPL = 127;
	public static final int M680X_INS_LBRA = 128;
	public static final int M680X_INS_LBRN = 129;
	public static final int M680X_INS_LBSR = 130;
	public static final int M680X_INS_LBVC = 131;
	public static final int M680X_INS_LBVS = 132;
	public static final int M680X_INS_LDA = 133;
	public static final int M680X_INS_LDAA = 134;
	public static final int M680X_INS_LDAB = 135;
	public static final int M680X_INS_LDB = 136;
	public static final int M680X_INS_LDBT = 137;
	public static final int M680X_INS_LDD = 138;
	public static final int M680X_INS_LDE = 139;
	public static final int M680X_INS_LDF = 140;
	public static final int M680X_INS_LDMD = 141;
	public static final int M680X_INS_LDQ = 142;
	public static final int M680X_INS_LDS = 143;
	public static final int M680X_INS_LDU = 144;
	public static final int M680X_INS_LDW = 145;
	public static final int M680X_INS_LDX = 146;
	public static final int M680X_INS_LDY = 147;
	public static final int M680X_INS_LEAS = 148;
	public static final int M680X_INS_LEAU = 149;
	public static final int M680X_INS_LEAX = 150;
	public static final int M680X_INS_LEAY = 151;
	public static final int M680X_INS_LSL = 152;
	public static final int M680X_INS_LSLA = 153;
	public static final int M680X_INS_LSLB = 154;
	public static final int M680X_INS_LSLD = 155;
	public static final int M680X_INS_LSR = 156;
	public static final int M680X_INS_LSRA = 157;
	public static final int M680X_INS_LSRB = 158;
	public static final int M680X_INS_LSRD = 159;
	public static final int M680X_INS_LSRW = 160;
	public static final int M680X_INS_MUL = 161;
	public static final int M680X_INS_MULD = 162;
	public static final int M680X_INS_NEG = 163;
	public static final int M680X_INS_NEGA = 164;
	public static final int M680X_INS_NEGB = 165;
	public static final int M680X_INS_NEGD = 166;
	public static final int M680X_INS_NOP = 167;
	public static final int M680X_INS_OIM = 168;
	public static final int M680X_INS_ORA = 169;
	public static final int M680X_INS_ORAA = 170;
	public static final int M680X_INS_ORAB = 171;
	public static final int M680X_INS_ORB = 172;
	public static final int M680X_INS_ORCC = 173;
	public static final int M680X_INS_ORD = 174;
	public static final int M680X_INS_ORR = 175;
	public static final int M680X_INS_PSHA = 176;
	public static final int M680X_INS_PSHB = 177;
	public static final int M680X_INS_PSHS = 178;
	public static final int M680X_INS_PSHSW = 179;
	public static final int M680X_INS_PSHU = 180;
	public static final int M680X_INS_PSHUW = 181;
	public static final int M680X_INS_PSHX = 182;
	public static final int M680X_INS_PULA = 183;
	public static final int M680X_INS_PULB = 184;
	public static final int M680X_INS_PULS = 185;
	public static final int M680X_INS_PULSW = 186;
	public static final int M680X_INS_PULU = 187;
	public static final int M680X_INS_PULUW = 188;
	public static final int M680X_INS_PULX = 189;
	public static final int M680X_INS_ROL = 190;
	public static final int M680X_INS_ROLA = 191;
	public static final int M680X_INS_ROLB = 192;
	public static final int M680X_INS_ROLD = 193;
	public static final int M680X_INS_ROLW = 194;
	public static final int M680X_INS_ROR = 195;
	public static final int M680X_INS_RORA = 196;
	public static final int M680X_INS_RORB = 197;
	public static final int M680X_INS_RORD = 198;
	public static final int M680X_INS_RORW = 199;
	public static final int M680X_INS_RTI = 200;
	public static final int M680X_INS_RTS = 201;
	public static final int M680X_INS_SBA = 202;
	public static final int M680X_INS_SBCA = 203;
	public static final int M680X_INS_SBCB = 204;
	public static final int M680X_INS_SBCD = 205;
	public static final int M680X_INS_SBCR = 206;
	public static final int M680X_INS_SEC = 207;
	public static final int M680X_INS_SEI = 208;
	public static final int M680X_INS_SEV = 209;
	public static final int M680X_INS_SEX = 210;
	public static final int M680X_INS_SEXW = 211;
	public static final int M680X_INS_STA = 212;
	public static final int M680X_INS_STAA = 213;
	public static final int M680X_INS_STAB = 214;
	public static final int M680X_INS_STB = 215;
	public static final int M680X_INS_STBT = 216;
	public static final int M680X_INS_STD = 217;
	public static final int M680X_INS_STE = 218;
	public static final int M680X_INS_STF = 219;
	public static final int M680X_INS_STQ = 220;
	public static final int M680X_INS_STS = 221;
	public static final int M680X_INS_STU = 222;
	public static final int M680X_INS_STW = 223;
	public static final int M680X_INS_STX = 224;
	public static final int M680X_INS_STY = 225;
	public static final int M680X_INS_SUBA = 226;
	public static final int M680X_INS_SUBB = 227;
	public static final int M680X_INS_SUBD = 228;
	public static final int M680X_INS_SUBE = 229;
	public static final int M680X_INS_SUBF = 230;
	public static final int M680X_INS_SUBR = 231;
	public static final int M680X_INS_SUBW = 232;
	public static final int M680X_INS_SWI = 233;
	public static final int M680X_INS_SWI2 = 234;
	public static final int M680X_INS_SWI3 = 235;
	public static final int M680X_INS_SYNC = 236;
	public static final int M680X_INS_TAB = 237;
	public static final int M680X_INS_TAP = 238;
	public static final int M680X_INS_TBA = 239;
	public static final int M680X_INS_TPA = 240;
	public static final int M680X_INS_TFM = 241;
	public static final int M680X_INS_TFR = 242;
	public static final int M680X_INS_TIM = 243;
	public static final int M680X_INS_TST = 244;
	public static final int M680X_INS_TSTA = 245;
	public static final int M680X_INS_TSTB = 246;
	public static final int M680X_INS_TSTD = 247;
	public static final int M680X_INS_TSTE = 248;
	public static final int M680X_INS_TSTF = 249;
	public static final int M680X_INS_TSTW = 250;
	public static final int M680X_INS_TSX = 251;
	public static final int M680X_INS_TXS = 252;
	public static final int M680X_INS_WAI = 253;
	public static final int M680X_INS_XGDX = 254;
	public static final int M680X_INS_ENDING = 255;
}