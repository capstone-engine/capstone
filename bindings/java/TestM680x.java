// Capstone Java binding
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

import capstone.Capstone;
import capstone.M680x;

import static capstone.M680x_const.*;

public class TestM680x {

  static final String sAddressingModes[] = {
    "M680X_AM_NONE",
    "M680X_AM_INHERENT",
    "M680X_AM_REGISTER",
    "M680X_AM_IMMEDIATE",
    "M680X_AM_INDEXED",
    "M680X_AM_EXTENDED",
    "M680X_AM_DIRECT",
    "M680X_AM_RELATIVE",
    "M680X_AM_IMM_DIRECT",
    "M680X_AM_IMM_INDEXED",
  };

  static final String sInsnIds[] = {
    "M680X_INS_INVLD", "M680X_INS_ABA", "M680X_INS_ABX", "M680X_INS_ADCA",
    "M680X_INS_ADCB", "M680X_INS_ADCD", "M680X_INS_ADDA", "M680X_INS_ADDB",
    "M680X_INS_ADDD", "M680X_INS_ADDE", "M680X_INS_ADDF", "M680X_INS_ADDR",
    "M680X_INS_ADDW", "M680X_INS_AIM", "M680X_INS_ANDA", "M680X_INS_ANDB",
    "M680X_INS_ANDCC", "M680X_INS_ANDD", "M680X_INS_ANDR", "M680X_INS_ASL",
    "M680X_INS_ASLA", "M680X_INS_ASLB", "M680X_INS_ASLD", "M680X_INS_ASR",
    "M680X_INS_ASRA", "M680X_INS_ASRB", "M680X_INS_BAND", "M680X_INS_BCC",
    "M680X_INS_BCS", "M680X_INS_BEOR", "M680X_INS_BEQ", "M680X_INS_BGE",
    "M680X_INS_BGT", "M680X_INS_BHI", "M680X_INS_BIAND", "M680X_INS_BIEOR",
    "M680X_INS_BIOR", "M680X_INS_BITA", "M680X_INS_BITB", "M680X_INS_BITD",
    "M680X_INS_BITMD", "M680X_INS_BLE", "M680X_INS_BLS", "M680X_INS_BLT",
    "M680X_INS_BMI", "M680X_INS_BNE", "M680X_INS_BOR", "M680X_INS_BPL",
    "M680X_INS_BRA", "M680X_INS_BRN", "M680X_INS_BSR", "M680X_INS_BVC",
    "M680X_INS_BVS", "M680X_INS_CBA", "M680X_INS_CLC", "M680X_INS_CLI",
    "M680X_INS_CLR", "M680X_INS_CLRA", "M680X_INS_CLRB", "M680X_INS_CLRD",
    "M680X_INS_CLRE", "M680X_INS_CLRF", "M680X_INS_CLRW", "M680X_INS_CLV",
    "M680X_INS_CMPA", "M680X_INS_CMPB", "M680X_INS_CMPD", "M680X_INS_CMPE",
    "M680X_INS_CMPF", "M680X_INS_CMPR", "M680X_INS_CMPS", "M680X_INS_CMPU",
    "M680X_INS_CMPW", "M680X_INS_CMPX", "M680X_INS_CMPY", "M680X_INS_COM",
    "M680X_INS_COMA", "M680X_INS_COMB", "M680X_INS_COMD", "M680X_INS_COME",
    "M680X_INS_COMF", "M680X_INS_COMW", "M680X_INS_CPX", "M680X_INS_CWAI",
    "M680X_INS_DAA", "M680X_INS_DEC", "M680X_INS_DECA", "M680X_INS_DECB",
    "M680X_INS_DECD", "M680X_INS_DECE", "M680X_INS_DECF", "M680X_INS_DECW",
    "M680X_INS_DES", "M680X_INS_DEX", "M680X_INS_DIVD", "M680X_INS_DIVQ",
    "M680X_INS_EIM", "M680X_INS_EORA", "M680X_INS_EORB", "M680X_INS_EORD",
    "M680X_INS_EORR", "M680X_INS_EXG", "M680X_INS_ILLGL", "M680X_INS_INC",
    "M680X_INS_INCA", "M680X_INS_INCB", "M680X_INS_INCD", "M680X_INS_INCE",
    "M680X_INS_INCF", "M680X_INS_INCW", "M680X_INS_INS", "M680X_INS_INX",
    "M680X_INS_JMP", "M680X_INS_JSR", "M680X_INS_LBCC", "M680X_INS_LBCS",
    "M680X_INS_LBEQ", "M680X_INS_LBGE", "M680X_INS_LBGT", "M680X_INS_LBHI",
    "M680X_INS_LBLE", "M680X_INS_LBLS", "M680X_INS_LBLT", "M680X_INS_LBMI",
    "M680X_INS_LBNE", "M680X_INS_LBPL", "M680X_INS_LBRA", "M680X_INS_LBRN",
    "M680X_INS_LBSR", "M680X_INS_LBVC", "M680X_INS_LBVS", "M680X_INS_LDA",
    "M680X_INS_LDAA", "M680X_INS_LDAB", "M680X_INS_LDB", "M680X_INS_LDBT",
    "M680X_INS_LDD", "M680X_INS_LDE", "M680X_INS_LDF", "M680X_INS_LDMD",
    "M680X_INS_LDQ", "M680X_INS_LDS", "M680X_INS_LDU", "M680X_INS_LDW",
    "M680X_INS_LDX", "M680X_INS_LDY", "M680X_INS_LEAS", "M680X_INS_LEAU",
    "M680X_INS_LEAX", "M680X_INS_LEAY", "M680X_INS_LSL", "M680X_INS_LSLA",
    "M680X_INS_LSLB", "M680X_INS_LSR", "M680X_INS_LSRA", "M680X_INS_LSRB",
    "M680X_INS_LSRD", "M680X_INS_LSRW", "M680X_INS_MUL", "M680X_INS_MULD",
    "M680X_INS_NEG", "M680X_INS_NEGA", "M680X_INS_NEGB", "M680X_INS_NEGD",
    "M680X_INS_NOP", "M680X_INS_OIM", "M680X_INS_ORA", "M680X_INS_ORAA",
    "M680X_INS_ORAB", "M680X_INS_ORB", "M680X_INS_ORCC", "M680X_INS_ORD",
    "M680X_INS_ORR", "M680X_INS_PSHA", "M680X_INS_PSHB", "M680X_INS_PSHS",
    "M680X_INS_PSHSW", "M680X_INS_PSHU", "M680X_INS_PSHUW", "M680X_INS_PSHX",
    "M680X_INS_PULA", "M680X_INS_PULB", "M680X_INS_PULS", "M680X_INS_PULSW",
    "M680X_INS_PULU", "M680X_INS_PULUW", "M680X_INS_PULX", "M680X_INS_ROL",
    "M680X_INS_ROLA", "M680X_INS_ROLB", "M680X_INS_ROLD", "M680X_INS_ROLW",
    "M680X_INS_ROR", "M680X_INS_RORA", "M680X_INS_RORB", "M680X_INS_RORD",
    "M680X_INS_RORW", "M680X_INS_RTI", "M680X_INS_RTS", "M680X_INS_SBA",
    "M680X_INS_SBCA", "M680X_INS_SBCB", "M680X_INS_SBCD", "M680X_INS_SBCR",
    "M680X_INS_SEC", "M680X_INS_SEI", "M680X_INS_SEV", "M680X_INS_SEX",
    "M680X_INS_SEXW", "M680X_INS_STA", "M680X_INS_STAA", "M680X_INS_STAB",
    "M680X_INS_STB", "M680X_INS_STBT", "M680X_INS_STD", "M680X_INS_STE",
    "M680X_INS_STF", "M680X_INS_STQ", "M680X_INS_STS", "M680X_INS_STU",
    "M680X_INS_STW", "M680X_INS_STX", "M680X_INS_STY", "M680X_INS_SUBA",
    "M680X_INS_SUBB", "M680X_INS_SUBD", "M680X_INS_SUBE", "M680X_INS_SUBF",
    "M680X_INS_SUBR", "M680X_INS_SUBW", "M680X_INS_SWI", "M680X_INS_SWI2",
    "M680X_INS_SWI3", "M680X_INS_SYNC", "M680X_INS_TAB", "M680X_INS_TAP",
    "M680X_INS_TBA", "M680X_INS_TPA", "M680X_INS_TFM", "M680X_INS_TFR",
    "M680X_INS_TIM", "M680X_INS_TST", "M680X_INS_TSTA", "M680X_INS_TSTB",
    "M680X_INS_TSTD", "M680X_INS_TSTE", "M680X_INS_TSTF", "M680X_INS_TSTW",
    "M680X_INS_TSX", "M680X_INS_TXS", "M680X_INS_WAI", "M680X_INS_XGDX",
  };

  static final String M6800_CODE = "010936647f7410009010A410b6100039";
  static final String M6801_CODE = "04053c3d389310ec10ed1039";
  static final String HD6301_CODE = "6b100071100072101039";
  static final String M6809_CODE = "0610191a551e0123e931063455a681a7897fffa69d1000a791a69f100011ac99100039A607A627A647A667A60FA610A680A681A682A683A684A685A686A6887FA68880A6897FFFA6898000A68BA68C10A68D1000A691A693A694A695A696A6987FA69880A6997FFFA6998000A69BA69C10A69D1000A69F1000";

  static byte[] hexString2Byte(String s) {
    // from http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
          + Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }

  static public String stringToHexUc(byte[] code) {
    StringBuilder buf = new StringBuilder(800);
    for (byte ch: code) {
      buf.append(String.format(" 0x%02X", ch));
    }
    return buf.toString();
  }

  static public String stringToHexShortUc(byte[] code) {
    StringBuilder buf = new StringBuilder(800);
    for (byte ch: code) {
      buf.append(String.format("%02X", ch));
    }
    return buf.toString();
  }

  public static Capstone cs;
/*
  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }
*/
  public static void print_ins_detail(Capstone.CsInsn ins) {
    String bytes = stringToHexShortUc(ins.bytes);
    System.out.printf("0x%04X:\t%s\t%s\t%s\n", ins.address, bytes, ins.mnemonic, ins.opStr);

    M680x.OpInfo operands = (M680x.OpInfo) ins.operands;

    System.out.printf("\tinsn id: %s\n", sInsnIds[ins.id]);
    System.out.printf("\taddress_mode: %s\n", sAddressingModes[operands.addressMode]);

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c = 0; c < operands.op.length; c++) {
        M680x.Operand i = (M680x.Operand) operands.op[c];
        if (i.type == M680X_OP_REGISTER) {
          String comment = "";
          if (c == 0 && ((operands.flags & M680X_FIRST_OP_IN_MNEM) != 0))
            comment = " (in mnemonic)";
          System.out.printf("\t\toperands[%d].type: REGISTER = %s%s\n", c, ins.regName(i.value.reg), comment);
          System.out.printf("\t\t\tsize: %d\n", i.size);
        }
        if (i.type == M680X_OP_IMMEDIATE) {
          System.out.printf("\t\toperands[%d].type: IMMEDIATE = #%d\n", c, i.value.imm);
          System.out.printf("\t\t\tsize: %d\n", i.size);
        }
        if (i.type == M680X_OP_DIRECT) {
          System.out.printf("\t\toperands[%d].type: DIRECT = 0x%02X\n", c, i.value.direct_addr);
          System.out.printf("\t\t\tsize: %d\n", i.size);
        }
        if (i.type == M680X_OP_EXTENDED) {
          System.out.printf("\t\toperands[%d].type: EXTENDED %s = 0x%04X\n", c,
            i.value.ext.indirect != 0 ? "INDIRECT" : "", i.value.ext.address);
          System.out.printf("\t\t\tsize: %d\n", i.size);
        }
        if (i.type == M680X_OP_RELATIVE) {
          System.out.printf("\t\toperands[%d].type: RELATIVE = 0x%04X\n", c, i.value.rel.address );
          System.out.printf("\t\t\tsize: %d\n", i.size);
        }
        if (i.type == M680X_OP_INDEXED_00) {
          System.out.printf("\t\toperands[%d].type: INDEXED_M6800\n", c);
          System.out.printf("\t\t\tsize: %d\n", i.size);
          if (i.value.idx.base_reg != M680X_REG_INVALID) {
            String base = ins.regName(i.value.idx.base_reg);
            if (base != null)
              System.out.printf("\t\t\tbase register: %s\n", base);
          }
          if (i.value.idx.offset_bits != 0) {
            System.out.printf("\t\t\toffset: %d\n", i.value.idx.offset);
            System.out.printf("\t\t\toffset bits: %d\n", i.value.idx.offset_bits);
          }
        }
        if (i.type == M680X_OP_INDEXED_09) {
          System.out.printf("\t\toperands[%d].type: INDEXED_M6809 %s\n", c,
            i.value.idx.indirect != 0 ? "INDIRECT" : "");
          System.out.printf("\t\t\tsize: %d\n", i.size);
          if (i.value.idx.base_reg != M680X_REG_INVALID) {
            String regName = ins.regName(i.value.idx.base_reg);
            if (regName != null)
              System.out.printf("\t\t\tbase register: %s\n", regName);
          }
          if (i.value.idx.offset_reg != M680X_REG_INVALID) {
            String regName = ins.regName(i.value.idx.offset_reg);
            if (regName != null)
              System.out.printf("\t\t\toffset register: %s\n", regName);
          }
          if ((i.value.idx.offset_bits != 0) &&
              (i.value.idx.offset_reg == M680X_REG_INVALID) &&
              (i.value.idx.inc_dec == 0)) {
            System.out.printf("\t\t\toffset: %d\n", i.value.idx.offset);
            if (i.value.idx.base_reg == M680X_REG_PC)
              System.out.printf("\t\t\toffset address: 0x%04X\n", i.value.idx.offset_addr);
            System.out.printf("\t\t\toffset bits: %d\n", i.value.idx.offset_bits);
          }
          if (i.value.idx.inc_dec > 0)
            System.out.printf("\t\t\tpost increment: %d\n", i.value.idx.inc_dec);
          if (i.value.idx.inc_dec < 0)
            System.out.printf("\t\t\tpre decrement: %d\n", i.value.idx.inc_dec);
        }
      }
    }

    if (ins.regsRead.length > 0) {
      System.out.printf("\tRegisters read:");
      for (int c = 0; c < ins.regsRead.length; c++) {
        System.out.printf(" %s", ins.regName(ins.regsRead[c]));
      }
      System.out.printf("\n");
    }

    if (ins.regsWrite.length > 0) {
      System.out.printf("\tRegisters modified:");
      for (int c = 0; c < ins.regsWrite.length; c++) {
        System.out.printf(" %s", ins.regName(ins.regsWrite[c]));
      }
      System.out.printf("\n");
    }

    if (ins.groups.length > 0)
      System.out.printf("\tgroups_count: %d\n", ins.groups.length);
  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6800,
          hexString2Byte(M6800_CODE), "M680X_M6800"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6801,
          hexString2Byte(M6801_CODE), "M680X_M6801"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6301,
          hexString2Byte(HD6301_CODE), "M680X_HD6301"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6809,
          hexString2Byte(M6809_CODE), "M680X_M6809"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[20]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + stringToHexUc(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      Capstone.CsInsn[] all_ins = cs.disasm(test.code, 0x1000);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }

      // Close when done
      cs.close();
    }
  }

}
