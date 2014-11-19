// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014

import capstone.Capstone;
import capstone.Sparc;

import static capstone.Sparc_const.*;

public class TestSparc {

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

  static final String SPARC_CODE = "80a0400285c2600885e8200181e8000090102001d5f610162100000a860040020100000012bfffff10bfffffa00200090dbfffffd4206000d44e00162ac28003";
  static final String SPARCV9_CODE = "81a80a2489a0102089a01a6089a000e0";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Sparc.OpInfo operands = (Sparc.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Sparc.Operand i = (Sparc.Operand) operands.op[c];
        if (i.type == SPARC_OP_REG)
            System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == SPARC_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == SPARC_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          if (i.value.mem.base != SPARC_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, ins.regName(i.value.mem.base));
          if (i.value.mem.index != SPARC_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, ins.regName(i.value.mem.index));
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
      }
    }

    if (operands.cc != 0)
      System.out.printf("\tCode condition: %d\n", operands.cc);

    if (operands.hint != 0)
      System.out.printf("\tHint code: %d\n", operands.hint);

  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_SPARC, Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(SPARC_CODE), "Sparc"),
      new Test.platform(Capstone.CS_ARCH_SPARC, Capstone.CS_MODE_BIG_ENDIAN + Capstone.CS_MODE_V9, hexString2Byte(SPARCV9_CODE), "SparcV9"),
    };

    for (int i=0; i<all_tests.length; i++) {
      Test.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + Test.stringToHex(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      Capstone.CsInsn[] all_ins = cs.disasm(test.code, 0x1000);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }
      System.out.printf("0x%x:\n\n", (all_ins[all_ins.length-1].address + all_ins[all_ins.length-1].size));

      // Close when done
      cs.close();
    }
  }

}
