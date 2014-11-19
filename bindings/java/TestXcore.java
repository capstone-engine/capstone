// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014

import capstone.Capstone;
import capstone.Xcore;

import static capstone.Xcore_const.*;

public class TestXcore {
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

  static final String XCORE_CODE = "fe0ffe171317c6feec1797f8ec4f1ffdec3707f2455bf9fa02061b1009fdeca7";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Xcore.OpInfo operands = (Xcore.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Xcore.Operand i = (Xcore.Operand) operands.op[c];
        if (i.type == XCORE_OP_REG)
            System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == XCORE_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == XCORE_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          if (i.value.mem.base != XCORE_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, ins.regName(i.value.mem.base));
          if (i.value.mem.index != XCORE_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, ins.regName(i.value.mem.index));
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
          if (i.value.mem.direct != 1)
            System.out.printf("\t\t\toperands[%d].mem.direct: -1\n", c);
        }
      }
    }
  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_XCORE, Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(XCORE_CODE), "XCore"),
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
