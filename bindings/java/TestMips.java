// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.Mips;

import static capstone.Mips_const.*;

public class TestMips {

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

  static final String MIPS_CODE  = "0C100097000000002402000c8fa2000034213456";
  static final String MIPS_CODE2 = "56342134c2170100";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Mips.OpInfo operands = (Mips.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Mips.Operand i = (Mips.Operand) operands.op[c];
        String imm = hex(i.value.imm);
        if (i.type == MIPS_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == MIPS_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == MIPS_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String base = ins.regName(i.value.mem.base);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: %s\n", c, hex(i.value.mem.disp));
        }
      }
    }
  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_MIPS, Capstone.CS_MODE_MIPS32 + Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(MIPS_CODE), "MIPS-32 (Big-endian)"),
      new Test.platform(Capstone.CS_ARCH_MIPS, Capstone.CS_MODE_MIPS64 + Capstone.CS_MODE_LITTLE_ENDIAN, hexString2Byte(MIPS_CODE2), "MIPS-64-EL (Little-endian)"),
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

      System.out.printf("0x%x:\n\n", all_ins[all_ins.length-1].address + all_ins[all_ins.length-1].size);

      // Close when done
      cs.close();
    }
  }

}
