// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import com.sun.jna.Native;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;

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

  public static void print_ins_detail(Capstone.cs_insn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.operands);

    Mips.OpInfo op_info = (Mips.OpInfo) ins.op_info;

    if (op_info.op != null) {
      System.out.printf("\top_count: %d\n", op_info.op.length);
      for (int c=1; c<op_info.op.length+1; c++) {
        Mips.Operand i = (Mips.Operand) op_info.op[c-1];
        String imm = hex(i.value.imm);
        if (i.type == Mips.MIPS_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, cs.reg_name(i.value.reg));
        if (i.type == Mips.MIPS_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = %s\n", c, imm);
        if (i.type == Mips.MIPS_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String base = cs.reg_name(i.value.mem.base);
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
      new Test.platform(Capstone.CS_ARCH_MIPS, Capstone.CS_MODE_32 + Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(MIPS_CODE), "MIPS-32 (Big-endian)"),
      new Test.platform(Capstone.CS_ARCH_MIPS, Capstone.CS_MODE_64 + Capstone.CS_MODE_LITTLE_ENDIAN, hexString2Byte(MIPS_CODE2), "MIPS-64-EL (Little-endian)"),
    };

    for (int i=0; i<all_tests.length; i++) {
      Test.platform test = all_tests[i];
      System.out.println(new String(new char[30]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      Capstone.cs_insn[] all_ins = cs.disasm(test.code, 0x1000);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }
    }
  }

}
