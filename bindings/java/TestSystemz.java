// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014

import capstone.Capstone;
import capstone.Systemz;

import static capstone.Sysz_const.*;

public class TestSystemz {

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

  static final String SYSZ_CODE = "ed000000001a5a0f1fffc2098000000007f7eb2affff7f57e301ffff7f57eb00f0000024b24f0078ec180000c17f";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Systemz.OpInfo operands = (Systemz.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Systemz.Operand i = (Systemz.Operand) operands.op[c];
        if (i.type == SYSZ_OP_REG)
            System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == SYSZ_OP_ACREG)
            System.out.printf("\t\toperands[%d].type: ACREG = %s\n", c, i.value.reg);
        if (i.type == SYSZ_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == SYSZ_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          if (i.value.mem.base != SYSZ_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, ins.regName(i.value.mem.base));
          if (i.value.mem.index != SYSZ_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, ins.regName(i.value.mem.index));
          if (i.value.mem.length != 0)
            System.out.printf("\t\t\toperands[%d].mem.length: 0x%x\n", c, i.value.mem.disp);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
      }
    }

    if (operands.cc != 0)
      System.out.printf("\tConditional code: %d\n", operands.cc);

  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_SYSZ, 0, hexString2Byte(SYSZ_CODE), "SystemZ"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + TestBasic.stringToHex(test.code));
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
