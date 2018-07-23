// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.Ppc;

import static capstone.Ppc_const.*;

public class TestPpc {

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

  static final String PPC_CODE = "80200000803f00001043230ed04400804c4322022d0300807c4320147c4320934f2000214cc8002140820014";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Ppc.OpInfo operands = (Ppc.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Ppc.Operand i = (Ppc.Operand) operands.op[c];
        if (i.type == PPC_OP_REG)
            System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == PPC_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == PPC_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          if (i.value.mem.base != PPC_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, ins.regName(i.value.mem.base));
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
      }
    }

    if (operands.bc != 0)
      System.out.printf("\tBranch code: %d\n", operands.bc);

    if (operands.bh != 0)
      System.out.printf("\tBranch hint: %d\n", operands.bh);

    if (operands.updateCr0)
      System.out.printf("\tUpdate-CR0: True\n");

  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_PPC, Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(PPC_CODE), "PPC-64"),
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
