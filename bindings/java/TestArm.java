// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.Arm;

import static capstone.Arm_const.*;

public class TestArm {

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

  static final String ARM_CODE = "EDFFFFEB04e02de500000000e08322e5f102030e0000a0e30230c1e7000053e3";
  static final String ARM_CODE2 = "d1e800f0f02404071f3cf2c000004ff00001466c";
  static final String THUMB_CODE2  = "4ff00001bde80088d1e800f0";
  static final String THUMB_CODE  = "7047eb4683b0c9681fb1";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Arm.OpInfo operands = (Arm.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Arm.Operand i = (Arm.Operand) operands.op[c];
        String imm = hex(i.value.imm);
        if (i.type == ARM_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == ARM_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == ARM_OP_PIMM)
          System.out.printf("\t\toperands[%d].type: P-IMM = %d\n", c, i.value.imm);
        if (i.type == ARM_OP_CIMM)
          System.out.printf("\t\toperands[%d].type: C-IMM = %d\n", c, i.value.imm);
        if (i.type == ARM_OP_FP)
          System.out.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
        if (i.type == ARM_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String base = ins.regName(i.value.mem.base);
          String index = ins.regName(i.value.mem.index);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (index != null)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
          if (i.value.mem.scale != 1)
            System.out.printf("\t\t\toperands[%d].mem.scale: %d\n", c, (i.value.mem.scale));
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, (i.value.mem.disp));
        }
        if (i.shift.type != ARM_SFT_INVALID && i.shift.value > 0)
          System.out.printf("\t\t\tShift: type = %d, value = %d\n", i.shift.type, i.shift.value);
      }
      if (operands.writeback)
        System.out.println("\tWrite-back: True");

      if (operands.updateFlags)
        System.out.println("\tUpdate-flags: True");

      if (operands.cc != ARM_CC_AL && operands.cc != ARM_CC_INVALID)
        System.out.printf("\tCode condition: %d\n",  operands.cc);
    }
  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM, hexString2Byte(ARM_CODE), "ARM"),
      new Test.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, hexString2Byte(THUMB_CODE), "Thumb"),
      new Test.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, hexString2Byte(ARM_CODE2), "Thumb-mixed"),
      new Test.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, hexString2Byte(THUMB_CODE2), "Thumb-2"),
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
    }
  }

}
