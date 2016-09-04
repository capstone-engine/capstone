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

  static final String ARM_CODE = "EDFFFFEB04e02de500000000e08322e5f102030e0000a0e30230c1e7000053e3000201f10540d0e8";
  static final String ARM_CODE2 = "d1e800f0f02404071f3cf2c000004ff00001466c";
  static final String THUMB_CODE2 = "4ff00001bde80088d1e800f018bfadbff3ff0b0c86f3008980f3008c4ffa99f6d0ffa201";
  static final String THUMB_CODE  = "7047eb4683b0c9681fb130bfaff32084";

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
        if (i.type == ARM_OP_SYSREG)
          System.out.printf("\t\toperands[%d].type: SYSREG = %d\n", c, i.value.reg);
        if (i.type == ARM_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == ARM_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == ARM_OP_PIMM)
          System.out.printf("\t\toperands[%d].type: P-IMM = %d\n", c, i.value.imm);
        if (i.type == ARM_OP_CIMM)
          System.out.printf("\t\toperands[%d].type: C-IMM = %d\n", c, i.value.imm);
        if (i.type == ARM_OP_SETEND)
  				System.out.printf("\t\toperands[%d].type: SETEND = %s\n", c, i.value.setend == ARM_SETEND_BE? "be" : "le");
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
          if (i.value.mem.lshift != 0)
            System.out.printf("\t\t\toperands[%d].mem.lshift: 0x%x\n", c, (i.value.mem.lshift));
        }
        if (i.vector_index > 0)
          System.out.printf("\t\t\toperands[%d].vector_index = %d\n", c, (i.vector_index));
        if (i.shift.type != ARM_SFT_INVALID && i.shift.value > 0)
          System.out.printf("\t\t\tShift: %d = %d\n", i.shift.type, i.shift.value);
        if (i.subtracted)
          System.out.printf("\t\t\toperands[%d].subtracted = True\n", c);
      }
    }
    if (operands.writeback)
      System.out.println("\tWrite-back: True");

    if (operands.updateFlags)
      System.out.println("\tUpdate-flags: True");

    if (operands.cc != ARM_CC_AL && operands.cc != ARM_CC_INVALID)
      System.out.printf("\tCode condition: %d\n",  operands.cc);

    if (operands.cpsMode > 0)
      System.out.printf("\tCPSI-mode: %d\n", operands.cpsMode);

    if (operands.cpsFlag > 0)
      System.out.printf("\tCPSI-flag: %d\n", operands.cpsFlag);

    if (operands.vectorData > 0)
      System.out.printf("\tVector-data: %d\n", operands.vectorData);

    if (operands.vectorSize > 0)
      System.out.printf("\tVector-size: %d\n", operands.vectorSize);

    if (operands.usermode)
      System.out.printf("\tUser-mode: True\n");
  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM, hexString2Byte(ARM_CODE), "ARM"),
      new TestBasic.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, hexString2Byte(THUMB_CODE), "Thumb"),
      new TestBasic.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, hexString2Byte(ARM_CODE2), "Thumb-mixed"),
      new TestBasic.platform(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB, Capstone.CS_OPT_SYNTAX_NOREGNAME, hexString2Byte(THUMB_CODE2), "Thumb-2 & register named with numbers"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + TestBasic.stringToHex(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      if (test.syntax != 0)
        cs.setSyntax(test.syntax);
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
