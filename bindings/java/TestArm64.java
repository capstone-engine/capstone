// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.Arm64;

import static capstone.Arm64_const.*;

public class TestArm64 {

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

  static final String ARM64_CODE = "090038d5bf4000d50c0513d52050020e20e43d0f0018a05fa200ae9e9f3703d5bf3303d5df3f03d5217c029b217c00530040214be10b40b9200481da2008028b105be83c";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Arm64.OpInfo operands = (Arm64.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Arm64.Operand i = (Arm64.Operand) operands.op[c];
        String imm = hex(i.value.imm);
        if (i.type == ARM64_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == ARM64_OP_REG_MRS)
          System.out.printf("\t\toperands[%d].type: REG_MRS = 0x%x\n", c, i.value.reg);
        if (i.type == ARM64_OP_REG_MSR)
          System.out.printf("\t\toperands[%d].type: REG_MSR = 0x%x\n", c, i.value.reg);
        if (i.type == ARM64_OP_PSTATE)
          System.out.printf("\t\toperands[%d].type: PSTATE = 0x%x\n", c, i.value.imm);
			  if (i.type == ARM64_OP_BARRIER)
  				System.out.printf("\t\toperands[%d].type: BARRIER = 0x%x\n", c, i.value.imm);

        if (i.type == ARM64_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == ARM64_OP_CIMM)
          System.out.printf("\t\toperands[%d].type: C-IMM = %d\n", c, i.value.imm);
        if (i.type == ARM64_OP_FP)
          System.out.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
        if (i.type == ARM64_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String base = ins.regName(i.value.mem.base);
          String index = ins.regName(i.value.mem.index);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (index != null)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
        if (i.shift.type != ARM64_SFT_INVALID && i.shift.value > 0)
          System.out.printf("\t\t\tShift: type = %d, value = %d\n", i.shift.type, i.shift.value);
        if (i.ext != ARM64_EXT_INVALID)
          System.out.printf("\t\t\tExt: %d\n", i.ext);
        if (i.vas != ARM64_VAS_INVALID)
          System.out.printf("\t\t\tVector Arrangement Specifier: 0x%x\n", i.vas);
        if (i.vess != ARM64_VESS_INVALID)
          System.out.printf("\t\t\tVector Element Size Specifier: %d\n", i.vess);
        if (i.vector_index != -1)
          System.out.printf("\t\t\tVector Index: %d\n", i.vector_index);

      }
    }

    if (operands.writeback)
      System.out.println("\tWrite-back: True");

    if (operands.updateFlags)
      System.out.println("\tUpdate-flags: True");

    if (operands.cc != ARM64_CC_AL && operands.cc != ARM64_CC_INVALID)
      System.out.printf("\tCode-condition: %d\n",  operands.cc);

  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM, hexString2Byte(ARM64_CODE), "ARM-64"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + TestBasic.stringToHex(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      Capstone.CsInsn[] all_ins = cs.disasm(test.code, 0x2c);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }

      System.out.printf("0x%x: \n\n", all_ins[all_ins.length-1].address + all_ins[all_ins.length-1].size);

      // Close when done
      cs.close();
    }
  }

}
