// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.X86;

import static capstone.X86_const.*;

public class TestX86 {

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

  static final String X86_CODE64 = "55488b05b8130000";
  static final String X86_CODE16 = "8d4c320801d881c6341200000523010000368b849123010000418d8439896700008d8789670000b4c6";
  static final String X86_CODE32 = "8d4c320801d881c6341200000523010000368b849123010000418d8439896700008d8789670000b4c6";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  private static String array2hex(byte[] arr) {
    String ret = "";
    for (int i=0 ;i<arr.length; i++)
      ret += String.format("0x%02x ", arr[i]);
    return ret;
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    X86.OpInfo operands = (X86.OpInfo) ins.operands;

    System.out.printf("\tPrefix: %s\n", array2hex(operands.prefix));

    System.out.printf("\tOpcode: %s\n", array2hex(operands.opcode));

    // print REX prefix (non-zero value is relevant for x86_64)
    System.out.printf("\trex: 0x%x\n", operands.rex);

    // print address size
    System.out.printf("\taddr_size: %d\n", operands.addrSize);

    // print modRM byte
    System.out.printf("\tmodrm: 0x%x\n", operands.modrm);

    // print displacement value
    System.out.printf("\tdisp: 0x%x\n", operands.disp);

    // SIB is not available in 16-bit mode
    if ( (cs.mode & Capstone.CS_MODE_16) == 0) {
      // print SIB byte
      System.out.printf("\tsib: 0x%x\n", operands.sib);
      if (operands.sib != 0)
        System.out.printf("\t\tsib_base: %s\n\t\tsib_index: %s\n\t\tsib_scale: %d\n",
          ins.regName(operands.sibBase), ins.regName(operands.sibIndex), operands.sibScale);
    }

    if (operands.sseCC != 0)
        System.out.printf("\tsse_cc: %u\n", operands.sseCC);

    if (operands.avxCC != 0)
        System.out.printf("\tavx_cc: %u\n", operands.avxCC);

    if (operands.avxSae)
        System.out.printf("\tavx_sae: TRUE\n");

    if (operands.avxRm != 0)
        System.out.printf("\tavx_rm: %u\n", operands.avxRm);

    int count = ins.opCount(X86_OP_IMM);
    if (count > 0) {
      System.out.printf("\timm_count: %d\n", count);
      for (int i=0; i<count; i++) {
        int index = ins.opIndex(X86_OP_IMM, i + 1);
        System.out.printf("\t\timms[%d]: 0x%x\n", i+1, (operands.op[index].value.imm));
      }
    }

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        X86.Operand i = (X86.Operand) operands.op[c];
        String imm = hex(i.value.imm);
        if (i.type == X86_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == X86_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == X86_OP_FP)
          System.out.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
        if (i.type == X86_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String segment = ins.regName(i.value.mem.segment);
          String base = ins.regName(i.value.mem.base);
          String index = ins.regName(i.value.mem.index);
          if (segment != null)
            System.out.printf("\t\t\toperands[%d].mem.segment: REG = %s\n", c, segment);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (index != null)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
          if (i.value.mem.scale != 1)
            System.out.printf("\t\t\toperands[%d].mem.scale: %d\n", c, i.value.mem.scale);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }

        // AVX broadcast type
        if (i.avx_bcast != X86_AVX_BCAST_INVALID) {
          System.out.printf("\t\toperands[%d].avx_bcast: %d\n", c, i.avx_bcast);
        }

        // AVX zero opmask {z}
        if (i.avx_zero_opmask) {
          System.out.printf("\t\toperands[%d].avx_zero_opmask: TRUE\n", c);
        }

        System.out.printf("\t\toperands[%d].size: %d\n", c, i.size);
      }
    }
  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16, hexString2Byte(X86_CODE16), "X86 16bit (Intel syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32, Capstone.CS_OPT_SYNTAX_ATT, hexString2Byte(X86_CODE32), "X86 32 (AT&T syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32, hexString2Byte(X86_CODE32), "X86 32 (Intel syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64, hexString2Byte(X86_CODE64), "X86 64 (Intel syntax)"),
    };

    for (int i=0; i<all_tests.length; i++) {
      Test.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + Test.stringToHex(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      if (test.syntax != 0) {
        cs.setSyntax(test.syntax);
      }
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
