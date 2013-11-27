// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import com.sun.jna.Native;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;

import capstone.Capstone;
import capstone.X86;

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

  public static void print_ins_detail(Capstone.cs_insn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.operands);

    X86.OpInfo op_info = (X86.OpInfo) ins.op_info;

    System.out.printf("\tPrefix: %s\n", array2hex(op_info.prefix));

    if (op_info.segment != X86.X86_REG_INVALID)
      System.out.println("\tSegment override: " + cs.reg_name(op_info.segment));


    System.out.printf("\tOpcode: %s\n", array2hex(op_info.opcode));

    // print operand's size, address size, displacement size & immediate size
    System.out.printf("\top_size: %d, addr_size: %d, disp_size: %d, imm_size: %d\n"
        , op_info.op_size, op_info.addr_size, op_info.disp_size, op_info.imm_size);

    // print modRM byte
    System.out.printf("\tmodrm: 0x%x\n", op_info.modrm);

    // print displacement value
    System.out.printf("\tdisp: 0x%x\n", op_info.disp);

    // SIB is not available in 16-bit mode
    if ( (cs.mode & Capstone.CS_MODE_16) == 0)
      // print SIB byte
      System.out.printf("\tsib: 0x%x\n", op_info.sib);

    int count = ins.op_count(X86.X86_OP_IMM);
    if (count > 0) {
      System.out.printf("\timm_count: %d\n", count);
      for (int i=0; i<count; i++) {
        int index = ins.op_index(X86.X86_OP_IMM, i + 1);
        System.out.printf("\t\timms[%d]: 0x%x\n", i+1, (op_info.op[index].value.imm));
      }
    }

    if (op_info.op != null) {
      System.out.printf("\top_count: %d\n", op_info.op.length);
      for (int c=0; c<op_info.op.length; c++) {
        X86.Operand i = (X86.Operand) op_info.op[c];
        String imm = hex(i.value.imm);
        if (i.type == X86.X86_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, cs.reg_name(i.value.reg));
        if (i.type == X86.X86_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == X86.X86_OP_FP)
          System.out.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
        if (i.type == X86.X86_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n",c);
          String base = cs.reg_name(i.value.mem.base);
          String index = cs.reg_name(i.value.mem.index);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (index != null)
            System.out.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
          if (i.value.mem.scale != 1)
            System.out.printf("\t\t\toperands[%d].mem.scale: %d\n", c, i.value.mem.scale);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
      }
    }
  }

  public static void main(String argv[]) {

    final Test.platform[] all_tests = {
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16, hexString2Byte(X86_CODE16), "X86 16bit (Intel syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32 + Capstone.CS_MODE_SYNTAX_ATT, hexString2Byte(X86_CODE32), "X86 32bit (ATT syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32, hexString2Byte(X86_CODE32), "X86 32 (Intel syntax)"),
      new Test.platform(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64, hexString2Byte(X86_CODE64), "X86 64 (Intel syntax)"),
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
