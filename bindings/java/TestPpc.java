// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import capstone.Capstone;
import capstone.Ppc;

import static capstone.Capstone.CS_AC_READ;
import static capstone.Capstone.CS_AC_READ_WRITE;
import static capstone.Capstone.CS_AC_WRITE;
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

  private static String get_pred_name(int pred)
  {
    switch(pred) {
      default:
        return ("invalid");
      case PPC_PRED_LT:
      case PPC_PRED_LT_MINUS:
      case PPC_PRED_LT_PLUS:
      case PPC_PRED_LT_RESERVED:
        return ("lt");
      case PPC_PRED_LE:
      case PPC_PRED_LE_MINUS:
      case PPC_PRED_LE_PLUS:
      case PPC_PRED_LE_RESERVED:
        return ("le");
      case PPC_PRED_EQ:
      case PPC_PRED_EQ_MINUS:
      case PPC_PRED_EQ_PLUS:
      case PPC_PRED_EQ_RESERVED:
        return ("eq");
      case PPC_PRED_GE:
      case PPC_PRED_GE_MINUS:
      case PPC_PRED_GE_PLUS:
      case PPC_PRED_GE_RESERVED:
        return ("ge");
      case PPC_PRED_GT:
      case PPC_PRED_GT_MINUS:
      case PPC_PRED_GT_PLUS:
      case PPC_PRED_GT_RESERVED:
        return ("gt");
      case PPC_PRED_NE:
      case PPC_PRED_NE_MINUS:
      case PPC_PRED_NE_PLUS:
      case PPC_PRED_NE_RESERVED:
        return ("ne");
      case PPC_PRED_UN: // PPC_PRED_SO
      case PPC_PRED_UN_MINUS:
      case PPC_PRED_UN_PLUS:
      case PPC_PRED_UN_RESERVED:
        return ("so/un");
      case PPC_PRED_NU: // PPC_PRED_NS
      case PPC_PRED_NU_MINUS:
      case PPC_PRED_NU_PLUS:
      case PPC_PRED_NU_RESERVED:
        return ("ns/nu");
      case PPC_PRED_NZ:
      case PPC_PRED_NZ_MINUS:
      case PPC_PRED_NZ_PLUS:
      case PPC_PRED_NZ_RESERVED:
        return ("nz");
      case PPC_PRED_Z:
      case PPC_PRED_Z_MINUS:
      case PPC_PRED_Z_PLUS:
      case PPC_PRED_Z_RESERVED:
        return ("z");
      case PPC_PRED_BIT_SET:
        return "bit-set";
      case PPC_PRED_BIT_UNSET:
        return "bit-unset";
    }
  }

  private static String get_pred_hint(int at) {
    switch (at) {
    default:
      return "invalid";
    case PPC_BR_NOT_GIVEN:
      return "not-given";
    case PPC_BR_TAKEN:
      return "likely-taken";
    case PPC_BR_NOT_TAKEN:
      return "likely-not-taken";
    case PPC_BR_RESERVED:
      return "reserved";
    }
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    Ppc.OpInfo operands = (Ppc.OpInfo) ins.operands;

    if (operands.operands.length != 0) {
      System.out.printf("\top_count: %d\n", operands.operands.length);
      for (int c=0; c<operands.operands.length; c++) {
        Ppc.Operand i = (Ppc.Operand) operands.operands[c];
        if (i.type == PPC_OP_REG)
            System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == PPC_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == PPC_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          if (i.value.mem.base != PPC_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, ins.regName(i.value.mem.base));
          if (i.value.mem.offset != PPC_REG_INVALID)
            System.out.printf("\t\t\toperands[%d].mem.offset: REG = %s\n", c, ins.regName(i.value.mem.offset));
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
        }
        switch (i.access) {
          case CS_AC_READ:
            System.out.printf("\t\toperands[%d].access: READ\n", c);
            break;
          case CS_AC_WRITE:
            System.out.printf("\t\toperands[%d].access: WRITE\n", c);
            break;
          case CS_AC_READ_WRITE:
            System.out.printf("\t\toperands[%d].access: READ | WRITE\n", c);
            break;
        }
      }
    }

    if (operands.bc.pred_cr != PPC_PRED_INVALID ||
		    operands.bc.pred_ctr != PPC_PRED_INVALID) {
	    System.out.printf("\tBranch:\n");
	    System.out.printf("\t\tbi: %d\n", operands.bc.bi);
	    System.out.printf("\t\tbo: %d\n", operands.bc.bo);
	    if (operands.bc.bh != PPC_BH_INVALID)
		    System.out.printf("\t\tbh: %d\n", operands.bc.bh);
	    if (operands.bc.pred_cr != PPC_PRED_INVALID) {
		    System.out.printf("\t\tcrX: %s\n", ins.regName(operands.bc.crX));
		    System.out.printf("\t\tpred CR-bit: %s\n", get_pred_name(operands.bc.pred_cr));
	    }
	    if (operands.bc.pred_ctr != PPC_PRED_INVALID)
		    System.out.printf("\t\tpred CTR: %s\n", get_pred_name(operands.bc.pred_ctr));
	    if (operands.bc.hint != PPC_BR_NOT_GIVEN)
		    System.out.printf("\t\thint: %s\n", get_pred_hint(operands.bc.hint));
    }

    if (operands.updateCr0)
	    System.out.printf("\tUpdate-CR0: True\n");

    // Print out all registers accessed by this instruction (either implicit or explicit)
    if (ins.regsRead.length > 0) {
	    System.out.printf("\tImplicit registers read:");
	    for(short r : ins.regsRead) {
		    System.out.printf(" %s", ins.regName(r));
	    }
	    System.out.printf("\n");
    }

    if (ins.regsWrite.length > 0) {
	    System.out.printf("\tImplicit registers modified:");
	    for(short r : ins.regsWrite) {
		    System.out.printf(" %s", ins.regName(r));
	    }
	    System.out.printf("\n");
    }

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
