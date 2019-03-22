// Capstone Java binding
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

import java.lang.*;
import capstone.Capstone;
import capstone.M680x;

import static capstone.M680x_const.*;

public class TestM680x {

  static final String sAccess[] = {
    "UNCHANGED", "READ", "WRITE", "READ | WRITE",
  };

  static final String M6800_CODE = "010936647f7410009010A410b6100039";
  static final String M6801_CODE = "04053c3d389310ec10ed1039";
  static final String M6805_CODE = "047f00172228002e0040425a708e979ca015ad00c31000da1234e57ffe";
  static final String M6808_CODE = "31220035224510004b005110525e226265123472848586878a8b8c9495a710af109e607f9e6b7f009ed610009ee67f";
  static final String HD6301_CODE = "6b100071100072101039";
  static final String M6809_CODE = "0610191a551e0123e931063455a681a7897fffa69d1000a791a69f100011ac99100039A607A627A647A667A60FA610A680A681A682A683A684A685A686A6887FA68880A6897FFFA6898000A68BA68C10A68D1000A691A693A694A695A696A6987FA69880A6997FFFA6998000A69BA69C10A69D1000A69F1000";
  static final String M6811_CODE = "0203127f100013990800147f02157f011e7f20008fcf18081830183c1867188c1000188f18ce100018ff10001aa37f1aac1aee7f1aef7fcdac7f";
  static final String CPU12_CODE = "000401000c00800e008000111e100080003b4a1000044b01044f7f80008f1000b752b7b1a667a6fea6f71802e23039e21000180c30391000181118121000181900181e00183e183f00";
  static final String HD6309_CODE = "0110106210107b101000cd499602d21030231038103b1053105d1130431011372510113812113923113b34118e100011af1011ab1011f68000";
  static final String HCS08_CODE = "3210009eae9ece7f9ebe10009efe7f3e10009ef37f9610009eff7f82";

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

  static public String stringToHexUc(byte[] code) {
    StringBuilder buf = new StringBuilder(800);
    for (byte ch: code) {
      buf.append(String.format(" 0x%02x", ch));
    }
    return buf.toString();
  }

  static public String stringToHexShortUc(byte[] code) {
    StringBuilder buf = new StringBuilder(800);
    for (byte ch: code) {
      buf.append(String.format("%02x", ch));
    }
    return buf.toString();
  }

  public static Capstone cs;
/*
  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }
*/
  public static void print_ins_detail(Capstone.CsInsn ins) {
    String bytes = stringToHexShortUc(ins.bytes);
    System.out.printf("0x%04x:\t%s\t%s\t%s\n", ins.address, bytes, ins.mnemonic, ins.opStr);

    M680x.OpInfo operands = (M680x.OpInfo) ins.operands;

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c = 0; c < operands.op.length; c++) {
        M680x.Operand i = (M680x.Operand) operands.op[c];
        if (i.type == M680X_OP_REGISTER) {
          String comment = "";
          if ((c == 0 && ((operands.flags & M680X_FIRST_OP_IN_MNEM) != 0)) ||
              (c == 1 && ((operands.flags & M680X_SECOND_OP_IN_MNEM) != 0)))
            comment = " (in mnemonic)";
          System.out.printf("\t\toperands[%d].type: REGISTER = %s%s\n", c, ins.regName(i.value.reg), comment);
        }
        if (i.type == M680X_OP_CONSTANT)
          System.out.printf("\t\toperands[%d].type: CONSTANT = %d\n", c, i.value.const_val);
        if (i.type == M680X_OP_IMMEDIATE)
          System.out.printf("\t\toperands[%d].type: IMMEDIATE = #%d\n", c, i.value.imm);
        if (i.type == M680X_OP_DIRECT)
          System.out.printf("\t\toperands[%d].type: DIRECT = 0x%02x\n", c, i.value.direct_addr);
        if (i.type == M680X_OP_EXTENDED)
          System.out.printf("\t\toperands[%d].type: EXTENDED %s = 0x%04x\n", c,
            i.value.ext.indirect != 0 ? "INDIRECT" : "", i.value.ext.address);
        if (i.type == M680X_OP_RELATIVE)
          System.out.printf("\t\toperands[%d].type: RELATIVE = 0x%04x\n", c, i.value.rel.address );
        if (i.type == M680X_OP_INDEXED) {
          System.out.printf("\t\toperands[%d].type: INDEXED%s\n", c,
            (i.value.idx.flags & M680X_IDX_INDIRECT) != 0 ? " INDIRECT" : "");
          if (i.value.idx.base_reg != M680X_REG_INVALID) {
            String regName = ins.regName(i.value.idx.base_reg);
            if (regName != null)
              System.out.printf("\t\t\tbase register: %s\n", regName);
          }
          if (i.value.idx.offset_reg != M680X_REG_INVALID) {
            String regName = ins.regName(i.value.idx.offset_reg);
            if (regName != null)
              System.out.printf("\t\t\toffset register: %s\n", regName);
          }
          if ((i.value.idx.offset_bits != 0) &&
              (i.value.idx.offset_reg == M680X_REG_INVALID) &&
              (i.value.idx.inc_dec == 0)) {
            System.out.printf("\t\t\toffset: %d\n", i.value.idx.offset);
            if (i.value.idx.base_reg == M680X_REG_PC)
              System.out.printf("\t\t\toffset address: 0x%04x\n", i.value.idx.offset_addr);
            System.out.printf("\t\t\toffset bits: %d\n", i.value.idx.offset_bits);
          }
          if (i.value.idx.inc_dec != 0) {
            String post_pre =
               (i.value.idx.flags & M680X_IDX_POST_INC_DEC) != 0 ?
		"post" : "pre";
            String inc_dec =
               i.value.idx.inc_dec > 0 ? "increment" : "decrement";

            System.out.printf("\t\t\t%s %s: %d\n", post_pre, inc_dec,
			Math.abs(i.value.idx.inc_dec));
          }
        }
        if (i.size != 0)
          System.out.printf("\t\t\tsize: %d\n", i.size);
        if (i.access != Capstone.CS_AC_INVALID)
          System.out.printf("\t\t\taccess: %s\n", sAccess[i.access]);
      }
    }

    if (ins.regsRead.length > 0) {
      System.out.printf("\tRegisters read:");
      for (int c = 0; c < ins.regsRead.length; c++) {
        System.out.printf(" %s", ins.regName(ins.regsRead[c]));
      }
      System.out.printf("\n");
    }

    if (ins.regsWrite.length > 0) {
      System.out.printf("\tRegisters modified:");
      for (int c = 0; c < ins.regsWrite.length; c++) {
        System.out.printf(" %s", ins.regName(ins.regsWrite[c]));
      }
      System.out.printf("\n");
    }

    if (ins.groups.length > 0)
      System.out.printf("\tgroups_count: %d\n", ins.groups.length);
  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6301,
          hexString2Byte(HD6301_CODE), "M680X_HD6301"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6309,
          hexString2Byte(HD6309_CODE), "M680X_HD6309"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6800,
          hexString2Byte(M6800_CODE), "M680X_M6800"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6801,
          hexString2Byte(M6801_CODE), "M680X_M6801"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6805,
          hexString2Byte(M6805_CODE), "M680X_M68HC05"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6808,
          hexString2Byte(M6808_CODE), "M680X_M68HC08"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6809,
          hexString2Byte(M6809_CODE), "M680X_M6809"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_6811,
          hexString2Byte(M6811_CODE), "M680X_M68HC11"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_CPU12,
          hexString2Byte(CPU12_CODE), "M680X_CPU12"),
      new TestBasic.platform(Capstone.CS_ARCH_M680X,
          Capstone.CS_MODE_M680X_HCS08,
          hexString2Byte(HCS08_CODE), "M680X_HCS08"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[20]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + stringToHexUc(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      Capstone.CsInsn[] all_ins = cs.disasm(test.code, 0x1000);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }

      // Close when done
      cs.close();
    }
  }

}
