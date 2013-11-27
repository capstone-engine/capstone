/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

import com.sun.jna.Native;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;

public class Test {
  public static class platform {
    public int arch;
    public int mode;
    public byte[] code;
    public String comment;

    public platform(int a, int m, byte[] c, String s) {
      arch = a;
      mode = m;
      code = c;
      comment = s;
    }
  };

  static String stringToHex(byte[] code) {
    StringBuilder buf = new StringBuilder(200);
    for (byte ch: code) {
      if (buf.length() > 0)
        buf.append(' ');
      buf.append(String.format("0x%02x", ch));
    }
    return buf.toString();
  }

  static public void main(String argv[]) {
    platform[] platforms = {
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_16,
          new byte[] { (byte)0x8d, (byte)0x4c, (byte)0x32, (byte)0x08, (byte)0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, (byte)0x34, (byte)0x12, 0x00, 0x00 },
          "X86 16bit (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_32 + Capstone.CS_MODE_SYNTAX_ATT,
          new byte[] { (byte)0x8d, 0x4c, 0x32, 0x08, 0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, 0x34, 0x12, 0x00, 0x00 },
          "X86 32bit (ATT syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_32,
          new byte[] { (byte)0x8d, 0x4c, 0x32, 0x08, 0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, 0x34, 0x12, 0x00, 0x00 },
          "X86 32bit (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_64,
          new byte[] { 0x55, 0x48, (byte)0x8b, 0x05, (byte)0xb8, 0x13, 0x00, 0x00 },
          "X86 64 (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_ARM,
          new byte[] { (byte)0xED, (byte)0xFF, (byte)0xFF, (byte)0xEB, 0x04, (byte)0xe0, 0x2d, (byte)0xe5, 0x00, 0x00, 0x00, 0x00, (byte)0xe0, (byte)0x83, 0x22, (byte)0xe5, (byte)0xf1, 0x02, 0x03, 0x0e, 0x00, 0x00, (byte)0xa0, (byte)0xe3, 0x02, 0x30, (byte)0xc1, (byte)0xe7, 0x00, 0x00, 0x53, (byte)0xe3 },
          "ARM"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_THUMB,
          new byte[] { 0x4f, (byte)0xf0, 0x00, 0x01, (byte)0xbd, (byte)0xe8, 0x00, (byte)0x88, (byte)0xd1, (byte)0xe8, 0x00, (byte)0xf0 },
          "THUMB-2"

          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_ARM,
          new byte[] { 0x10, (byte)0xf1, 0x10, (byte)0xe7, 0x11, (byte)0xf2, 0x31, (byte)0xe7, (byte)0xdc, (byte)0xa1, 0x2e, (byte)0xf3, (byte)0xe8, 0x4e, 0x62, (byte)0xf3 },
          "ARM: Cortex-A15 + NEON"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_THUMB,
          new byte[] { 0x70, 0x47, (byte)0xeb, 0x46, (byte)0x83, (byte)0xb0, (byte)0xc9, 0x68 },
          "THUMB"
          ),
      new platform(
          Capstone.CS_ARCH_MIPS,
          Capstone.CS_MODE_32 + Capstone.CS_MODE_BIG_ENDIAN,
          new byte[] { 0x0C, 0x10, 0x00, (byte)0x97, 0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x0c, (byte)0x8f, (byte)0xa2, 0x00, 0x00, 0x34, 0x21, 0x34, 0x56 },
          "MIPS-32 (Big-endian)"
          ),
      new platform(
          Capstone.CS_ARCH_MIPS,
          Capstone.CS_MODE_64+ Capstone.CS_MODE_LITTLE_ENDIAN,
          new byte[] { 0x56, 0x34, 0x21, 0x34, (byte)0xc2, 0x17, 0x01, 0x00 },
          "MIPS-64-EL (Little-endian)"
          ),
      new platform(
          Capstone.CS_ARCH_ARM64,
          Capstone.CS_MODE_ARM,
          new byte [] { 0x21, 0x7c, 0x02, (byte)0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, (byte)0xe1, 0x0b, 0x40, (byte)0xb9 },
          "ARM-64"
          ),
    };

    for (int j = 0; j < platforms.length; j++) {
      System.out.println("************");
      System.out.println(String.format("Platform: %s", platforms[j].comment));
      System.out.println(String.format("Code: %s", stringToHex(platforms[j].code)));

      Capstone cs = new Capstone(platforms[j].arch, platforms[j].mode);

      Capstone.cs_insn[] all_insn = cs.disasm(platforms[j].code, 0x1000);

      for (int i = 0; i < all_insn.length; i++) {
        System.out.println(String.format("0x%x\t%s\t%s", all_insn[i].address,
              all_insn[i].mnemonic, all_insn[i].operands));

        if (all_insn[i].regs_read[0] != 0) {
          System.out.print("\tRegister read: ");
          for(int k = 0; k < all_insn[i].regs_read.length; k++) {
            if (all_insn[i].regs_read[k] == 0)
              break;
            System.out.print(String.format("%d ", all_insn[i].regs_read[k]));
          }
          System.out.println();
        }

        if (all_insn[i].regs_write[0] != 0) {
          System.out.print("\tRegister written: ");
          for(int k = 0; k < all_insn[i].regs_write.length; k++) {
            if (all_insn[i].regs_write[k] == 0)
              break;
            System.out.print(String.format("%d ", all_insn[i].regs_write[k]));
          }
          System.out.println();
        }

        if (all_insn[i].groups[0] != 0) {
          System.out.print("\tThis instruction belongs to group: ");
          for(int k = 0; k < all_insn[i].groups.length; k++) {
            if (all_insn[i].groups[k] == 0)
              break;
            System.out.print(String.format("%d ", all_insn[i].groups[k]));
          }
          System.out.println();
        }
      }
    }
  }
}
