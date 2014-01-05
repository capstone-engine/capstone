/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

import capstone.Capstone;

public class Test {
  public static class platform {
    public int arch;
    public int mode;
    public int syntax;
    public byte[] code;
    public String comment;

    public platform(int a, int m, int syt, byte[] c, String s) {
      arch = a;
      mode = m;
      code = c;
      comment = s;
      syntax = syt;
    }

    public platform(int a, int m, byte[] c, String s) {
      arch = a;
      mode = m;
      code = c;
      comment = s;
    }
  };

  static public String stringToHex(byte[] code) {
    StringBuilder buf = new StringBuilder(200);
    for (byte ch: code) {
      if (buf.length() > 0)
        buf.append(' ');
      buf.append(String.format("0x%02x", ch));
    }
    return buf.toString();
  }

  public static final byte[] PPC_CODE = new byte[] {(byte)0x80, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x80, (byte)0x3f, (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x43, (byte)0x23, (byte)0x0e, (byte)0xd0, (byte)0x44, (byte)0x00, (byte)0x80, (byte)0x4c, (byte)0x43, (byte)0x22, (byte)0x02, (byte)0x2d, (byte)0x03, (byte)0x00, (byte)0x80, (byte)0x7c, (byte)0x43, (byte)0x20, (byte)0x14, (byte)0x7c, (byte)0x43, (byte)0x20, (byte)0x93, (byte)0x4f, (byte)0x20, (byte)0x00, (byte)0x21, (byte)0x4c, (byte)0xc8, (byte)0x00, (byte)0x21 };
  public static final byte[] X86_CODE = new byte[] { (byte)0x8d, (byte)0x4c, (byte)0x32, (byte)0x08, (byte)0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, (byte)0x34, (byte)0x12, (byte)0x00, (byte)0x00 };

  static public void main(String argv[]) {
    platform[] platforms = {
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_16,
          Capstone.CS_OPT_SYNTAX_INTEL,
          new byte[] { (byte)0x8d, (byte)0x4c, (byte)0x32, (byte)0x08, (byte)0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, (byte)0x34, (byte)0x12, (byte)0x00, (byte)0x00 },
          "X86 16bit (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_32,
          Capstone.CS_OPT_SYNTAX_ATT,
          X86_CODE,
          "X86 32bit (ATT syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_32,
          X86_CODE,
          "X86 32 (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_X86,
          Capstone.CS_MODE_64,
          new byte[] {(byte)0x55, (byte)0x48, (byte)0x8b, (byte)0x05, (byte)0xb8, (byte)0x13, (byte)0x00, (byte)0x00 },
          "X86 64 (Intel syntax)"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_ARM,
          new byte[] { (byte)0xED, (byte)0xFF, (byte)0xFF, (byte)0xEB, (byte)0x04, (byte)0xe0, (byte)0x2d, (byte)0xe5, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xe0, (byte)0x83, (byte)0x22, (byte)0xe5, (byte)0xf1, (byte)0x02, (byte)0x03, (byte)0x0e, (byte)0x00, (byte)0x00, (byte)0xa0, (byte)0xe3, (byte)0x02, (byte)0x30, (byte)0xc1, (byte)0xe7, (byte)0x00, (byte)0x00, (byte)0x53, (byte)0xe3 },
          "ARM"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_THUMB,
          new byte[] {(byte)0x4f, (byte)0xf0, (byte)0x00, (byte)0x01, (byte)0xbd, (byte)0xe8, (byte)0x00, (byte)0x88, (byte)0xd1, (byte)0xe8, (byte)0x00, (byte)0xf0 },
          "THUMB-2"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_ARM,
          new byte[] {(byte)0x10, (byte)0xf1, (byte)0x10, (byte)0xe7, (byte)0x11, (byte)0xf2, (byte)0x31, (byte)0xe7, (byte)0xdc, (byte)0xa1, (byte)0x2e, (byte)0xf3, (byte)0xe8, (byte)0x4e, (byte)0x62, (byte)0xf3 },
          "ARM: Cortex-A15 + NEON"
          ),
      new platform(
          Capstone.CS_ARCH_ARM,
          Capstone.CS_MODE_THUMB,
          new byte[] {(byte)0x70, (byte)0x47, (byte)0xeb, (byte)0x46, (byte)0x83, (byte)0xb0, (byte)0xc9, (byte)0x68 },
          "THUMB"
          ),
      new platform(
          Capstone.CS_ARCH_MIPS,
          Capstone.CS_MODE_32 + Capstone.CS_MODE_BIG_ENDIAN,
          new byte[] {(byte)0x0C, (byte)0x10, (byte)0x00, (byte)0x97, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x24, (byte)0x02, (byte)0x00, (byte)0x0c, (byte)0x8f, (byte)0xa2, (byte)0x00, (byte)0x00, (byte)0x34, (byte)0x21, (byte)0x34, (byte)0x56 },
          "MIPS-32 (Big-endian)"
          ),
      new platform(
          Capstone.CS_ARCH_MIPS,
          Capstone.CS_MODE_64+ Capstone.CS_MODE_LITTLE_ENDIAN,
          new byte[] {(byte)0x56, (byte)0x34, (byte)0x21, (byte)0x34, (byte)0xc2, (byte)0x17, (byte)0x01, (byte)0x00 },
          "MIPS-64-EL (Little-endian)"
          ),
      new platform(
          Capstone.CS_ARCH_ARM64,
          Capstone.CS_MODE_ARM,
          new byte [] { 0x21, 0x7c, 0x02, (byte)0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, (byte)0xe1, 0x0b, 0x40, (byte)0xb9 },
          "ARM-64"
          ),
      new platform (
          Capstone.CS_ARCH_PPC,
          Capstone.CS_MODE_BIG_ENDIAN,
          PPC_CODE,
          "PPC-64"
          ),
      new platform (
          Capstone.CS_ARCH_PPC,
          Capstone.CS_MODE_BIG_ENDIAN,
          Capstone.CS_OPT_SYNTAX_NOREGNAME,
          PPC_CODE,
          "PPC-64, print register with number only"
          ),
    };

    for (int j = 0; j < platforms.length; j++) {
      System.out.println("****************");
      System.out.println(String.format("Platform: %s", platforms[j].comment));
      System.out.println(String.format("Code: %s", stringToHex(platforms[j].code)));
      System.out.println("Disasm:");

      Capstone cs = new Capstone(platforms[j].arch, platforms[j].mode);
      if (platforms[j].syntax != 0)
        cs.setSyntax(platforms[j].syntax);

      Capstone.CsInsn[] all_insn = cs.disasm(platforms[j].code, 0x1000);

      for (int i = 0; i < all_insn.length; i++) {
        System.out.println(String.format("0x%x: \t%s\t%s", all_insn[i].address,
              all_insn[i].mnemonic, all_insn[i].opStr));
      }
      System.out.printf("0x%x:\n\n", all_insn[all_insn.length-1].address + all_insn[all_insn.length-1].size);
    }
  }
}
