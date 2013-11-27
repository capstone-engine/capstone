/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

using System;
using System.Runtime.InteropServices;

public class Program {
	struct platform {
		public int arch;
		public int mode;
		public byte[] code;
		public string comment;

		public platform(int a, int m, byte[] c, String s)
		{
			arch = a;
			mode = m;
			code = c;
			comment = s;
		}
	}

	public static void Main() {
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

		for (int j = 0; j < platforms.Length; j++) {
			System.Console.WriteLine("************");
			System.Console.WriteLine("Platform: {0}", platforms[j].comment);
			System.Console.WriteLine();

			Capstone cs = new Capstone(platforms[j].arch, platforms[j].mode);
			cs_insn[] insns = cs.disasm(platforms[j].code, 0x1000, 0);
			for(int i = 0; i < insns.Length; i++) {
				System.Console.WriteLine("0x{0:X}\t{1}\t{2}", insns[i].address, insns[i].mnemonic, insns[i].operands);
			}
		}
	}
}
