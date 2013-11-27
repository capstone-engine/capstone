/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

using System;
using System.Runtime.InteropServices;

public struct cs_insn {
	public UInt32 id;
	public UInt64 address;
	public UInt16 size;
	public string mnemonic;
	public string operands;
	public int[] regs_read;
	public int[] regs_write;
	public int[] groups;
};

public class Capstone {
	[StructLayout(LayoutKind.Sequential)] struct _cs_insn {
		public UInt32 id;
		public UInt64 address;
		public UInt16 size;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
			public char[] mnemonic;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
			public char[] operands;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
			public int[] regs_read;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
			public int[] regs_write;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public int[] groups;
	};

	public const int	CS_ARCH_ARM = 0;
	public const int	CS_ARCH_ARM64 = 1;
	public const int	CS_ARCH_MIPS = 2;
	public const int	CS_ARCH_X86 = 3;

	public const int	CS_MODE_LITTLE_ENDIAN = 0;      // default mode
	public const int	CS_MODE_SYNTAX_INTEL = 0;       // default X86 asm syntax (applicable for CS_ARCH_INTEL only)
	public const int	CS_MODE_ARM = 0;
	public const int	CS_MODE_16 = 1 << 1;
	public const int	CS_MODE_32 = 1 << 2;
	public const int	CS_MODE_64 = 1 << 3;
	public const int	CS_MODE_THUMB = 1 << 4;
	public const int	CS_MODE_SYNTAX_ATT = 1 << 30;   // X86 ATT asm syntax (applicable for CS_ARCH_INTEL only)
	public const int	CS_MODE_BIG_ENDIAN = 1 << 31;

	private UInt64 handle;

	[DllImport("capstone.so",CallingConvention=CallingConvention.Cdecl)]
		private static extern bool cs_open(int arch, int mode, ref UInt64 handle);
	[DllImport("capstone.so",CallingConvention=CallingConvention.Cdecl)]
		private static extern bool cs_close(UInt64 handle);
	[DllImport("capstone.so",CallingConvention=CallingConvention.Cdecl)]
		private static extern UInt64 cs_disasm_dyn(UInt64 handle, byte[] code,
				UInt64 code_len, UInt64 offset, UInt64 count, ref IntPtr insn);
	[DllImport("capstone.so",CallingConvention=CallingConvention.Cdecl)]
		private static extern bool cs_free(IntPtr insn);

	public Capstone(int arch, int mode) {
		cs_open(arch, mode, ref handle);
	}

	~Capstone() {
		cs_close(handle);
	}

	public cs_insn[] disasm(byte[] code, UInt64 addr, UInt64 count) {
		IntPtr ptr = IntPtr.Zero;

		UInt64 c = cs_disasm_dyn(handle, code, (UInt64)code.Length, addr, count, ref ptr);
		if (c > 0) {
			UInt64 j;
			//UInt64 size = (UInt64)Marshal.SizeOf(typeof(_cs_insn));
			UInt64 size = 1728;
			cs_insn[] insns = new cs_insn[c];

			for (j = 0; j < c; j++) {
				IntPtr data = new IntPtr(ptr.ToInt64() + (Int64)(size * j));
				_cs_insn _insn = (_cs_insn)Marshal.PtrToStructure(data, typeof(_cs_insn));
				insns[j].id = _insn.id;
				insns[j].address = _insn.address;
				insns[j].size = _insn.size;
				insns[j].mnemonic = new string(_insn.mnemonic);
				insns[j].operands = new string(_insn.operands);

				//insns[j].regs_read = new int[insns[j].regs_read.Length];
				//Array.Copy(_insn.regs_read, 0, insns[j].regs_read, 0, insns[j].regs_read.Length);

				//insns[j].regs_write = new int[insns[j].regs_write.Length];
				//Array.Copy(_insn.regs_write, 0, insns[j].regs_write, 0, insns[j].regs_write.Length);

				//insns[j].groups = new int[insns[j].groups.Length];
				//Array.Copy(_insn.groups, 0, insns[j].groups, 0, insns[j].groups.Length);
			}

			cs_free(ptr);

			return insns;
		} else
			return new cs_insn[0];
	}
}
