[CCode (cprefix="CS_")]
namespace Capstone {
	[CCode (cname="cs_insn", cheader_filename="capstone.h")]
	//[CCode (cname="cs_insn", cheader_filename="capstone.h", copy_function="", destroy_function="")]
	public struct Insn {
		uint32 id;
		uint64 addr;
		uint16 size;
		string mnemonic;
		string op_str;
		int[] regs_read;
		int[] regs_write;
		int[] groups;
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_ARCH_")]
	public enum ARCH {
		ARM = 0,
		ARM64 = 1,
		MIPS = 2,
		X86 = 3
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_MODE_")]
	public enum MODE {
		LITTLE_ENDIAN = 0,
		SYNTAX_INTEL = 0,
		ARM = 0,
		[CCode (cname="CS_MODE_16")]
		B16 = 1<<1,
		[CCode (cname="CS_MODE_32")]
		B32 = 1<<2,
		[CCode (cname="CS_MODE_64")]
		B64 = 1<<3,
		THUMB = 1<<4,
		SYNTAX_ATT = 1<<30,
		BIG_ENDIAN = 1<<31
	}
	[CCode (cname="cs_open")]
	public static int open (ARCH arch, MODE mode, out uint64 handle);
	[CCode (cname="cs_close")]
	public static int close (uint64 handle);

	[CCode (cname="cs_disasm_dyn")]
	public static int disasm_dyn (uint64 handle, void* code, int len, uint64 addr, int count, out Insn* insn );
}
