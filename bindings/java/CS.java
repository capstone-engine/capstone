// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Structure;
import com.sun.jna.Union;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.util.List;
import java.util.Arrays;
import java.lang.RuntimeException;

class Capstone {

  public int arch;
  public int mode;

  public static class OpInfo {
	  public int cc;
    public boolean update_flags;
    public boolean writeback;
  }

	public class cs_insn {
		/*
		== total size: 1728
			@id: 0
			@address: 8
			@size: 16
			@mnemonic: 18
			@operands: 50
			@regs_read: 148
			@regs_write: 276
			@groups: 404
			@arch: 440
		*/
		public int id;
		public long address;
		public short size;
		public String mnemonic;
		public String operands;
		public int[] regs_read;
		public int[] regs_write;
		public int[] groups;

		public OpInfo op_info;

		Pointer ptr_cs_ins;
		long handleval;

    public int op_count(int type) {
      return cs.cs_op_count(handleval, ptr_cs_ins, type);
    }

    public int op_index(int type, int index) {
      return cs.cs_op_index(handleval, ptr_cs_ins, type, index);
    }

	}

	private cs_insn fromPointer(Pointer pointer)
	{
		cs_insn insn = new cs_insn();

		insn.id = pointer.getInt(0);

		insn.address = pointer.getLong(8);

		insn.size = pointer.getShort(16);

		insn.mnemonic = pointer.getString(18);

		insn.operands = pointer.getString(50);

		insn.regs_read = pointer.getIntArray(148, 32);

		insn.regs_write = pointer.getIntArray(276, 32);

		insn.groups = pointer.getIntArray(404, 8);

		switch (this.arch) {
      case CS_ARCH_ARM:
        insn.op_info = new Arm.OpInfo(pointer.share(440));
        break;
      case CS_ARCH_ARM64:
        insn.op_info = new Arm64.OpInfo(pointer.share(440));
        break;
      case CS_ARCH_MIPS:
        insn.op_info = new Mips.OpInfo(pointer.share(440));
        break;
      case CS_ARCH_X86:
        insn.op_info = new X86.OpInfo(pointer.share(440));
        break;
      default:
        insn.op_info = null;
    }

    insn.ptr_cs_ins = pointer;
    insn.handleval = handle.getValue();

		return insn;
	}

	private cs_insn[] fromArrayPointer(Pointer pointer, int numberResults)
	{
		cs_insn[] arr = new cs_insn[numberResults];
		int offset = 0;

		for (int i = 0; i < numberResults; i++) {
			arr[i] = fromPointer(pointer.share(offset));
			offset += 1728;	// sizeof(cs_insn);
		}

		return arr;
	}

	private interface CS extends Library {
		public int cs_open(int arch, int mode, LongByReference handle);
		public long cs_disasm_dyn(long handle, byte[] code, long code_len,
				long addr, long count, PointerByReference insn);
		public void cs_free(Pointer p);
		public boolean cs_close(long handle);
		public String cs_reg_name(long csh, int id);
		public int cs_op_count(long csh, Pointer insn, int type);
		public int cs_op_index(long csh, Pointer insn, int type, int index);
	}

	public static final int CS_ARCH_ARM = 0;
	public static final int CS_ARCH_ARM64 = 1;
	public static final int CS_ARCH_MIPS = 2;
	public static final int CS_ARCH_X86 = 3;

	public static final int CS_MODE_LITTLE_ENDIAN = 0;  // default mode
	public static final int CS_MODE_SYNTAX_INTEL = 0;	  // default X86 asm syntax (applicable for CS_ARCH_INTEL only)
	public static final int CS_MODE_ARM = 0;	          // 32-bit ARM
	public static final int CS_MODE_16 = 1 << 1;
	public static final int CS_MODE_32 = 1 << 2;
	public static final int CS_MODE_64 = 1 << 3;
	public static final int CS_MODE_THUMB = 1 << 4;	      // ARM's Thumb mode, including Thumb-2
	public static final int CS_MODE_SYNTAX_ATT = 1 << 30;	// X86 ATT asm syntax (applicable for CS_ARCH_INTEL only)
	public static final int CS_MODE_BIG_ENDIAN = 1 << 31;

// capstone error
  public static final int CS_ERR_OK = 0;
  public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
  public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
  public static final int CS_ERR_HANDLE = 3;	// Invalid handle
  public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
  public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode


	private LongByReference handle;
	private PointerByReference insnRef;
	private CS cs;

	Capstone(int arch, int mode)
	{
	  this.arch = arch;
	  this.mode = mode;
		cs = (CS)Native.loadLibrary("capstone", CS.class);
		handle = new LongByReference();
		if (cs.cs_open(arch, mode, handle) != CS_ERR_OK) {
		  throw new RuntimeException("ERROR: Wrong arch or mode");
    }
	}

  public String reg_name(int reg) {
    return cs.cs_reg_name(handle.getValue(), reg);
  }

	protected void finalize()
	{
		cs.cs_close(handle.getValue());
	}

	cs_insn[] disasm(byte[] code, long address)
	{
		return disasm(code, address, 0);
	}

	cs_insn[] disasm(byte[] code, long address, long count)
	{
		insnRef = new PointerByReference();

		long c = cs.cs_disasm_dyn(handle.getValue(), code, code.length, address, count, insnRef);

		Pointer p = insnRef.getValue();
		cs_insn[] all_insn = fromArrayPointer(p, (int)c);
		return all_insn;
	}
}

