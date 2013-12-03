// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.Structure;
import com.sun.jna.Union;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.IntByReference;

import java.util.List;
import java.util.Arrays;
import java.lang.RuntimeException;
import java.lang.Math;

public class Capstone {

  public int arch;
  public int mode;

  protected static abstract class OpInfo {}
  protected static abstract class UnionOpInfo extends Structure {}

  protected static int max(int a, int b, int c, int d) {
    if (a<b) a = b;
    if (c<d) c = d;
    if (a<c) a = c;
    return a;
  }

  protected static class _cs_insn extends Structure {
    public int id;
    public long address;
    public short size;
    public byte[] mnemonic = new byte[32];
    public byte[] operands = new byte[96];
    public int[] regs_read = new int[32];
    public int regs_read_count;
    public int[] regs_write = new int[32];
    public int regs_write_count;
    public int[] groups = new int[8];
    public int groups_count;

    public _cs_insn(Pointer p) {
      mnemonic = new byte[32];
      operands = new byte[96];
      regs_read = new int[32];
      regs_write = new int[32];
      groups = new int[8];
      useMemory(p);
      read();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("id", "address", "size", "mnemonic", "operands",
			  "regs_read", "regs_read_count",
			  "regs_write", "regs_write_count",
			  "groups", "groups_count");
    }
  }

  public static class cs_insn {
    public OpInfo op_info;
    public Pointer ptr_origin;
    public NativeLong csh;

    public int id;
    public long address;
    public short size;
    public String mnemonic;
    public String operands;
    public int[] regs_read;
    public int[] regs_write;
    public int[] groups;

    private CS cs;
    private static int _size = -1;

    public cs_insn (_cs_insn struct, Pointer _ptr_origin, NativeLong _csh, CS _cs, OpInfo _op_info) {
      id = struct.id;
      address = struct.address;
      size = struct.size;
      mnemonic = new String(struct.mnemonic).replace("\u0000","");
      operands = new String(struct.operands).replace("\u0000","");
      regs_read = struct.regs_read;
      regs_write = struct.regs_write;
      groups = struct.groups;

      ptr_origin = _ptr_origin;
      op_info = _op_info;
      csh = _csh;
      cs = _cs;

      // cache the size so we do not need to recompute the offset everytime
      if (_size == -1)
        _size = struct.size() + Arm.UnionOpInfo.getSize();
        // Arm is the max, so we optimized it here, a more generic way is as follows:
        // = max( Arm.UnionOpInfo.getSize(), Arm64.UnionOpInfo.getSize(), Mips.UnionOpInfo.getSize(), X86.UnionOpInfo.getSize() );
    }

    protected int size() {
      return _size;
    }

    public int op_count(int type) {
      return cs.cs_op_count(csh, ptr_origin, type);
    }

    public int op_index(int type, int index) {
      return cs.cs_op_index(csh, ptr_origin, type, index);
    }

    public boolean reg_read(int reg_id) {
      return cs.cs_reg_read(csh, ptr_origin, reg_id) != 0;
    }

    public boolean reg_write(int reg_id) {
      return cs.cs_reg_write(csh, ptr_origin, reg_id) != 0;
    }

    public int errno() {
      return cs.cs_errno(csh);
    }

    public String reg_name(int reg_id) {
      return cs.cs_reg_name(csh, reg_id);
    }

    public String insn_name() {
      return cs.cs_insn_name(csh, id);
    }

    public boolean group(int gid) {
      return cs.cs_insn_group(csh, ptr_origin, gid) != 0;
    }

  }

  private cs_insn fromPointer(Pointer pointer)
  {
    _cs_insn insn = new _cs_insn(pointer);
    OpInfo op_info = null;
    UnionOpInfo _op_info = null;

    switch (this.arch) {
      case CS_ARCH_ARM:
        _op_info = new Arm.UnionOpInfo(pointer.share(insn.size()));
        op_info = new Arm.OpInfo((Arm.UnionOpInfo) _op_info);
        break;
      case CS_ARCH_ARM64:
        _op_info = new Arm64.UnionOpInfo(pointer.share(insn.size()));
        op_info = new Arm64.OpInfo((Arm64.UnionOpInfo) _op_info);
        break;
      case CS_ARCH_MIPS:
        _op_info = new Mips.UnionOpInfo(pointer.share(insn.size()));
        op_info = new Mips.OpInfo((Mips.UnionOpInfo) _op_info);
        break;
      case CS_ARCH_X86:
        _op_info = new X86.UnionOpInfo(pointer.share(insn.size()));
        op_info = new X86.OpInfo((X86.UnionOpInfo) _op_info);
        break;
      default:
    }
    return new cs_insn(insn, pointer, ns.csh, cs, op_info);
  }

  private cs_insn[] fromArrayPointer(Pointer pointer, int numberResults)
  {
    cs_insn[] arr = new cs_insn[numberResults];
    int offset = 0;

    for (int i = 0; i < numberResults; i++) {
      arr[i] = fromPointer(pointer.share(offset));
      offset += arr[i].size();
    }

    return arr;
  }

  private interface CS extends Library {
    public int cs_open(int arch, int mode, NativeLongByReference handle);
    public NativeLong cs_disasm_dyn(NativeLong handle, byte[] code, NativeLong code_len,
        long addr, NativeLong count, PointerByReference insn);
    public void cs_free(Pointer p);
    public int cs_close(NativeLong handle);
    public String cs_reg_name(NativeLong csh, int id);
    public int cs_op_count(NativeLong csh, Pointer insn, int type);
    public int cs_op_index(NativeLong csh, Pointer insn, int type, int index);

    public String cs_insn_name(NativeLong csh, int id);
    public byte cs_insn_group(NativeLong csh, Pointer insn, int id);
    public byte cs_reg_read(NativeLong csh, Pointer insn, int id);
    public byte cs_reg_write(NativeLong csh, Pointer insn, int id);
    public void cs_version(IntByReference major, IntByReference minor);
    public int cs_errno(NativeLong csh);
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
  public static final int CS_MODE_MICRO = 1 << 4;	      // MicroMips mode (Mips arch)
  public static final int CS_MODE_N64 = 1 << 5;	      // Nintendo-64 mode (Mips arch)
  public static final int CS_MODE_SYNTAX_ATT = 1 << 30;	// X86 ATT asm syntax (applicable for CS_ARCH_INTEL only)
  public static final int CS_MODE_BIG_ENDIAN = 1 << 31;

  // capstone error
  public static final int CS_ERR_OK = 0;
  public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
  public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
  public static final int CS_ERR_HANDLE = 3;	// Invalid handle
  public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
  public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode

  protected class NativeStruct {
      private NativeLong csh;
      private NativeLongByReference handleref;
      private PointerByReference insnRef;
  }

  protected NativeStruct ns; // for memory retention
  private CS cs;

  public Capstone(int arch, int mode)
  {
    this.arch = arch;
    this.mode = mode;
    ns = new NativeStruct();
    cs = (CS)Native.loadLibrary("capstone", CS.class);
    ns.handleref = new NativeLongByReference();
    if (cs.cs_open(arch, mode, ns.handleref) != CS_ERR_OK) {
      throw new RuntimeException("ERROR: Wrong arch or mode");
    }
    ns.csh = ns.handleref.getValue();
  }

  public String reg_name(int reg) {
    return cs.cs_reg_name(ns.csh, reg);
  }

  protected void finalize() {
     cs.cs_close(ns.csh);
  }

  public cs_insn[] disasm(byte[] code, long address) {
    return disasm(code, address, 0);
  }

  public cs_insn[] disasm(byte[] code, long address, long count) {
    ns.insnRef = new PointerByReference();

    NativeLong c = cs.cs_disasm_dyn(ns.csh, code, new NativeLong(code.length), address, new NativeLong(count), ns.insnRef);

    Pointer p = ns.insnRef.getValue();
    cs_insn[] all_insn = fromArrayPointer(p, c.intValue());
    return all_insn;
  }
}

