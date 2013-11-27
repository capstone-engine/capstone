// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

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

public class Capstone {

  public int arch;
  public int mode;

  public static abstract class OpInfo {
  }

  public static class PrivateOpInfo extends Union {
    public X86.UnionOpInfo x86;
    public Arm64.UnionOpInfo arm64;
    public Arm.UnionOpInfo arm;
    public Mips.UnionOpInfo mips;
  }

  public static abstract class UnionOpInfo extends Structure implements Structure.ByReference {
    public UnionOpInfo(Pointer p) {
      super(p);
    }
  }

  public static class _cs_insn extends Structure implements Structure.ByReference {
    public int id;
    public long address;
    public short size;
    public byte[] mnemonic = new byte[32];
    public byte[] operands = new byte[96];
    public int[] regs_read = new int[32];
    public int[] regs_write = new int[32];
    public int[] groups = new int[8];

    public _cs_insn(Pointer p) { super(p); read(); }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("id", "address", "size", "mnemonic", "operands", "regs_read", "regs_write", "groups");
    }
  }

  public static class cs_insn {
    public OpInfo op_info;
    public Pointer ptr_origin;
    public long csh;
    public CS cs;

    public int id;
    public long address;
    public short size;
    public String mnemonic;
    public String operands;
    public int[] regs_read;
    public int[] regs_write;
    public int[] groups;

    public cs_insn (_cs_insn struct, Pointer _ptr_origin, long _csh, CS _cs, OpInfo _op_info) {
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
    }

    public int op_count(int type) {
      return cs.cs_op_count(csh, ptr_origin, type);
    }

    public int op_index(int type, int index) {
      return cs.cs_op_index(csh, ptr_origin, type, index);
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
    return new cs_insn(insn, pointer, csh, cs, op_info);
  }

  private cs_insn[] fromArrayPointer(Pointer pointer, int numberResults)
  {
    cs_insn[] arr = new cs_insn[numberResults];
    int offset = 0;

    for (int i = 0; i < numberResults; i++) {
      arr[i] = fromPointer(pointer.share(offset));
      offset += 1728; // TODO: fix this constant, can have JNA calculated but will be 5x slower
    }

    return arr;
  }

  private interface CS extends Library {
    public int cs_open(int arch, int mode, LongByReference handle);
    public long cs_disasm_dyn(long handle, byte[] code, long code_len,
        long addr, long count, PointerByReference insn);
    public void cs_free(Pointer p);
    public int cs_close(long handle);
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


  private long csh;
  private PointerByReference insnRef;
  private CS cs;

  public Capstone(int arch, int mode)
  {
    this.arch = arch;
    this.mode = mode;
    cs = (CS)Native.loadLibrary("capstone", CS.class);
    LongByReference handleref = new LongByReference();
    if (cs.cs_open(arch, mode, handleref) != CS_ERR_OK) {
      throw new RuntimeException("ERROR: Wrong arch or mode");
    }
    csh = handleref.getValue();
  }

  public String reg_name(int reg) {
    return cs.cs_reg_name(csh, reg);
  }

  protected void finalize() {
    cs.cs_close(csh);
  }

  public cs_insn[] disasm(byte[] code, long address) {
    return disasm(code, address, 0);
  }

  public cs_insn[] disasm(byte[] code, long address, long count) {
    insnRef = new PointerByReference();

    long c = cs.cs_disasm_dyn(csh, code, code.length, address, count, insnRef);

    Pointer p = insnRef.getValue();
    cs_insn[] all_insn = fromArrayPointer(p, (int)c);
    return all_insn;
  }
}

