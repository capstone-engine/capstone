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

public class Capstone {

  protected static abstract class OpInfo {};
  protected static abstract class UnionOpInfo extends Structure {};

  public static class UnionArch extends Union {
    public static class ByValue extends UnionArch implements Union.ByValue {};

    public Arm.UnionOpInfo arm;
    public Arm64.UnionOpInfo arm64;
    public X86.UnionOpInfo x86;
    public Mips.UnionOpInfo mips;
  }

  protected static class _cs_insn extends Structure {
    public int id;
    public long address;
    public short size;
    public byte[] bytes;
    public byte[] mnemonic;
    public byte[] operands;
    public _cs_detail.ByReference cs_detail;

    public _cs_insn() {
      bytes = new byte[16];
      mnemonic = new byte[32];
      operands = new byte[96];
    }

    public _cs_insn(Pointer p) {
      this();
      useMemory(p);
      read();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("id", "address", "size", "bytes", "mnemonic", "operands", "cs_detail");
    }
  }

  protected static class _cs_detail extends Structure {
    public static class ByReference extends _cs_detail implements Structure.ByReference {};

    public byte[] regs_read = new byte[12];
    public byte regs_read_count;
    public byte[] regs_write = new byte[20];
    public byte regs_write_count;
    public byte[] groups = new byte[8];
    public byte groups_count;

    public UnionArch arch;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("regs_read", "regs_read_count", "regs_write", "regs_write_count", "groups", "groups_count", "arch");
    }
  }

  public static class CsInsn {
    private NativeLong csh;
    private CS cs;
    private _cs_insn raw;
    private int arch;

    public int id;
    public long address;
    public short size;
    public String mnemonic;
    public String opStr;
    public byte[] regsRead;
    public byte[] regsWrite;
    public byte[] groups;
    public OpInfo operands;

    public CsInsn (_cs_insn insn, int _arch, NativeLong _csh, CS _cs) {
      id = insn.id;
      address = insn.address;
      size = insn.size;
      mnemonic = new String(insn.mnemonic).replace("\u0000","");
      opStr = new String(insn.operands).replace("\u0000","");

      arch = _arch;
      raw = insn;
      csh = _csh;
      cs = _cs;

      if (insn.cs_detail != null) {
        regsRead = new byte[insn.cs_detail.regs_read_count];
        for (int i=0; i<regsRead.length; i++)
          regsRead[i] = insn.cs_detail.regs_read[i];
        regsWrite = new byte[insn.cs_detail.regs_write_count];
        for (int i=0; i<regsWrite.length; i++)
          regsWrite[i] = insn.cs_detail.regs_write[i];
        groups = new byte[insn.cs_detail.groups_count];
        for (int i=0; i<groups.length; i++)
          groups[i] = insn.cs_detail.groups[i];

        operands = getOptInfo(insn.cs_detail);
      }
    }

    private OpInfo getOptInfo(_cs_detail detail) {
      OpInfo op_info = null;

      switch (this.arch) {
        case CS_ARCH_ARM:
          detail.arch.setType(Arm.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Arm.OpInfo((Arm.UnionOpInfo) detail.arch.arm);
          break;
        case CS_ARCH_ARM64:
          detail.arch.setType(Arm64.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Arm64.OpInfo((Arm64.UnionOpInfo) detail.arch.arm64);
          break;
        case CS_ARCH_MIPS:
          detail.arch.setType(Mips.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Mips.OpInfo((Mips.UnionOpInfo) detail.arch.mips);
          break;
        case CS_ARCH_X86:
          detail.arch.setType(X86.UnionOpInfo.class);
          detail.arch.read();
          op_info = new X86.OpInfo((X86.UnionOpInfo) detail.arch.x86);
          break;
        default:
      }

      return op_info;
    }

    public int opCount(int type) {
      return cs.cs_op_count(csh, raw.getPointer(), type);
    }

    public int opIndex(int type, int index) {
      return cs.cs_op_index(csh, raw.getPointer(), type, index);
    }

    public boolean regRead(int reg_id) {
      return cs.cs_reg_read(csh, raw.getPointer(), reg_id) != 0;
    }

    public boolean regWrite(int reg_id) {
      return cs.cs_reg_write(csh, raw.getPointer(), reg_id) != 0;
    }

    public int errno() {
      return cs.cs_errno(csh);
    }

    public String regName(int reg_id) {
      return cs.cs_reg_name(csh, reg_id);
    }

    public String insnName() {
      return cs.cs_insn_name(csh, id);
    }

    public boolean group(int gid) {
      return cs.cs_insn_group(csh, raw.getPointer(), gid) != 0;
    }

  }

  private CsInsn[] fromArrayRaw(_cs_insn[] arr_raw) {
    CsInsn[] arr = new CsInsn[arr_raw.length];

    for (int i = 0; i < arr_raw.length; i++) {
      arr[i] = new CsInsn(arr_raw[i], this.arch, ns.csh, cs);
    }

    return arr;
  }

  private interface CS extends Library {
    public int cs_open(int arch, int mode, NativeLongByReference handle);
    public NativeLong cs_disasm_ex(NativeLong handle, byte[] code, NativeLong code_len,
        long addr, NativeLong count, PointerByReference insn);
    public void cs_free(Pointer p);
    public int cs_close(NativeLong handle);
    public int cs_option(NativeLong handle, int option, NativeLong optionValue);

    public String cs_reg_name(NativeLong csh, int id);
    public int cs_op_count(NativeLong csh, Pointer insn, int type);
    public int cs_op_index(NativeLong csh, Pointer insn, int type, int index);

    public String cs_insn_name(NativeLong csh, int id);
    public byte cs_insn_group(NativeLong csh, Pointer insn, int id);
    public byte cs_reg_read(NativeLong csh, Pointer insn, int id);
    public byte cs_reg_write(NativeLong csh, Pointer insn, int id);
    public int cs_errno(NativeLong csh);
    public int cs_version(IntByReference major, IntByReference minor);
  }

  // capstone API version
  public static final int CS_API_MAJOR = 1;
  public static final int CS_API_MINOR = 0;

  public static final int CS_ARCH_ARM = 0;
  public static final int CS_ARCH_ARM64 = 1;
  public static final int CS_ARCH_MIPS = 2;
  public static final int CS_ARCH_X86 = 3;

  public static final int CS_MODE_LITTLE_ENDIAN = 0;  // default mode
  public static final int CS_MODE_ARM = 0;	          // 32-bit ARM
  public static final int CS_MODE_16 = 1 << 1;
  public static final int CS_MODE_32 = 1 << 2;
  public static final int CS_MODE_64 = 1 << 3;
  public static final int CS_MODE_THUMB = 1 << 4;	      // ARM's Thumb mode, including Thumb-2
  public static final int CS_MODE_MICRO = 1 << 4;	      // MicroMips mode (Mips arch)
  public static final int CS_MODE_N64 = 1 << 5;	      // Nintendo-64 mode (Mips arch)
  public static final int CS_MODE_BIG_ENDIAN = 1 << 31;

  // capstone error
  public static final int CS_ERR_OK = 0;
  public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
  public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
  public static final int CS_ERR_HANDLE = 3;	// Invalid handle
  public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
  public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode

  // Capstone option type
  public static final int CS_OPT_SYNTAX = 1;  // Intel X86 asm syntax (CS_ARCH_X86 arch)
  public static final int CS_OPT_DETAIL = 2;  // Break down instruction structure into details
  public static final int CS_OPT_MODE = 3;  // Change engine's mode at run-time

  //Capstone option value
  public static final int CS_OPT_OFF = 0;  // Turn OFF an option (CS_OPT_DETAIL)
  public static final int CS_OPT_SYNTAX_INTEL = 1;  // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX,  CS_ARCH_X86)
  public static final int CS_OPT_SYNTAX_ATT = 2;    // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
  public static final int CS_OPT_ON = 3;  // Turn ON an option - this is default option for CS_OPT_DETAIL

  protected class NativeStruct {
      private NativeLong csh;
      private NativeLongByReference handleRef;
  }

  protected NativeStruct ns; // for memory retention
  private CS cs;
  public int arch;
  public int mode;
  private int syntax;
  private int detail;

  public Capstone(int arch, int mode) {
    this.arch = arch;
    this.mode = mode;
    ns = new NativeStruct();
    cs = (CS)Native.loadLibrary("capstone", CS.class);
    ns.handleRef = new NativeLongByReference();
    if (cs.cs_open(arch, mode, ns.handleRef) != CS_ERR_OK) {
      throw new RuntimeException("ERROR: Wrong arch or mode");
    }
    ns.csh = ns.handleRef.getValue();
  }

  public void setSyntax(int syntax) {
    if (cs.cs_option(ns.csh, CS_OPT_SYNTAX, new NativeLong(syntax)) == CS_ERR_OK) {
      this.syntax = syntax;
    } else {
      throw new RuntimeException("ERROR: Unknown syntax");
    }
  }

  public void setDetail(int opt) {
    if (cs.cs_option(ns.csh, CS_OPT_DETAIL, new NativeLong(opt)) == CS_ERR_OK) {
      this.detail = opt;
    } else {
      throw new RuntimeException("ERROR: Unknown detail option");
    }
  }

  public void setMode(int opt) {
    if (cs.cs_option(ns.csh, CS_OPT_MODE, new NativeLong(opt)) == CS_ERR_OK) {
      this.mode = opt;
    } else {
      throw new RuntimeException("ERROR: Unknown mode option");
    }
  }

  public String getRegName(int reg) {
    return cs.cs_reg_name(ns.csh, reg);
  }

  protected void finalize() {
    cs.cs_close(ns.csh);
  }

  public CsInsn[] disasm(byte[] code, long address) {
    return disasm(code, address, 0);
  }

  public CsInsn[] disasm(byte[] code, long address, long count) {
    PointerByReference insnRef = new PointerByReference();

    NativeLong c = cs.cs_disasm_ex(ns.csh, code, new NativeLong(code.length), address, new NativeLong(count), insnRef);

    Pointer p = insnRef.getValue();
    _cs_insn byref = new _cs_insn(p);

    CsInsn[] allInsn = fromArrayRaw((_cs_insn[]) byref.toArray(c.intValue()));
    return allInsn;
  }
}

