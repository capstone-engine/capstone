// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.ByteByReference;
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
    public Ppc.UnionOpInfo ppc;
    public Sparc.UnionOpInfo sparc;
    public Systemz.UnionOpInfo sysz;
    public Xcore.UnionOpInfo xcore;
    public M680x.UnionOpInfo m680x;
  }

  protected static class _cs_insn extends Structure {
    // instruction ID.
    public int id;
    // instruction address.
    public long address;
    // instruction size.
    public short size;
    // machine bytes of instruction.
    public byte[] bytes;
    // instruction mnemonic. NOTE: irrelevant for diet engine.
    public byte[] mnemonic;
    // instruction operands. NOTE: irrelevant for diet engine.
    public byte[] op_str;
    // detail information of instruction.
    public _cs_detail.ByReference cs_detail;

    public _cs_insn() {
      bytes = new byte[24];
      mnemonic = new byte[32];
      op_str = new byte[160];
      java.util.Arrays.fill(mnemonic, (byte) 0);
      java.util.Arrays.fill(op_str, (byte) 0);
    }

    public _cs_insn(Pointer p) {
      this();
      useMemory(p);
      read();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("id", "address", "size", "bytes", "mnemonic", "op_str", "cs_detail");
    }
  }

  protected static class _cs_detail extends Structure {
    public static class ByReference extends _cs_detail implements Structure.ByReference {};

    // list of all implicit registers being read.
    public short[] regs_read = new short[16];
    public byte regs_read_count;
    // list of all implicit registers being written.
    public short[] regs_write = new short[20];
    public byte regs_write_count;
    // list of semantic groups this instruction belongs to.
    public byte[] groups = new byte[8];
    public byte groups_count;

    public UnionArch arch;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("regs_read", "regs_read_count", "regs_write", "regs_write_count", "groups", "groups_count", "arch");
    }
  }

  public static class CsInsn {
    private Pointer csh;
    private CS cs;
    private _cs_insn raw;
    private int arch;

    // instruction ID.
    public int id;
    // instruction address.
    public long address;
    // instruction size.
    public short size;
    // Machine bytes of this instruction, with number of bytes indicated by size above
    public byte[] bytes;
    // instruction mnemonic. NOTE: irrelevant for diet engine.
    public String mnemonic;
    // instruction operands. NOTE: irrelevant for diet engine.
    public String opStr;
    // list of all implicit registers being read.
    public short[] regsRead;
    // list of all implicit registers being written.
    public short[] regsWrite;
    // list of semantic groups this instruction belongs to.
    public byte[] groups;
    public OpInfo operands;

    public CsInsn (_cs_insn insn, int _arch, Pointer _csh, CS _cs, boolean diet) {
      id = insn.id;
      address = insn.address;
      size = insn.size;

      if (!diet) {
        int lm = 0;
        while (insn.mnemonic[lm++] != 0);
        int lo = 0;
        while (insn.op_str[lo++] != 0);
        mnemonic = new String(insn.mnemonic, 0, lm-1);
        opStr = new String(insn.op_str, 0, lo-1);
        bytes = Arrays.copyOf(insn.bytes, insn.size);
      }

      cs = _cs;
      arch = _arch;
      raw = insn;
      csh = _csh;

      if (insn.cs_detail != null) {
        if (!diet) {
          regsRead = new short[insn.cs_detail.regs_read_count];
          for (int i=0; i<regsRead.length; i++)
            regsRead[i] = insn.cs_detail.regs_read[i];
          regsWrite = new short[insn.cs_detail.regs_write_count];
          for (int i=0; i<regsWrite.length; i++)
            regsWrite[i] = insn.cs_detail.regs_write[i];
          groups = new byte[insn.cs_detail.groups_count];
          for (int i=0; i<groups.length; i++)
            groups[i] = insn.cs_detail.groups[i];
        }

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
        case CS_ARCH_SPARC:
          detail.arch.setType(Sparc.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Sparc.OpInfo((Sparc.UnionOpInfo) detail.arch.sparc);
          break;
        case CS_ARCH_SYSZ:
          detail.arch.setType(Systemz.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Systemz.OpInfo((Systemz.UnionOpInfo) detail.arch.sysz);
          break;
        case CS_ARCH_PPC:
          detail.arch.setType(Ppc.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Ppc.OpInfo((Ppc.UnionOpInfo) detail.arch.ppc);
          break;
        case CS_ARCH_XCORE:
          detail.arch.setType(Xcore.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Xcore.OpInfo((Xcore.UnionOpInfo) detail.arch.xcore);
          break;
        case CS_ARCH_M680X:
          detail.arch.setType(M680x.UnionOpInfo.class);
          detail.arch.read();
          op_info = new M680x.OpInfo((M680x.UnionOpInfo) detail.arch.m680x);
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

    public String groupName(int id) {
      return cs.cs_group_name(csh, id);
    }

    public boolean group(int gid) {
      return cs.cs_insn_group(csh, raw.getPointer(), gid) != 0;
    }

    public CsRegsAccess regsAccess() {
      Memory regsReadMemory = new Memory(64*2);
      ByteByReference regsReadCountRef = new ByteByReference();
      Memory regsWriteMemory = new Memory(64*2);
      ByteByReference regsWriteCountRef = new ByteByReference();

      int c = cs.cs_regs_access(csh, raw.getPointer(), regsReadMemory, regsReadCountRef, regsWriteMemory, regsWriteCountRef);
      if (c != CS_ERR_OK) {
        return null;
      }

      byte regsReadCount = regsReadCountRef.getValue();
      byte regsWriteCount = regsWriteCountRef.getValue();

      short[] regsRead = new short[regsReadCount];
      regsReadMemory.read(0, regsRead, 0, regsReadCount);

      short[] regsWrite = new short[regsWriteCount];
      regsWriteMemory.read(0, regsWrite, 0, regsWriteCount);

      return new CsRegsAccess(regsRead, regsWrite);
    }
  }

  public static class CsRegsAccess {
    public short[] regsRead;
    public short[] regsWrite;

    public CsRegsAccess(short[] regsRead, short[] regsWrite) {
      this.regsRead = regsRead;
      this.regsWrite = regsWrite;
    }
  }

  private CsInsn[] fromArrayRaw(_cs_insn[] arr_raw) {
    CsInsn[] arr = new CsInsn[arr_raw.length];

    for (int i = 0; i < arr_raw.length; i++) {
      arr[i] = new CsInsn(arr_raw[i], this.arch, ns.csh, cs, this.diet);
    }

    return arr;
  }

  private interface CS extends Library {
    public int cs_open(int arch, int mode, PointerByReference handle);
    public NativeLong cs_disasm(Pointer handle, byte[] code, NativeLong code_len,
        long addr, NativeLong count, PointerByReference insn);
    public void cs_free(Pointer p, NativeLong count);
    public int cs_close(PointerByReference handle);
    public int cs_option(Pointer handle, int option, NativeLong optionValue);

    public String cs_reg_name(Pointer csh, int id);
    public int cs_op_count(Pointer csh, Pointer insn, int type);
    public int cs_op_index(Pointer csh, Pointer insn, int type, int index);

    public String cs_insn_name(Pointer csh, int id);
    public String cs_group_name(Pointer csh, int id);
    public byte cs_insn_group(Pointer csh, Pointer insn, int id);
    public byte cs_reg_read(Pointer csh, Pointer insn, int id);
    public byte cs_reg_write(Pointer csh, Pointer insn, int id);
    public int cs_errno(Pointer csh);
    public int cs_version(IntByReference major, IntByReference minor);
    public boolean cs_support(int query);
    public String cs_strerror(int code);
    public int cs_regs_access(Pointer handle, Pointer insn, Pointer regs_read, ByteByReference regs_read_count, Pointer regs_write, ByteByReference regs_write_count);
  }

  // Capstone API version
  public static final int CS_API_MAJOR = 5;
  public static final int CS_API_MINOR = 0;

  // architectures
  public static final int CS_ARCH_ARM = 0;
  public static final int CS_ARCH_ARM64 = 1;
  public static final int CS_ARCH_MIPS = 2;
  public static final int CS_ARCH_X86 = 3;
  public static final int CS_ARCH_PPC = 4;
  public static final int CS_ARCH_SPARC = 5;
  public static final int CS_ARCH_SYSZ = 6;
  public static final int CS_ARCH_XCORE = 7;
  public static final int CS_ARCH_M68K = 8;
  public static final int CS_ARCH_TMS320C64X = 9;
  public static final int CS_ARCH_M680X = 10;
  public static final int CS_ARCH_MAX = 11;
  public static final int CS_ARCH_ALL = 0xFFFF; // query id for cs_support()

  // disasm mode
  public static final int CS_MODE_LITTLE_ENDIAN = 0;  // little-endian mode (default mode)
  public static final int CS_MODE_ARM = 0;	          // 32-bit ARM
  public static final int CS_MODE_16 = 1 << 1;		// 16-bit mode for X86
  public static final int CS_MODE_32 = 1 << 2;		// 32-bit mode for X86
  public static final int CS_MODE_64 = 1 << 3;		// 64-bit mode for X86, PPC
  public static final int CS_MODE_THUMB = 1 << 4;	  // ARM's Thumb mode, including Thumb-2
  public static final int CS_MODE_MCLASS = 1 << 5;	  // ARM's Cortex-M series
  public static final int CS_MODE_V8 = 1 << 6;	      // ARMv8 A32 encodings for ARM
  public static final int CS_MODE_MICRO = 1 << 4;	  // MicroMips mode (Mips arch)
  public static final int CS_MODE_MIPS3 = 1 << 5;     // Mips III ISA
  public static final int CS_MODE_MIPS32R6 = 1 << 6;  // Mips32r6 ISA
  public static final int CS_MODE_MIPS2 = 1 << 7;  // Mips II ISA
  public static final int CS_MODE_BIG_ENDIAN = 1 << 31; // big-endian mode
  public static final int CS_MODE_V9 = 1 << 4;	      // SparcV9 mode (Sparc arch)
  public static final int CS_MODE_MIPS32 = CS_MODE_32; // Mips32 ISA
  public static final int CS_MODE_MIPS64 = CS_MODE_64; // Mips64 ISA
  public static final int CS_MODE_QPX = 1 << 4; // Quad Processing eXtensions mode (PPC)
  public static final int CS_MODE_SPE = 1 << 5; // Signal Processing Engine mode (PPC)
  public static final int CS_MODE_BOOKE = 1 << 6; // Book-E mode (PPC)
  public static final int CS_MODE_PS = 1 << 7; // Paired-singles mode (PPC)
  public static final int CS_MODE_M680X_6301 = 1 << 1; // M680X Hitachi 6301,6303 mode
  public static final int CS_MODE_M680X_6309 = 1 << 2; // M680X Hitachi 6309 mode
  public static final int CS_MODE_M680X_6800 = 1 << 3; // M680X Motorola 6800,6802 mode
  public static final int CS_MODE_M680X_6801 = 1 << 4; // M680X Motorola 6801,6803 mode
  public static final int CS_MODE_M680X_6805 = 1 << 5; // M680X Motorola 6805 mode
  public static final int CS_MODE_M680X_6808 = 1 << 6; // M680X Motorola 6808 mode
  public static final int CS_MODE_M680X_6809 = 1 << 7; // M680X Motorola 6809 mode
  public static final int CS_MODE_M680X_6811 = 1 << 8; // M680X Motorola/Freescale 68HC11 mode
  public static final int CS_MODE_M680X_CPU12 = 1 << 9; // M680X Motorola/Freescale/NXP CPU12 mode
  public static final int CS_MODE_M680X_HCS08 = 1 << 10; // M680X Freescale HCS08 mode

  // Capstone error
  public static final int CS_ERR_OK = 0;
  public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
  public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
  public static final int CS_ERR_HANDLE = 3;	// Invalid handle
  public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
  public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode
  public static final int CS_ERR_OPTION = 6;  // Invalid/unsupported option: cs_option()
  public static final int CS_ERR_DETAIL = 7;  // Invalid/unsupported option: cs_option()
  public static final int CS_ERR_MEMSETUP = 8;
  public static final int CS_ERR_VERSION = 9;  //Unsupported version (bindings)
  public static final int CS_ERR_DIET = 10;  //Information irrelevant in diet engine
  public static final int CS_ERR_SKIPDATA = 11;  //Access irrelevant data for "data" instruction in SKIPDATA mode
  public static final int CS_ERR_X86_ATT = 12;  //X86 AT&T syntax is unsupported (opt-out at compile time)
  public static final int CS_ERR_X86_INTEL = 13;  //X86 Intel syntax is unsupported (opt-out at compile time)

  // Capstone option type
  public static final int CS_OPT_SYNTAX = 1;  // Intel X86 asm syntax (CS_ARCH_X86 arch)
  public static final int CS_OPT_DETAIL = 2;  // Break down instruction structure into details
  public static final int CS_OPT_MODE = 3;  // Change engine's mode at run-time

  // Capstone option value
  public static final int CS_OPT_OFF = 0;  // Turn OFF an option - default option of CS_OPT_DETAIL
  public static final int CS_OPT_SYNTAX_INTEL = 1;  // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX,  CS_ARCH_X86)
  public static final int CS_OPT_SYNTAX_ATT = 2;    // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
  public static final int CS_OPT_ON = 3;  // Turn ON an option (CS_OPT_DETAIL)
  public static final int CS_OPT_SYNTAX_NOREGNAME = 3; // PPC asm syntax: Prints register name with only number (CS_OPT_SYNTAX)

  // Common instruction operand types - to be consistent across all architectures.
  public static final int CS_OP_INVALID = 0;
  public static final int CS_OP_REG = 1;
  public static final int CS_OP_IMM = 2;
  public static final int CS_OP_MEM = 3;
  public static final int CS_OP_FP  = 4;

  // Common instruction operand access types - to be consistent across all architectures.
  // It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
  public static final int CS_AC_INVALID = 0;
  public static final int CS_AC_READ = 1 << 0;
  public static final int CS_AC_WRITE = 1 << 1;

  // Common instruction groups - to be consistent across all architectures.
  public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
  public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
  public static final int CS_GRP_CALL    = 2;  // all call instructions
  public static final int CS_GRP_RET     = 3;  // all return instructions
  public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
  public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
  public static final int CS_GRP_PRIVILEGE = 6;  // all privileged instructions

  // Query id for cs_support()
  public static final int CS_SUPPORT_DIET = CS_ARCH_ALL+1;	  // diet mode
  public static final int CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL+2;  // X86 reduce mode

  protected class NativeStruct {
      private Pointer csh;
      private PointerByReference handleRef;
  }

  private static final CsInsn[] EMPTY_INSN = new CsInsn[0];

  protected NativeStruct ns; // for memory retention
  private CS cs;
  public int arch;
  public int mode;
  private int syntax;
  private int detail;
  private boolean diet;

  public Capstone(int arch, int mode) {
    cs = (CS)Native.loadLibrary("capstone", CS.class);
    int coreVersion = cs.cs_version(null, null);
    int bindingVersion = (CS_API_MAJOR << 8) + CS_API_MINOR;
    if (coreVersion != bindingVersion) {
      throw  new RuntimeException("Different API version between core " + coreVersion +
              " & binding " + bindingVersion + " (CS_ERR_VERSION)");
    }

    this.arch = arch;
    this.mode = mode;
    ns = new NativeStruct();
    ns.handleRef = new PointerByReference();
    if (cs.cs_open(arch, mode, ns.handleRef) != CS_ERR_OK) {
      throw new RuntimeException("ERROR: Wrong arch or mode");
    }
    ns.csh = ns.handleRef.getValue();
    this.detail = CS_OPT_OFF;
	this.diet = cs.cs_support(CS_SUPPORT_DIET);
  }

  // return combined API version
  public int version() {
    return cs.cs_version(null, null);
  }

  // set Assembly syntax
  public void setSyntax(int syntax) {
    if (cs.cs_option(ns.csh, CS_OPT_SYNTAX, new NativeLong(syntax)) == CS_ERR_OK) {
      this.syntax = syntax;
    } else {
      throw new RuntimeException("ERROR: Failed to set assembly syntax");
    }
  }

  // set detail option at run-time
  public void setDetail(int opt) {
    if (cs.cs_option(ns.csh, CS_OPT_DETAIL, new NativeLong(opt)) == CS_ERR_OK) {
      this.detail = opt;
    } else {
      throw new RuntimeException("ERROR: Failed to set detail option");
    }
  }

  // set mode option at run-time
  public void setMode(int opt) {
    if (cs.cs_option(ns.csh, CS_OPT_MODE, new NativeLong(opt)) == CS_ERR_OK) {
      this.mode = opt;
    } else {
      throw new RuntimeException("ERROR: Failed to set mode option");
    }
  }

  // destructor automatically caled at destroyed time.
  protected void finalize() {
    // FIXME: crashed on Ubuntu 14.04 64bit, OpenJDK java 1.6.0_33
    // cs.cs_close(ns.handleRef);
  }

  // destructor automatically caled at destroyed time.
  public int close() {
    return cs.cs_close(ns.handleRef);
  }

  /**
   * Disassemble instructions from @code assumed to be located at @address,
   * stop when encountering first broken instruction.
   * 
   * @param code The source machine code bytes.
   * @param address The address of the first machine code byte.
   * @return the array of successfully disassembled instructions, empty if no instruction could be disassembled.
   */
  public CsInsn[] disasm(byte[] code, long address) {
    return disasm(code, address, 0);
  }

  /**
   * Disassemble up to @count instructions from @code assumed to be located at @address,
   * stop when encountering first broken instruction.
   * 
   * @param code The source machine code bytes.
   * @param address The address of the first machine code byte.
   * @param count The maximum number of instructions to disassemble, 0 for no maximum.
   * @return the array of successfully disassembled instructions, empty if no instruction could be disassembled.
   */
  public CsInsn[] disasm(byte[] code, long address, long count) {
    PointerByReference insnRef = new PointerByReference();

    NativeLong c = cs.cs_disasm(ns.csh, code, new NativeLong(code.length), address, new NativeLong(count), insnRef);
    
    if (0 == c.intValue()) {
    	return EMPTY_INSN;
    }
    
    Pointer p = insnRef.getValue();
    _cs_insn byref = new _cs_insn(p);

    CsInsn[] allInsn = fromArrayRaw((_cs_insn[]) byref.toArray(c.intValue()));

    // free allocated memory
    // cs.cs_free(p, c);
    // FIXME(danghvu): Can't free because memory is still inside CsInsn

    return allInsn;
  }

  public String strerror(int code) {
    return cs.cs_strerror(code);
  }
}
