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
    public AArch64.UnionOpInfo aarch64;
    public M68k.UnionOpInfo m68k;
    public X86.UnionOpInfo x86;
    public Mips.UnionOpInfo mips;
    public Ppc.UnionOpInfo ppc;
    public Sparc.UnionOpInfo sparc;
    public Systemz.UnionOpInfo sysz;
    public Xcore.UnionOpInfo xcore;
    public TMS320C64x.UnionOpInfo tms320c64x;
    public M680x.UnionOpInfo m680x;
    public Evm.UnionOpInfo evm;
    public Mos65xx.UnionOpInfo mos65xx;
    public Wasm.UnionOpInfo wasm;
    public Bpf.UnionOpInfo bpf;
    public Riscv.UnionOpInfo riscv;
    public Sh.UnionOpInfo sh;
    public Tricore.UnionOpInfo tricore;
    public Alpha.UnionOpInfo alpha;
    public Hppa.UnionOpInfo hppa;
    public Loongarch.UnionOpInfo loongarch;
    public Xtensa.UnionOpInfo xtensa;
    public Arc.UnionOpInfo arc;
  }

  protected static class _cs_insn extends Structure {
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    public int id;
    /// If this instruction is an alias instruction, this member is set with
    /// the alias ID.
    /// Otherwise to <ARCH>_INS_INVALID.
    /// -- Only supported by auto-sync archs --
    public long alias_id;
    /// Address (EIP) of this instruction
	  /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    public long address;
    /// Size of this instruction
	  /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    public short size;
    /// Machine bytes of this instruction, with number of bytes indicated by @size above
	  /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    public byte[] bytes;
    /// Ascii text of instruction mnemonic
	  /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    public byte[] mnemonic;
    /// Ascii text of instruction operands
	  /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    public byte[] op_str;
    /// True: This instruction is an alias.
    /// False: Otherwise.
    /// -- Only supported by auto-sync archs --
    public byte is_alias;
    /// True: The operands are the ones of the alias instructions.
    /// False: The detail operands are from the real instruction.
    public byte usesAliasDetails;
    /// Set if instruction can be decoded but is invalid
    /// due to context or illegal operands.
    public byte illegal;
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
    public List<String> getFieldOrder() {
      return Arrays.asList("id", "alias_id", "address", "size", "bytes", "mnemonic", "op_str", "is_alias", "usesAliasDetails", "illegal", "cs_detail");
    }
  }

  public static final int UINT8_MAX = 0xff;
  public static final int UINT16_MAX = 0xffff;
  public static final int MAX_IMPL_W_REGS = 47;
  public static final int MAX_IMPL_R_REGS = 20;
  public static final int MAX_NUM_GROUPS = 16;

  protected static class _cs_detail extends Structure {
    public static class ByReference extends _cs_detail implements Structure.ByReference {};

    // list of all implicit registers being read.
    public short[] regs_read = new short[MAX_IMPL_R_REGS];
    public byte regs_read_count;
    // list of all implicit registers being written.
    public short[] regs_write = new short[MAX_IMPL_W_REGS];
    public byte regs_write_count;
    // list of semantic groups this instruction belongs to.
    public byte[] groups = new byte[MAX_NUM_GROUPS];
    public byte groups_count;

    // Instruction has writeback operands.
    public byte writeback;

    public UnionArch arch;

    public void read() {
      readField("regs_read_count");
      regs_read = new short[regs_read_count];
      if (regs_read_count > 0)
        readField("regs_read");
      readField("regs_write_count");
      regs_write = new short[regs_write_count];
      if (regs_write_count > 0)
        readField("regs_write");
      readField("groups_count");
      groups = new byte[groups_count];
      if (groups_count > 0)
        readField("groups");
      readField("writeback");
      readField("arch");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("regs_read", "regs_read_count", "regs_write", "regs_write_count", "groups", "groups_count", "writeback", "arch");
    }
  }

  public static class CsInsn {
    private Pointer csh;
    private CS cs;
    private _cs_insn raw;
    private int arch;

    // instruction ID.
    public int id;
    /// If this instruction is an alias instruction, this member is set with
    /// the alias ID.
    /// Otherwise to <ARCH>_INS_INVALID.
    /// -- Only supported by auto-sync archs --
    public long aliasId;
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
    // this instruction is an alias.
    // -- Only supported by auto-sync archs --
    public boolean isAlias;
    /// True: The operands are the ones of the alias instructions.
    /// False: The detail operands are from the real instruction.
    public boolean usesAliasDetails;
    // Set if instruction can be decoded but is invalid
    // due to context or illegal operands.
    public boolean illegal;
    // list of all implicit registers being read.
    public short[] regsRead;
    // list of all implicit registers being written.
    public short[] regsWrite;
    // list of semantic groups this instruction belongs to.
    public byte[] groups;
    // instruction has writeback operands.
    public boolean writeback;
    public OpInfo operands;

    public CsInsn (_cs_insn insn, int _arch, Pointer _csh, CS _cs, boolean diet) {
      id = insn.id;
      aliasId = insn.alias_id;
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

      isAlias = insn.is_alias != 0;
      usesAliasDetails = insn.usesAliasDetails != 0;
      illegal = insn.illegal != 0;

      cs = _cs;
      arch = _arch;
      raw = insn;
      csh = _csh;

      if (insn.cs_detail != null && !isInvalidInsn()) {
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
          writeback = insn.cs_detail.writeback != 0;
        }

        operands = getOptInfo(insn.cs_detail);
      }
    }

    public String toString() {
      return String.format("0x%x [%s]:\t%s\t%s", address, formatBytesHex(bytes), mnemonic, opStr);
    }

    private String formatBytesHex(byte[] data) {
      if (data == null || data.length == 0) {
        return "";
      }

      StringBuilder sb = new StringBuilder(data.length * 3 - 1);
      for (int i = 0; i < data.length; i++) {
        sb.append(String.format("%02x", data[i] & 0xff));
      }

      return sb.toString();
    }

    private OpInfo getOptInfo(_cs_detail detail) {
      OpInfo op_info = null;

      switch (this.arch) {
        case CS_ARCH_ARM:
          detail.arch.setType(Arm.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Arm.OpInfo((Arm.UnionOpInfo) detail.arch.arm);
          break;
        case CS_ARCH_AARCH64:
          detail.arch.setType(AArch64.UnionOpInfo.class);
          detail.arch.read();
          op_info = new AArch64.OpInfo((AArch64.UnionOpInfo) detail.arch.aarch64);
          break;
        case CS_ARCH_M68K:
          detail.arch.setType(M68k.UnionOpInfo.class);
          detail.arch.read();
          op_info = new M68k.OpInfo((M68k.UnionOpInfo) detail.arch.m68k);
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
        case CS_ARCH_SYSTEMZ:
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
        case CS_ARCH_TMS320C64X:
          detail.arch.setType(TMS320C64x.UnionOpInfo.class);
          detail.arch.read();
          op_info = new TMS320C64x.OpInfo((TMS320C64x.UnionOpInfo) detail.arch.tms320c64x);
          break;
        case CS_ARCH_M680X:
          detail.arch.setType(M680x.UnionOpInfo.class);
          detail.arch.read();
          op_info = new M680x.OpInfo((M680x.UnionOpInfo) detail.arch.m680x);
          break;
        case CS_ARCH_EVM:
          detail.arch.setType(Evm.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Evm.OpInfo((Evm.UnionOpInfo) detail.arch.evm);
          break;
        case CS_ARCH_MOS65XX:
          detail.arch.setType(Mos65xx.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Mos65xx.OpInfo((Mos65xx.UnionOpInfo) detail.arch.mos65xx);
          break;
        case CS_ARCH_WASM:
          detail.arch.setType(Wasm.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Wasm.OpInfo((Wasm.UnionOpInfo) detail.arch.wasm);
          break;
        case CS_ARCH_BPF:
          detail.arch.setType(Bpf.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Bpf.OpInfo((Bpf.UnionOpInfo) detail.arch.bpf);
          break;
        case CS_ARCH_RISCV:
          detail.arch.setType(Riscv.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Riscv.OpInfo((Riscv.UnionOpInfo) detail.arch.riscv);
          break;
        case CS_ARCH_SH:
          detail.arch.setType(Sh.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Sh.OpInfo((Sh.UnionOpInfo) detail.arch.sh);
          break;
        case CS_ARCH_TRICORE:
          detail.arch.setType(Tricore.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Tricore.OpInfo((Tricore.UnionOpInfo) detail.arch.tricore);
          break;
        case CS_ARCH_ALPHA:
          detail.arch.setType(Alpha.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Alpha.OpInfo((Alpha.UnionOpInfo) detail.arch.alpha);
          break;
        case CS_ARCH_HPPA:
          detail.arch.setType(Hppa.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Hppa.OpInfo((Hppa.UnionOpInfo) detail.arch.hppa);
          break;
        case CS_ARCH_LOONGARCH:
          detail.arch.setType(Loongarch.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Loongarch.OpInfo((Loongarch.UnionOpInfo) detail.arch.loongarch);
          break;
        case CS_ARCH_XTENSA:
          detail.arch.setType(Xtensa.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Xtensa.OpInfo((Xtensa.UnionOpInfo) detail.arch.xtensa);
          break;
        case CS_ARCH_ARC:
          detail.arch.setType(Arc.UnionOpInfo.class);
          detail.arch.read();
          op_info = new Arc.OpInfo((Arc.UnionOpInfo) detail.arch.arc);
          break;
        default:
      }

      return op_info;
    }

    public boolean isInvalidInsn() {
      if (arch == CS_ARCH_EVM) {
        return id == Evm_const.EVM_INS_INVALID;
      } else {
        return id == 0;
      }
    }

    // TODO: Support SKIPDATA
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
    public int cs_option(Pointer handle, int type, NativeLong optionValue);

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
  public static final int CS_API_MAJOR = 6;
  public static final int CS_API_MINOR = 0;

  // architectures
  public static final int CS_ARCH_ARM = 0;
  public static final int CS_ARCH_ARM64 = 1;
  public static final int CS_ARCH_AARCH64 = 1;
  public static final int CS_ARCH_SYSZ = 2;
  public static final int CS_ARCH_SYSTEMZ = 2;
  public static final int CS_ARCH_MIPS = 3;
  public static final int CS_ARCH_X86 = 4;
  public static final int CS_ARCH_PPC = 5;
  public static final int CS_ARCH_SPARC = 6;
  public static final int CS_ARCH_XCORE = 7;
  public static final int CS_ARCH_M68K = 8;
  public static final int CS_ARCH_TMS320C64X = 9;
  public static final int CS_ARCH_M680X = 10;
  public static final int CS_ARCH_EVM = 11;
  public static final int CS_ARCH_MOS65XX = 12; 
  public static final int CS_ARCH_WASM = 13;
  public static final int CS_ARCH_BPF = 14;
  public static final int CS_ARCH_RISCV = 15;
  public static final int CS_ARCH_SH = 16;
  public static final int CS_ARCH_TRICORE = 17;
  public static final int CS_ARCH_ALPHA = 18;
  public static final int CS_ARCH_HPPA = 19;
  public static final int CS_ARCH_LOONGARCH = 20;
  public static final int CS_ARCH_XTENSA = 21;
  public static final int CS_ARCH_ARC = 22;
  public static final int CS_ARCH_MAX = 22;
  public static final int CS_ARCH_ALL = 0xFFFF; // query id for cs_support()

  public static final int CS_MODE_AARCH64_ISA_BITS = 0x00fffff8;
  public static final int CS_MODE_VENDOR_AARCH64_BIT0 = 30;

  // disasm mode
  public static final int CS_MODE_LITTLE_ENDIAN = 0;	// little-endian mode (default mode)
  public static final int CS_MODE_ARM = 0;	// 32-bit ARM
  public static final int CS_MODE_16 = 1 << 1;	// 16-bit mode (X86)
  public static final int CS_MODE_32 = 1 << 2;	// 32-bit mode (X86)
  public static final int CS_MODE_64 = 1 << 3;	// 64-bit mode (X86, PPC)
  public static final int CS_MODE_THUMB = 1 << 4;	// ARM's Thumb mode, including Thumb-2
  public static final int CS_MODE_MCLASS = 1 << 5;	// ARM's Cortex-M series
  public static final int CS_MODE_V8 = 1 << 6;	// ARMv8 A32 encodings for ARM
  public static final int CS_MODE_APPLE_PROPRIETARY = (1 << CS_MODE_VENDOR_AARCH64_BIT0);  // Apple proprietary AArch64 instructions like AMX, MUL53, and others.
  public static final int CS_MODE_V9 = 1 << 4; // SparcV9 mode (Sparc)
  public static final int CS_MODE_QPX = 1 << 4; // Quad Processing eXtensions mode (PPC)
  public static final int CS_MODE_SPE = 1 << 5; // Signal Processing Engine mode (PPC)
  public static final int CS_MODE_BOOKE = 1 << 6; // Book-E mode (PPC)
  public static final int CS_MODE_PS = 1 << 7; // Paired-singles mode (PPC)
  public static final int CS_MODE_AIX_OS = 1 << 8; // PowerPC AIX-OS
  public static final int CS_MODE_PWR7 = 1 << 9; // Power 7
  public static final int CS_MODE_PWR8 = 1 << 10; // Power 8
  public static final int CS_MODE_PWR9 = 1 << 11; // Power 9
  public static final int CS_MODE_PWR10 = 1 << 12; // Power 10
  public static final int CS_MODE_PPC_ISA_FUTURE = 1 << 13; // Power ISA Future
  public static final int CS_MODE_MODERN_AIX_AS = 1 << 14; // PowerPC AIX-OS with modern assembly
  public static final int CS_MODE_MSYNC = 1 << 15; // PowerPC Has only the msync instruction instead of sync. Implies BOOKE
  public static final int CS_MODE_M68K_000 = 1 << 1; // M68K 68000 mode
  public static final int CS_MODE_M68K_010 = 1 << 2; // M68K 68010 mode
  public static final int CS_MODE_M68K_020 = 1 << 3; // M68K 68020 mode
  public static final int CS_MODE_M68K_030 = 1 << 4; // M68K 68030 mode
  public static final int CS_MODE_M68K_040 = 1 << 5; // M68K 68040 mode
  public static final int CS_MODE_M68K_060 = 1 << 6; // M68K 68060 mode
  public static final int CS_MODE_BIG_ENDIAN = 1 << 31; // big-endian mode
  public static final int CS_MODE_MIPS16 = CS_MODE_16; // Generic mips16
  public static final int CS_MODE_MIPS32 = CS_MODE_32; // Generic mips32
  public static final int CS_MODE_MIPS64 = CS_MODE_64; // Generic mips64
  public static final int CS_MODE_MICRO = 1 << 4; // microMips
  public static final int CS_MODE_MIPS1 = 1 << 5; // Mips I ISA Support
  public static final int CS_MODE_MIPS2 = 1 << 6; // Mips II ISA Support
  public static final int CS_MODE_MIPS32R2 = 1 << 7; // Mips32r2 ISA Support
  public static final int CS_MODE_MIPS32R3 = 1 << 8; // Mips32r3 ISA Support
  public static final int CS_MODE_MIPS32R5 = 1 << 9; // Mips32r5 ISA Support
  public static final int CS_MODE_MIPS32R6 = 1 << 10; // Mips32r6 ISA Support
  public static final int CS_MODE_MIPS3 = 1 << 11; // MIPS III ISA Support
  public static final int CS_MODE_MIPS4 = 1 << 12; // MIPS IV ISA Support
  public static final int CS_MODE_MIPS5 = 1 << 13; // MIPS V ISA Support
  public static final int CS_MODE_MIPS64R2 = 1 << 14; // Mips64r2 ISA Support
  public static final int CS_MODE_MIPS64R3 = 1 << 15; // Mips64r3 ISA Support
  public static final int CS_MODE_MIPS64R5 = 1 << 16; // Mips64r5 ISA Support
  public static final int CS_MODE_MIPS64R6 = 1 << 17; // Mips64r6 ISA Support
  public static final int CS_MODE_OCTEON = 1 << 18; // Octeon cnMIPS Support
  public static final int CS_MODE_OCTEONP = 1 << 19; // Octeon+ cnMIPS Support
  public static final int CS_MODE_NANOMIPS = 1 << 20; // Generic nanomips 
  public static final int CS_MODE_NMS1 = ((1 << 21) | CS_MODE_NANOMIPS); // nanoMips NMS1
  public static final int CS_MODE_I7200 = ((1 << 22) | CS_MODE_NANOMIPS); // nanoMips I7200
  public static final int CS_MODE_MIPS_NOFLOAT = 1 << 23; // Disable floating points ops
  public static final int CS_MODE_MIPS_PTR64 = 1 << 24; // Mips pointers are 64-bit
  public static final int CS_MODE_MICRO32R3 = (CS_MODE_MICRO | CS_MODE_MIPS32R3); // microMips32r3
  public static final int CS_MODE_MICRO32R6 = (CS_MODE_MICRO | CS_MODE_MIPS32R6); // microMips32r6
  public static final int CS_MODE_M680X_6301 = 1 << 1; // M680X Hitachi 6301,6303 mode
  public static final int CS_MODE_M680X_6309 = 1 << 2; // M680X Hitachi 6309 mode
  public static final int CS_MODE_M680X_6800 = 1 << 3; // M680X Motorola 6800,6802 mode
  public static final int CS_MODE_M680X_6801 = 1 << 4; // M680X Motorola 6801,6803 mode
  public static final int CS_MODE_M680X_6805 = 1 << 5; // M680X Motorola/Freescale 6805 mode
  public static final int CS_MODE_M680X_6808 = 1 << 6; // M680X Motorola/Freescale/NXP 68HC08 mode
  public static final int CS_MODE_M680X_6809 = 1 << 7; // M680X Motorola 6809 mode
  public static final int CS_MODE_M680X_6811 = 1 << 8; // M680X Motorola/Freescale/NXP 68HC11 mode
  public static final int CS_MODE_M680X_CPU12 = 1 << 9; // M680X Motorola/Freescale/NXP CPU12
                                                        // used on M68HC12/HCS12
  public static final int CS_MODE_M680X_HCS08 = 1 << 10; // M680X Freescale/NXP HCS08 mode
  public static final int CS_MODE_M680X_RS08 = 1 << 11; // M680X Freescale/NXP RS08 mode
  public static final int CS_MODE_BPF_CLASSIC = 0;	// Classic BPF mode (default)
  public static final int CS_MODE_BPF_EXTENDED = 1 << 0;	// Extended BPF mode
  public static final int CS_MODE_RISCV32 = 1 << 0;        // RISCV RV32G
  public static final int CS_MODE_RISCV64 = 1 << 1;        // RISCV RV64G
  public static final int CS_MODE_RISCV_C = 1 << 2;        // RISCV compressed instructure mode
  public static final int CS_MODE_RISCV_FD = 1 << 3;
  public static final int CS_MODE_RISCV_F = CS_MODE_RISCV_FD;
  public static final int CS_MODE_RISCV_D = CS_MODE_RISCV_FD;
  public static final int CS_MODE_RISCV_V = 1 << 4;
  public static final int CS_MODE_RISCV_ZFINX = 1 << 5;
  public static final int CS_MODE_RISCV_ZDINX = CS_MODE_RISCV_ZFINX;
  public static final int CS_MODE_RISCV_ZHINX = CS_MODE_RISCV_ZFINX;
  public static final int CS_MODE_RISCV_ZHINXMIN = CS_MODE_RISCV_ZFINX;
  public static final int CS_MODE_RISCV_ZCMP_ZCMT_ZCE = 1 << 6;
  public static final int CS_MODE_RISCV_ZCE = CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
  public static final int CS_MODE_RISCV_ZCMP = CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
  public static final int CS_MODE_RISCV_ZCMT = CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
  public static final int CS_MODE_RISCV_ZICFISS = 1 << 7;
  public static final int CS_MODE_RISCV_EXPERIMENTAL_ZICFISS = CS_MODE_RISCV_ZICFISS;
  public static final int CS_MODE_RISCV_E = 1 << 8;
  public static final int CS_MODE_RISCV_A = 1 << 9;
  public static final int CS_MODE_RISCV_COREV = 1 << 10;
  public static final int CS_MODE_RISCV_XCVALU = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVBI = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVBITMANIP = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVELW = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVMAC = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVMEM = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_XCVSIMD = CS_MODE_RISCV_COREV;
  public static final int CS_MODE_RISCV_THEAD = 1 << 11;
  public static final int CS_MODE_RISCV_XTHEADBA = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADBS = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADCMO = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADCONDMOV = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADFMEMIDX = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADMAC = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADMEMIDX = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADMEMPAIR = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADSYNC = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_XTHEADVDOT = CS_MODE_RISCV_THEAD;
  public static final int CS_MODE_RISCV_SIFIVE = 1 << 12;
  public static final int CS_MODE_RISCV_XSFVCP = CS_MODE_RISCV_SIFIVE;
  public static final int CS_MODE_RISCV_XSFVFNRCLIPXFQF = CS_MODE_RISCV_SIFIVE;
  public static final int CS_MODE_RISCV_XSFVFWMACCQQQ = CS_MODE_RISCV_SIFIVE;
  public static final int CS_MODE_RISCV_XSFVQMACCDOD = CS_MODE_RISCV_SIFIVE;
  public static final int CS_MODE_RISCV_XSFVQMACCQOQ = CS_MODE_RISCV_SIFIVE;
  public static final int CS_MODE_RISCV_BITMANIP = 1 << 13;
  public static final int CS_MODE_RISCV_ZBA = 1 << 14;
  public static final int CS_MODE_RISCV_ZBB = 1 << 15;
  public static final int CS_MODE_RISCV_ZBC = 1 << 16;
  public static final int CS_MODE_RISCV_ZBKB = 1 << 17;
  public static final int CS_MODE_RISCV_ZBKC = 1 << 18;
  public static final int CS_MODE_RISCV_ZBKX = 1 << 19;
  public static final int CS_MODE_RISCV_ZBS = 1 << 20;
  public static final int CS_MODE_MOS65XX_6502 = 1 << 1; // MOS65XXX MOS 6502
  public static final int CS_MODE_MOS65XX_65C02 = 1 << 2; // MOS65XXX WDC 65c02
  public static final int CS_MODE_MOS65XX_W65C02 = 1 << 3; // MOS65XXX WDC W65c02
  public static final int CS_MODE_MOS65XX_65816 = 1 << 4; // MOS65XXX WDC 65816, 8-bit m/x
  public static final int CS_MODE_MOS65XX_65816_LONG_M = (1 << 5); // MOS65XXX WDC 65816, 16-bit m, 8-bit x
  public static final int CS_MODE_MOS65XX_65816_LONG_X = (1 << 6); // MOS65XXX WDC 65816, 8-bit m, 16-bit x
  public static final int CS_MODE_MOS65XX_65816_LONG_MX = CS_MODE_MOS65XX_65816_LONG_M | CS_MODE_MOS65XX_65816_LONG_X;
  public static final int CS_MODE_SH2 = 1 << 1;    // SH2
  public static final int CS_MODE_SH2A = 1 << 2;   // SH2A
  public static final int CS_MODE_SH3 = 1 << 3;    // SH3
  public static final int CS_MODE_SH4 = 1 << 4;    // SH4
  public static final int CS_MODE_SH4A = 1 << 5;   // SH4A
  public static final int CS_MODE_SHFPU = 1 << 6;  // w/ FPU
  public static final int CS_MODE_SHDSP = 1 << 7;  // w/ DSP
  public static final int CS_MODE_TRICORE_110 = 1 << 1; // Tricore 1.1
  public static final int CS_MODE_TRICORE_120 = 1 << 2; // Tricore 1.2
  public static final int CS_MODE_TRICORE_130 = 1 << 3; // Tricore 1.3
  public static final int CS_MODE_TRICORE_131 = 1 << 4; // Tricore 1.3.1
  public static final int CS_MODE_TRICORE_160 = 1 << 5; // Tricore 1.6
  public static final int CS_MODE_TRICORE_161 = 1 << 6; // Tricore 1.6.1
  public static final int CS_MODE_TRICORE_162 = 1 << 7; // Tricore 1.6.2
  public static final int CS_MODE_TRICORE_180 = 1 << 8; // Tricore 1.8.0
  public static final int CS_MODE_HPPA_11 = 1 << 1; // HPPA 1.1
  public static final int CS_MODE_HPPA_20 = 1 << 2; // HPPA 2.0
  public static final int CS_MODE_HPPA_20W = CS_MODE_HPPA_20 | (1 << 3); // HPPA 2.0 wide
  public static final int CS_MODE_LOONGARCH32  = 1 << 0;        // LoongArch32
  public static final int CS_MODE_LOONGARCH64  = 1 << 1;        // LoongArch64
  public static final int CS_MODE_SYSTEMZ_ARCH8 = 1 << 1; // Enables features of the ARCH8 processor
  public static final int CS_MODE_SYSTEMZ_ARCH9 = 1 << 2; // Enables features of the ARCH9 processor
  public static final int CS_MODE_SYSTEMZ_ARCH10 = 1 << 3; // Enables features of the ARCH10 processor
  public static final int CS_MODE_SYSTEMZ_ARCH11 = 1 << 4; // Enables features of the ARCH11 processor
  public static final int CS_MODE_SYSTEMZ_ARCH12 = 1 << 5; // Enables features of the ARCH12 processor
  public static final int CS_MODE_SYSTEMZ_ARCH13 = 1 << 6; // Enables features of the ARCH13 processor
  public static final int CS_MODE_SYSTEMZ_ARCH14 = 1 << 7; // Enables features of the ARCH14 processor
  public static final int CS_MODE_SYSTEMZ_Z10 = 1 << 8; // Enables features of the Z10 processor
  public static final int CS_MODE_SYSTEMZ_Z196 = 1 << 9; // Enables features of the Z196 processor
  public static final int CS_MODE_SYSTEMZ_ZEC12 = 1 << 10; // Enables features of the ZEC12 processor
  public static final int CS_MODE_SYSTEMZ_Z13 = 1 << 11; // Enables features of the Z13 processor
  public static final int CS_MODE_SYSTEMZ_Z14 = 1 << 12; // Enables features of the Z14 processor
  public static final int CS_MODE_SYSTEMZ_Z15 = 1 << 13; // Enables features of the Z15 processor
  public static final int CS_MODE_SYSTEMZ_Z16 = 1 << 14; // Enables features of the Z16 processor
  public static final int CS_MODE_SYSTEMZ_GENERIC = 1 << 15; // Enables features of the generic processor
  public static final int CS_MODE_XTENSA = 1 << 1; // Xtensa

  // Capstone error
  public static final int CS_ERR_OK = 0;      // No error: everything was fine
  public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
  public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
  public static final int CS_ERR_HANDLE = 3;	// Invalid handle
  public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
  public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode
  public static final int CS_ERR_OPTION = 6;  // Invalid/unsupported option: cs_option()
  public static final int CS_ERR_DETAIL = 7;  // Invalid/unsupported option: cs_option()
  public static final int CS_ERR_MEMSETUP = 8;
  public static final int CS_ERR_VERSION = 9;  // Unsupported version (bindings)
  public static final int CS_ERR_DIET = 10;  // Information irrelevant in diet engine
  public static final int CS_ERR_SKIPDATA = 11;  // Access irrelevant data for "data" instruction in SKIPDATA mode
  public static final int CS_ERR_X86_ATT = 12;  // X86 AT&T syntax is unsupported (opt-out at compile time)
  public static final int CS_ERR_X86_INTEL = 13;  // X86 Intel syntax is unsupported (opt-out at compile time)
  public static final int CS_ERR_X86_MASM = 14;  // X86 Masm syntax is unsupported (opt-out at compile time)

  // Capstone option type
  public static final int CS_OPT_INVALID = 0; // No option specified
  public static final int CS_OPT_SYNTAX = 1;	    // Assembly output syntax
  public static final int CS_OPT_DETAIL = 2;	    // Break down instruction structure into details
  public static final int CS_OPT_MODE = 3;	    // Change engine's mode at run-time
  public static final int CS_OPT_MEM = 4;	    // User-defined dynamic memory related functions
  public static final int CS_OPT_SKIPDATA = 5; // Skip data when disassembling. Then engine is in SKIPDATA mode.
  public static final int CS_OPT_SKIPDATA_SETUP = 6; // Setup user-defined function for SKIPDATA option
  public static final int CS_OPT_MNEMONIC = 7;       // Customize instruction mnemonic
  public static final int CS_OPT_UNSIGNED = 8;       // print immediate operands in unsigned form
  public static final int CS_OPT_ONLY_OFFSET_BRANCH = 9; // ARM, PPC, AArch64: Don't add the branch immediate value to the PC.
  public static final int CS_OPT_LITBASE = 10; // Xtensa, set the LITBASE value. LITBASE is set to 0 by default.

  // Capstone option value
  public static final int CS_OPT_OFF = 0;  // Turn OFF an option - default for CS_OPT_DETAIL, CS_OPT_SKIPDATA, CS_OPT_UNSIGNED.
  public static final int CS_OPT_ON = 1 << 0; // Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
  public static final int CS_OPT_SYNTAX_DEFAULT = 1 << 1; // Default asm syntax (CS_OPT_SYNTAX).
  public static final int CS_OPT_SYNTAX_INTEL = 1 << 2; // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
  public static final int CS_OPT_SYNTAX_ATT = 1 << 3;   // X86 ATT asm syntax (CS_OPT_SYNTAX).
  public static final int CS_OPT_SYNTAX_NOREGNAME = 1 << 4; // Prints register name with only number (CS_OPT_SYNTAX)
  public static final int CS_OPT_SYNTAX_MASM = 1 << 5; // X86 Intel Masm syntax (CS_OPT_SYNTAX).
  public static final int CS_OPT_SYNTAX_MOTOROLA = 1 << 6; // MOS65XX use $ as hex prefix
  public static final int CS_OPT_SYNTAX_CS_REG_ALIAS = 1 << 7; // Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)
  public static final int CS_OPT_SYNTAX_PERCENT = 1 << 8; // Prints the % in front of PPC registers.
  public static final int CS_OPT_SYNTAX_NO_DOLLAR = 1 << 9; // Does not print the $ in front of Mips, LoongArch registers.
  public static final int CS_OPT_SYNTAX_NO_ALIAS_TEXT = 1 << 10; // Does not print an instruction's alias test if the instruction is an alias
  public static final int CS_OPT_SYNTAX_NO_ALIAS_TEXT_COMPRESSED = 1 << 11; // Like the one above it, but only supresses compressed instruction aliases
  public static final int CS_OPT_DETAIL_REAL = 1 << 1; // If enabled, always sets the real instruction detail. Even if the instruction is an alias.

  // Common instruction operand types - to be consistent across all architectures.
  public static final int CS_OP_INVALID = 0; // uninitialized/invalid operand.
  public static final int CS_OP_REG = 1; // Register operand.
  public static final int CS_OP_IMM = 2; // Immediate operand.
  public static final int CS_OP_FP  = 3; // Floating-Point operand.
  public static final int CS_OP_PRED  = 4; // Predicate operand.
  public static final int CS_OP_RESERVED_5 = 5;
  public static final int CS_OP_RESERVED_6 = 6;
  public static final int CS_OP_RESERVED_7 = 7;
  public static final int CS_OP_RESERVED_8 = 8;
  public static final int CS_OP_RESERVED_9 = 9;
  public static final int CS_OP_RESERVED_10 = 10;
  public static final int CS_OP_RESERVED_11 = 11;
  public static final int CS_OP_RESERVED_12 = 12;
  public static final int CS_OP_RESERVED_13 = 13;
  public static final int CS_OP_RESERVED_14 = 14;
  public static final int CS_OP_RESERVED_15 = 15;
  public static final int CS_OP_SPECIAL = 0x10; // Special operands from archs
  public static final int CS_OP_BOUND = 0x40; // Operand is associated with a previous operand. Used by AArch64 for SME operands.
  public static final int CS_OP_MEM = 0x80; // Memory operand. Can be ORed with another operand type.
  public static final int CS_OP_MEM_REG = CS_OP_MEM | CS_OP_REG; // Memory referencing register operand.
  public static final int CS_OP_MEM_IMM = CS_OP_MEM | CS_OP_IMM; // Memory referencing immediate operand.

  // Common instruction operand access types - to be consistent across all architectures.
  // It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
  public static final int CS_AC_INVALID = 0; // Uninitialized/invalid access type.
  public static final int CS_AC_READ = 1 << 0; // Operand read from memory or register.
  public static final int CS_AC_WRITE = 1 << 1; // Operand write to memory or register.
  public static final int CS_AC_READ_WRITE = CS_AC_READ | CS_AC_WRITE; // Operand reads and writes from/to memory or register.

  // Common instruction groups - to be consistent across all architectures.
  public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
  public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
  public static final int CS_GRP_CALL    = 2;  // all call instructions
  public static final int CS_GRP_RET     = 3;  // all return instructions
  public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
  public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
  public static final int CS_GRP_PRIVILEGE = 6;  // all privileged instructions
  public static final int CS_GRP_BRANCH_RELATIVE = 7; // all relative branching instructions

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
    cs = (CS)Native.load("capstone", CS.class);
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
    int result = cs.cs_option(ns.csh, CS_OPT_SYNTAX, new NativeLong(syntax));
    if (result != CS_ERR_OK) {
      throw new RuntimeException(String.format("ERROR: Failed to set syntax to %d: %s", syntax, strerror(result)));
    }
    this.syntax = syntax;
  }

  // set detail option at run-time
  public void setDetail(int opt) {
    int result = cs.cs_option(ns.csh, CS_OPT_DETAIL, new NativeLong(opt));
    if (result != CS_ERR_OK) {
      throw new RuntimeException(String.format("ERROR: Failed to set detail to %d: %s", opt, strerror(result)));
    }
    this.detail = opt;
  }

  // set mode option at run-time
  public void setMode(int opt) {
    int result = cs.cs_option(ns.csh, CS_OPT_MODE, new NativeLong(opt));
    if (result != CS_ERR_OK) {
      throw new RuntimeException(String.format("ERROR: Failed to set mode to %d: %s", opt, strerror(result)));
    }
    this.mode = opt;
  }

  // Set any CS_OPT_* option at run-time
  public void setOption(int type, int opt) {
    if (type == CS_OPT_SYNTAX) {
      setSyntax(opt);
      return;
    }
    if (type == CS_OPT_DETAIL) {
      setDetail(opt);
      return;
    }
    if (type == CS_OPT_MODE) {
      setMode(opt);
      return;
    }
    int result = cs.cs_option(ns.csh, type, new NativeLong(opt));
    if (result != CS_ERR_OK) {
      throw new RuntimeException(String.format("ERROR: Failed to set option %d to %d: %s", type, opt, strerror(result)));
    }
  }

  // destructor automatically called at destroyed time.
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
