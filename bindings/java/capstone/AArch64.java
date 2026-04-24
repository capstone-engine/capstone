// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.AArch64_const.*;

public class AArch64 {

  public static class MemType extends Structure {
    public int base;
    public int index;
    public int disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "index", "disp");
    }
  }

  public static class ImmRange extends Structure {
    public byte first;
    public byte offset;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("first", "offset");
    }
  }

  public static class SliceOffsetUnion extends Union {
    public short imm;
    public ImmRange imm_range;
  }

  public static class OpSME extends Structure {
    public int type;
    public int tile;
    public int slice_reg;
    public SliceOffsetUnion slice_offset;
    public byte has_range_offset;
    public byte is_vertical;

    @Override
    public void read() {
        readField("type");
        readField("tile");
        readField("slice_reg");
        readField("has_range_offset");
        if (has_range_offset != 0)
          slice_offset.setType(ImmRange.class);
        else
          slice_offset.setType(Short.TYPE);
        readField("slice_offset");
        readField("is_vertical");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "tile", "slice_reg", "slice_offset", "has_range_offset", "is_vertical");
    }
  }

  public static class OpPred extends Structure {
    public int reg;
    public int vec_select;
    public int imm_index;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "vec_select", "imm_index");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public ImmRange imm_range;
    public double fp;
    public MemType mem;
    public OpSME sme;
    public OpPred pred;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "imm", "imm_range", "fp", "mem", "sme", "pred");
    }
  }

  public static class SysOpSysReg extends Union {
    public int sysreg;
    public int tlbi;
    public int ic;
    public int raw_val;
  }

  public static class SysOpSysImm extends Union {
    public int dbnxs;
    public int exactfpimm;
    public int raw_val;
  }

  public static class SysOpSysAlias extends Union {
    public int svcr;
    public int at;
    public int db;
    public int dc;
    public int isb;
    public int tsb;
    public int prfm;
    public int sveprfm;
    public int rprfm;
    public int pstateimm0_15;
    public int pstateimm0_1;
    public int psb;
    public int bti;
    public int svepredpat;
    public int sveveclenspecifier;
    public int raw_val;
  }

  public static class SysOp extends Structure {
    public SysOpSysReg reg;
    public SysOpSysImm imm;
    public SysOpSysAlias alias;
    public int sub_type;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg","imm","alias","sub_type");
    }
  }

  public static class OpShift extends Structure {
    public int type;
    public int value;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type","value");
    }
  }

  public static class Operand extends Structure {
    public int vector_index;
    public int vas;
    public OpShift shift;
    public int ext;
    public int type;
    public byte is_vreg;
    public OpValue value;
    public SysOp sysop;
    public int access;
    public byte is_list_member;

    public void read() {
      readField("type");
      if (type == AARCH64_OP_INVALID)
        return;
      if (type == AARCH64_OP_MEM)
        value.setType(MemType.class);
      else if (type == AARCH64_OP_FP)
        value.setType(Double.TYPE);
      //else if (type == AARCH64_OP_IMM || type == AARCH64_OP_CIMM || type == AARCH64_OP_REG || type == AARCH64_OP_REG_MRS || type == AARCH64_OP_REG_MSR || type == AARCH64_OP_PSTATE || type == AARCH64_OP_SYS || type == AARCH64_OP_PREFETCH || type == AARCH64_OP_BARRIER)
      //  value.setType(Integer.TYPE);
      else if (type == AARCH64_OP_SME)
        value.setType(OpSME.class);
      else if (type == AARCH64_OP_IMM_RANGE)
        value.setType(ImmRange.class);
      else if (type == AARCH64_OP_PRED)
        value.setType(OpPred.class);
      else
        value.setType(Integer.TYPE);
      readField("vector_index");
      readField("vas");
      readField("shift");
      readField("ext");
      readField("is_vreg");
      readField("value");
      readField("sysop");
      readField("access");
      readField("is_list_member");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("vector_index", "vas", "shift", "ext", "type", "is_vreg", "value", "sysop", "access", "is_list_member");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public byte _update_flags;
    public byte _post_index;
    public byte _is_doing_sme;
    public byte op_count;

    public Operand [] operands;

    public UnionOpInfo() {
      operands = new Operand[16];
    }

    public void read() {
      readField("cc");
      readField("_update_flags");
      readField("_post_index");
      readField("_is_doing_sme");
      readField("op_count");
      operands = new Operand[op_count];
      if (op_count != 0)
        readField("operands");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("cc", "_update_flags", "_post_index", "_is_doing_sme", "op_count", "operands");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public boolean updateFlags;
    public boolean postIndex;
    public boolean isDoingSme;
    public Operand [] operands = null;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      updateFlags = op_info._update_flags != 0;
      postIndex = op_info._post_index != 0;
      isDoingSme = op_info._is_doing_sme != 0;
      operands = op_info.operands;
    }
  }
}
