// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Arm_const.*;

public class Arm {

  public static class MemType extends Structure {
    public int base;
    public int index;
    public int scale;
    public int disp;
    public int align;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "index", "scale", "disp", "align");
    }
  }

  public static class SysopReg extends Union {
    public int mclasssysreg;
    public int bankedreg;
    public int raw_val;
  }

  public static class SysOpType extends Structure {
    public SysopReg reg; ///< The system or banked register.
    public int psr_bits; ///< SPSR/CPSR bits.
    public short sysm; ///< Raw SYSm field. UINT16_MAX if unset.
    public byte msr_mask; ///< Mask of MSR instructions. UINT8_MAX if invalid.

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "psr_bits", "sysm", "msr_mask");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public SysOpType sysop;
    public long imm;
    public int pred;
    public double fp;
    public MemType mem;
    public int setend;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "sysop", "imm", "pred", "fp", "mem", "setend");
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
    public OpShift shift;
    public int type;
    public OpValue value;
    public byte subtracted;
    public int access;
    public byte neon_lane;

    public void read() {
      readField("vector_index");
      readField("shift");
      readField("type");
      if (type == ARM_OP_MEM)
        value.setType(MemType.class);
      else if (type == ARM_OP_FP)
        value.setType(Double.TYPE);
      else if (type == ARM_OP_PIMM || type == ARM_OP_IMM || type == ARM_OP_CIMM)
        value.setType(Long.TYPE);
      else if (type == ARM_OP_REG || type == ARM_OP_SETEND || type == ARM_OP_PRED)
        value.setType(Integer.TYPE);
      else if (type == ARM_OP_SYSREG || type == ARM_OP_BANKEDREG || type == ARM_OP_SPSR || type == ARM_OP_CPSR || type == ARM_OP_SYSM)
        value.setType(SysOpType.class);
      else if (type == ARM_OP_INVALID)
        return;
      readField("value");
      readField("subtracted");
      readField("access");
      readField("neon_lane");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("vector_index", "shift", "type", "value", "subtracted", "access", "neon_lane");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte usermode;
    public int vector_size;
    public int vector_data;
    public int cps_mode;
    public int cps_flag;
    public int cc;
    public int vcc;
    public byte update_flags;
    public byte post_index;
    public int mem_barrier;
    public byte pred_mask;
    public byte op_count;

    public Operand [] operands;

    public UnionOpInfo() {
      operands = new Operand[36];
    }

    public void read() {
      readField("usermode");
      readField("vector_size");
      readField("vector_data");
      readField("cps_mode");
      readField("cps_flag");
      readField("cc");
      readField("update_flags");
      readField("post_index");
      readField("mem_barrier");
      readField("pred_mask");
      readField("op_count");
      operands = new Operand[op_count];
      if (op_count != 0)
        readField("operands");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("usermode", "vector_size", "vector_data",
          "cps_mode", "cps_flag", "cc", "vcc", "update_flags", "post_index", "mem_barrier", "pred_mask", "op_count", "operands");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public boolean usermode;
    public int vectorSize;
    public int vectorData;
    public int cpsMode;
    public int cpsFlag;
    public int cc;
    public int vcc;
    public boolean updateFlags;
    public boolean postIndex;
    public int memBarrier;
    public byte predMask;
    public Operand [] operands = null;

    public OpInfo(UnionOpInfo op_info) {
      usermode = op_info.usermode > 0;
      vectorSize = op_info.vector_size;
      vectorData = op_info.vector_data;
      cpsMode = op_info.cps_mode;
      cpsFlag = op_info.cps_flag;
      cc = op_info.cc;
      vcc = op_info.vcc;
      updateFlags = op_info.update_flags > 0;
      postIndex = op_info.post_index > 0;
      memBarrier = op_info.mem_barrier;
      predMask = op_info.pred_mask;
      operands = op_info.operands;
    }
  }
}
