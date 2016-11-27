// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

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
    public int lshift;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "scale", "disp", "lshift");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public double fp;
    public MemType mem;
    public int setend;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem", "setend");
    }
  }

  public static class OpShift extends Structure {
    public int type;
    public int value;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type","value");
    }
  }

  public static class Operand extends Structure {
    public int vector_index;
    public OpShift shift;
    public int type;
    public OpValue value;
    public boolean subtracted;
    public byte access;
    public byte neon_lane;

    public void read() {
      readField("vector_index");
      readField("type");
      if (type == ARM_OP_MEM)
        value.setType(MemType.class);
      if (type == ARM_OP_FP)
        value.setType(Double.TYPE);
      if (type == ARM_OP_PIMM || type == ARM_OP_IMM || type == ARM_OP_CIMM)
        value.setType(Integer.TYPE);
      if (type == ARM_OP_REG)
        value.setType(Integer.TYPE);
      if (type == ARM_OP_INVALID)
        return;
      readField("value");
      readField("shift");
      readField("subtracted");
      readField("access");
      readField("neon_lane");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("vector_index", "shift", "type", "value", "subtracted", "access", "neon_lane");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public boolean usermode;
    public int vector_size;
    public int vector_data;
    public int cps_mode;
    public int cps_flag;
    public int cc;
    public byte update_flags;
    public byte writeback;
    public int mem_barrier;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[36];
    }

    public void read() {
      readField("usermode");
      readField("vector_size");
      readField("vector_data");
      readField("cps_mode");
      readField("cps_flag");
      readField("cc");
      readField("update_flags");
      readField("writeback");
      readField("mem_barrier");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("usermode", "vector_size", "vector_data",
          "cps_mode", "cps_flag", "cc", "update_flags", "writeback", "mem_barrier", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public boolean usermode;
    public int vectorSize;
    public int vectorData;
    public int cpsMode;
    public int cpsFlag;
    public int cc;
    public boolean updateFlags;
    public boolean writeback;
    public int memBarrier;
    public Operand [] op = null;

    public OpInfo(UnionOpInfo op_info) {
      usermode = op_info.usermode;
      vectorSize = op_info.vector_size;
      vectorData = op_info.vector_data;
      cpsMode = op_info.cps_mode;
      cpsFlag = op_info.cps_flag;
      cc = op_info.cc;
      updateFlags = (op_info.update_flags > 0);
      writeback = (op_info.writeback > 0);
      memBarrier = op_info.mem_barrier;
      op = op_info.op;
    }
  }
}
