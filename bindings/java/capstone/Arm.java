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

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "scale", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public double fp;
    public MemType mem;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem");
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
    public OpShift shift;
    public int type;
    public OpValue value;

    public void read() {
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
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("shift", "type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public byte _update_flags;
    public byte _writeback;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[36];
    }

    public void read() {
      readField("cc");
      readField("_update_flags");
      readField("_writeback");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("cc", "_update_flags", "_writeback", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public boolean updateFlags;
    public boolean writeback;
    public Operand [] op = null;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      updateFlags = (op_info._update_flags > 0);
      writeback = (op_info._writeback > 0);
      op = op_info.op;
    }
  }
}
