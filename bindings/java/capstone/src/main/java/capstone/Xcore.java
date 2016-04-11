// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Xcore_const.*;

public class Xcore {

  public static class MemType extends Structure {
    public byte base;
    public byte index;
    public int disp;
    public int direct;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "disp", "direct");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == XCORE_OP_MEM)
        value.setType(MemType.class);
      if (type == XCORE_OP_IMM || type == XCORE_OP_REG)
        value.setType(Integer.TYPE);
      if (type == XCORE_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte op_count;
    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      op = op_info.op;
    }
  }
}
