// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Sparc_const.*;

public class Sparc {

  public static class MemType extends Structure {
    public byte base;
    public byte index;
    public int disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "disp");
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
      if (type == SPARC_OP_MEM)
        value.setType(MemType.class);
      if (type == SPARC_OP_IMM || type == SPARC_OP_REG)
        value.setType(Integer.TYPE);
      if (type == SPARC_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public int hint;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[4];
    }

    public void read() {
      readField("cc");
      readField("hint");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("cc", "hint", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public int hint;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      hint = op_info.hint;
      op = op_info.op;
    }
  }
}
