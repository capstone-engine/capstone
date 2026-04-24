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
    public int base;
    public int index;
    public int disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "index", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;
    public int membar_tag;
    public int asi;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte access;

    public void read() {
      readField("type");
      if (type == SPARC_OP_MEM)
        value.setType(MemType.class);
      if (type == SPARC_OP_IMM || type == SPARC_OP_REG)
        value.setType(Integer.TYPE);
      if (type == SPARC_OP_INVALID)
        return;
      readField("value");
      readField("access");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "access");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public int cc_field;
    public int hint;
    public int format;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[6];
    }

    public void read() {
      readField("cc");
      readField("cc_field");
      readField("hint");
      readField("format");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("cc", "cc_field", "hint", "format", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public int cc_field;
    public int hint;
    public int format;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      cc_field = op_info.cc_field;
      hint = op_info.hint;
      format = op_info.format;
      op = op_info.op;
    }
  }
}
