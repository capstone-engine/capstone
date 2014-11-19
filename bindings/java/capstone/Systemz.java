// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Sysz_const.*;

public class Systemz {

  public static class MemType extends Structure {
    public byte base;
    public byte index;
    public long length;
    public long disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "length", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == SYSZ_OP_MEM)
        value.setType(MemType.class);
      if (type == SYSZ_OP_IMM)
        value.setType(Long.TYPE);
      if (type == SYSZ_OP_REG || type == SYSZ_OP_ACREG)
        value.setType(Integer.TYPE);
      if (type == SYSZ_OP_INVALID)
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
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[6];
    }

    public void read() {
      readField("cc");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("cc", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      op = op_info.op;
    }
  }
}
