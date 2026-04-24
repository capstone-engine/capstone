// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Systemz_const.*;

public class Systemz {

  public static class MemType extends Structure {
    public int am;
    public byte base;
    public byte index;
    public long length;
    public long disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("am", "base", "index", "length", "disp");
    }

    public int getBase() {
      return base & 0xFF;
    }

    public int getIndex() {
      return index & 0xFF;
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
    public int access;
    public byte imm_width;

    public void read() {
      readField("type");
      if (type == SYSTEMZ_OP_MEM)
        value.setType(MemType.class);
      else if (type == SYSTEMZ_OP_IMM)
        value.setType(Long.TYPE);
      else if (type == SYSTEMZ_OP_REG)
        value.setType(Integer.TYPE);
      else if (type == SYSTEMZ_OP_INVALID)
        return;
      readField("value");
      readField("access");
      readField("imm_width");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "access", "imm_width");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public int format;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[6];
    }

    public void read() {
      readField("cc");
      readField("format");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("cc", "format", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public int format;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      format = op_info.format;
      op = op_info.op;
    }
  }
}
