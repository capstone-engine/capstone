// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Mips_const.*;

public class Mips {

  public static class MemType extends Structure {
    public int base;
    public long disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public long uimm;  // TODO: uint64
    public MemType mem;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte is_reglist;
    public byte is_unsigned;
    public int access;

    public void read() {
      readField("type");
      if (type == MIPS_OP_MEM)
        value.setType(MemType.class);
      if (type == MIPS_OP_IMM)
        value.setType(Long.TYPE);
      if (type == MIPS_OP_REG)
        value.setType(Integer.TYPE);
      if (type == MIPS_OP_INVALID)
        return;
      readField("value");
      readField("is_reglist");
      readField("is_unsigned");
      readField("access");
    }
    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "is_reglist", "is_unsigned", "access");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte op_count;
    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[16];
    }

    public void read() {
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {

    public Operand [] op;

    public OpInfo(UnionOpInfo e) {
      op = e.op;
    }
  }
}
