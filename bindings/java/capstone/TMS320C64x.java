// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.TMS320C64x_const.*;

public class TMS320C64x {

  public static class MemType extends Structure {
    public int base;
    public int disp;
    public int unit;
    public int scaled;
    public int disptype;
    public int direction;
    public int modify;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp", "unit", "scaled", "disptype", "direction", "modify");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public MemType mem;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "imm", "mem");
    }
  }

  public static class Condition extends Structure {
    public int reg;
    public int zero;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "zero");
    }
  }

  public static class FunctionalUnit extends Structure {
    public int unit;
    public int side;
    public int crosspath;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("unit", "side", "crosspath");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == TMS320C64X_OP_MEM)
        value.setType(MemType.class);
      if (type == TMS320C64X_OP_REG || type == TMS320C64X_OP_IMM)
        value.setType(Integer.TYPE);
      if (type == TMS320C64X_OP_INVALID)
        return;
      readField("value");
    }
    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte op_count;
    public Operand [] op;
    public Condition condition;
    public FunctionalUnit funit;
    public int parallel;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("condition");
      readField("funit");
      readField("parallel");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("op_count", "op", "condition", "funit", "parallel");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public Condition condition;
    public FunctionalUnit funit;
    public int parallel;
    public Operand [] op;

    public OpInfo(UnionOpInfo e) {
      condition = e.condition;
      funit = e.funit;
      parallel = e.parallel;
      op = e.op;
    }
  }
}
