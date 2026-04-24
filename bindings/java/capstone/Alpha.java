// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Alpha_const.*;

public class Alpha {

  public static class MemType extends Structure {
    public byte base;
    public int disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public int access;

    public void read() {
      readField("type");
      if (type == ALPHA_OP_REG || type == ALPHA_OP_IMM)
        value.setType(Integer.TYPE);
      else if (type == ALPHA_OP_INVALID)
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
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[3];
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

    public OpInfo(UnionOpInfo op_info) {
      op = op_info.op;
    }
  }
}
