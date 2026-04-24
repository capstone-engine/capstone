// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Xtensa_const.*;

public class Xtensa {

  public static class MemType extends Structure {
    public byte base;
    public byte disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public byte reg;
    public int imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public byte type;
    public byte access;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == XTENSA_OP_MEM)
        value.setType(MemType.class);
      else if (type == XTENSA_OP_REG)
        value.setType(Byte.TYPE);
      else if (type == XTENSA_OP_IMM)
        value.setType(Integer.TYPE);
      else if (type == XTENSA_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "access", "value");
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
