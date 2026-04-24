// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Tricore_const.*;

public class Tricore {

  public static class MemType extends Structure {
    public byte base;
    public long disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg", "imm", "mem");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public int access;

    public void read() {
      readField("type");
      if (type == TRICORE_OP_MEM)
        value.setType(MemType.class);
      if (type == TRICORE_OP_IMM)
        value.setType(Long.TYPE);
      if (type == TRICORE_OP_REG)
        value.setType(Integer.TYPE);
      if (type == TRICORE_OP_INVALID)
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
    public byte update_flags;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("update_flags");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("op_count", "op", "update_flags");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public boolean update_flags;
    public Operand [] op;

    public OpInfo(UnionOpInfo e) {
      update_flags = e.update_flags > 0;
      op = e.op;
    }
  }
}
