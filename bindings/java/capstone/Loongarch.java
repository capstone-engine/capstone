// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import capstone.Capstone;

import java.util.List;
import java.util.Arrays;

import static capstone.Loongarch_const.*;

public class Loongarch {

  public static class MemType extends Structure {
    public int base;
    public int index;
    public long disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "index", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public byte type;
    public OpValue value;
    public byte access;

    public void read() {
      readField("type");
      if (getType() == LOONGARCH_OP_MEM)
        value.setType(MemType.class);
      else if (getType() == LOONGARCH_OP_REG)
        value.setType(Integer.TYPE);
      else if (getType() == LOONGARCH_OP_IMM)
        value.setType(Long.TYPE);
      else if (getType() == LOONGARCH_OP_INVALID)
        return;
      readField("value");
      readField("access");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "access");
    }

    public int getType() {
      return type & 0xFF;
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int format;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("format");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("format", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int format;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      format = op_info.format;
      op = op_info.op;
    }
  }
}
