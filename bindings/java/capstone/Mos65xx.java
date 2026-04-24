// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Mos65xx_const.*;

public class Mos65xx {

  public static class OpValue extends Union {
    public int reg;
    public short imm;
    public int mem;
  }

  public static class Operand extends Structure {
    public byte type;
    public OpValue value;

    public void read() {
      readField("type");
      if (getType() == MOS65XX_OP_MEM || getType() == MOS65XX_OP_REG)
        value.setType(Integer.TYPE);
      else if (getType() == MOS65XX_OP_IMM)
        value.setType(Short.TYPE);
      else if (getType() == MOS65XX_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value");
    }

    public int getType() {
      return type & 0xFF;
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int am;
    public byte modifies_flags;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[3];
    }

    public void read() {
      readField("am");
      readField("modifies_flags");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("am", "modifies_flags", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int am;
    public byte modifies_flags;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      am = op_info.am;
      modifies_flags = op_info.modifies_flags;
      op = op_info.op;
    }
  }
}
