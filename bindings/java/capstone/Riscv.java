// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Riscv_const.*;

public class Riscv {

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
    public double dimm;
    public MemType mem;
    public short csr;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public int access;

    public void read() {
      readField("type");
      if (type == RISCV_OP_MEM)
        value.setType(MemType.class);
      else if (type == RISCV_OP_REG)
        value.setType(Integer.TYPE);
      else if (type == RISCV_OP_IMM)
        value.setType(Long.TYPE);
      else if (type == RISCV_OP_INVALID)
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
    public byte need_effective_addr;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("need_effective_addr");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("need_effective_addr", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public boolean need_effective_addr;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      need_effective_addr = op_info.need_effective_addr > 0;
      op = op_info.op;
    }
  }
}
