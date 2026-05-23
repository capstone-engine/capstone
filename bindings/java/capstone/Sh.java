// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Sh_const.*;

public class Sh {

  public static class MemType extends Structure {
    public int address;
    public int reg;
    public int disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("address", "reg", "disp");
    }
  }

  public static class OpDsp extends Structure {
    public int insn;
    public int operand[];
    public int r[];
    public int cc;
    public byte imm;
    public int size;

    public OpDsp() {
      operand = new int[2];
      r = new int[6];
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("insn", "operand", "r", "cc", "imm", "size");
    }
  }

  public static class OpValue extends Union {
    public long imm;
    public int reg;
    public MemType mem;
    public OpDsp dsp;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == SH_OP_MEM)
        value.setType(MemType.class);
      if (type == SH_OP_IMM || type == SH_OP_REG)
        value.setType(Integer.TYPE);

      // TODO: value.setType(OpDsp.class)
      if (type == SH_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int insn;
    public byte size;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[3];
    }

    public void read() {
      readField("insn");
      readField("size");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("insn", "size", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int insn;
    public byte size;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      insn = op_info.insn;
      size = op_info.size;
      op = op_info.op;
    }
  }
}
