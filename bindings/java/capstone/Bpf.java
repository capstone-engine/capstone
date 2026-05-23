// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Bpf_const.*;

public class Bpf {

  public static class MemType extends Structure {
    public int base;
    public int disp;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public int off;
    public MemType mem;
    public int mmem;
    public int msh;
    public int ext;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte is_signed;
    public byte is_pkt;
    public int access;

    public void read() {
      readField("type");
      if (type == BPF_OP_MEM)
        value.setType(MemType.class);
      else if (type == BPF_OP_REG || type == BPF_OP_OFF || type == BPF_OP_MMEM || type == BPF_OP_MSH || type == BPF_OP_EXT)
        value.setType(Integer.TYPE);
      else if (type == BPF_OP_IMM)
        value.setType(Long.TYPE);
      else if (type == BPF_OP_INVALID)
        return;
      readField("value");
      readField("is_signed");
      readField("is_pkt");
      readField("access");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "is_signed", "is_pkt", "access");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[4];
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
