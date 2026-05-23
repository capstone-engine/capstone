// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import capstone.Capstone;

import java.util.List;
import java.util.Arrays;

import static capstone.M68k_const.*;

public class M68k {

  public static class MemType extends Structure {
    public int base_reg;
    public int index_reg;
    public int in_base_reg;
    public int in_disp;
    public int out_disp;
    public short disp;
    public byte scale;
    public byte bitfield;
    public byte width;
    public byte offset;
    public byte index_size;
    public byte in_disp_size;
    public byte out_disp_size;
    public byte disp_size;


    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base_reg", "index_reg", "in_base_reg", "in_disp", "out_disp", "disp", "scale", "bitfield", "width", "offset", "index_size", "in_disp_size", "out_disp_size", "disp_size");
    }
  }

  public static class RegPair extends Structure {
    public int reg_0;
    public int reg_1;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("reg_0", "reg_1");
    }
  }

  public static class OpValue extends Union {
    public long imm;
    public double dimm;
    public float simm;
    public int reg;
    public RegPair reg_pair;
  }

  public static class BrDisp extends Structure {
    public int disp;
    public byte disp_size;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("disp", "disp_size");
    }
  }

  public static class Operand extends Structure {
    public OpValue value;
    public MemType mem;
    public BrDisp br_disp;
    public int register_bits;
    public int type;
    public int address_mode;

    public void read() {
      readField("type");
      if (type == M68K_OP_MEM)
        readField("mem");
      else if (type == M68K_OP_REG_BITS)
        readField("register_bits");
      else if (type == M68K_OP_BR_DISP)
        readField("br_disp");
      else {
        if (type == M68K_OP_REG)
            value.setType(Integer.TYPE);
        else if (type == M68K_OP_IMM)
            value.setType(Long.TYPE);
        else if (type == M68K_OP_FP_SINGLE)
            value.setType(Float.TYPE);
        else if (type == M68K_OP_FP_DOUBLE)
            value.setType(Double.TYPE);
        else if (type == M68K_OP_REG_PAIR)
            value.setType(RegPair.class);
        else if (type == M68K_OP_INVALID)
            return;
        readField("value");
      }
      readField("address_mode");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("value", "mem", "br_disp", "register_bits", "type", "address_mode");
    }
  }

  public static class OpSize extends Structure {
    public int type;
    public int size;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "size");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public Operand [] op;
    public OpSize op_size;
    public byte op_count;


    public UnionOpInfo() {
        op = new Operand[4];
    }

    public void read() {
      readField("op_size");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("op", "op_size", "op_count");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public OpSize op_size;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      op_size = op_info.op_size;
      op = op_info.op;
    }
  }
}
