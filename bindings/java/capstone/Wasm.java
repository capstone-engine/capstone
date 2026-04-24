// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import capstone.Capstone;

import java.util.List;
import java.util.Arrays;

import static capstone.Wasm_const.*;

public class Wasm {

  public static class BrTable extends Structure {
    public int length;
    public long address;
    public int default_target;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("length", "address", "default_target");
    }
  }

  public static class OpValue extends Union {
    public byte int7;
    public int varuint32;
    public long varuint64;
    public int uint32;
    public long uint64;
    public int immediate[];
    public BrTable brtable;

    public OpValue() {
      immediate = new int[2];
    }
  }

  public static class Operand extends Structure {
    public int type;
    public int size;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == WASM_OP_INT7)
        value.setType(Byte.TYPE);
      else if (type == WASM_OP_VARUINT64 || type == WASM_OP_UINT64)
        value.setType(Long.TYPE);
      else if (type == WASM_OP_VARUINT32 || type == WASM_OP_UINT32 || type == WASM_OP_IMM)
        value.setType(Integer.TYPE);
      else if (type == WASM_OP_BRTABLE)
        value.setType(BrTable.class);
      else if (type == WASM_OP_INVALID)
        return;
      readField("value");
      readField("size");
    }
    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "size", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte op_count;
    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[2];
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

    public OpInfo(UnionOpInfo e) {
      op = e.op;
    }
  }
}
