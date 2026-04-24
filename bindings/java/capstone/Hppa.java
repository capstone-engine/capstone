// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Hppa_const.*;

public class Hppa {

  public static class MemType extends Structure {
    public int base;
    public int space;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "space");
    }
  }

  public static class ModifierValue extends Union {
    public String str_mod;
    public int int_mod;
  }

  public static class Modifier extends Structure {
    public int type;
    public ModifierValue value;

    public void read() {
      readField("type");
      if (type == HPPA_MOD_STR)
        value.setType(String.class);
      else if (type == HPPA_MOD_INT)
        value.setType(Integer.TYPE);
      readField("value");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class Ext extends Structure {
    public Modifier modifiers[];
    public byte mod_num;
    public byte b_writable;
    public byte cmplt;

    public Ext() {
      modifiers = new Modifier[5];
    }

    public void read() {
      readField("mod_num");
      modifiers = new Modifier[mod_num];
      if (mod_num != 0)
        readField("modifiers");
      readField("b_writable");
      readField("cmplt");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("modifiers", "mod_num", "b_writable", "cmplt");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public byte type;  // JNA doesn't support unsigned types, so we read the byte and convert to int ourselves
    public OpValue value;
    public int access;

    public void read() {
      readField("type");
      if (getType() == HPPA_OP_MEM)
        value.setType(MemType.class);
      else if (getType() == HPPA_OP_REG)
        value.setType(Integer.TYPE);
      else if (getType() == HPPA_OP_IMM)
        value.setType(Long.TYPE);
      // TODO: value.setType(Ext.class)
      else if (getType() == HPPA_OP_INVALID)
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
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[5];
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
