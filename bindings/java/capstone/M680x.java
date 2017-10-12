// Capstone Java binding
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.M680x_const.*;

public class M680x {

  public static class OpIndexed extends Structure {
    public int base_reg;
    public int offset_reg;
    public short offset;
    public short offset_addr;
    public byte offset_bits;
    public byte inc_dec;
    public byte flags;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base_reg", "offset_reg", "offset", "offset_addr", "offset_bits", "inc_dec", "flags");
    }
  }

  public static class OpRelative extends Structure {
    public short address;
    public short offset;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("address", "offset");
    }
  }

  public static class OpExtended extends Structure {
    public short address;
    public byte indirect;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("address", "indirect");
    }
  }

  public static class OpValue extends Union {
    public int imm;
    public int reg;
    public OpIndexed idx;
    public OpRelative rel;
    public OpExtended ext;
    public byte direct_addr;
    public byte const_val;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("imm", "reg", "idx", "rel", "ext", "direct_addr", "const_val");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte size;
    public byte access;

    public void read() {
      readField("type");
      if (type == M680X_OP_IMMEDIATE)
        value.setType(Integer.TYPE);
      if (type == M680X_OP_REGISTER)
        value.setType(Integer.TYPE);
      if (type == M680X_OP_INDEXED)
        value.setType(OpIndexed.class);
      if (type == M680X_OP_RELATIVE)
        value.setType(OpRelative.class);
      if (type == M680X_OP_EXTENDED)
        value.setType(OpExtended.class);
      if (type == M680X_OP_DIRECT)
        value.setType(Integer.TYPE);
      if (type == M680X_OP_INVALID)
        return;
      readField("value");
      readField("size");
      readField("access");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value", "size", "access");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte flags;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[9];
    }

    public void read() {
      readField("flags");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("flags", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public byte flags;
    public Operand [] op = null;

    public OpInfo(UnionOpInfo op_info) {
      flags = op_info.flags;
      op = op_info.op;
    }
  }
}
