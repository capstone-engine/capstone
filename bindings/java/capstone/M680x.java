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
    public byte indirect;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base_reg", "offset_reg", "offset", "offset_addr", "offset_bits", "inc_dec", "indirect");
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

    @Override
    public List getFieldOrder() {
      return Arrays.asList("imm", "reg", "idx", "rel", "ext", "direct_addr");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public byte size;

    public void read() {
      readField("type");
      if (type == M680X_OP_IMMEDIATE)
        value.setType(Integer.TYPE);
      if (type == M680X_OP_REGISTER)
        value.setType(Integer.TYPE);
      if (type == M680X_OP_INDEXED_00 || type == M680X_OP_INDEXED_09)
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
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value", "size");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int address_mode;
    public byte flags;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[9];
    }

    public void read() {
      readField("address_mode");
      readField("flags");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("address_mode", "flags", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int addressMode;
    public byte flags;
    public Operand [] op = null;

    public OpInfo(UnionOpInfo op_info) {
      addressMode = op_info.address_mode;
      flags = op_info.flags;
      op = op_info.op;
    }
  }
}
