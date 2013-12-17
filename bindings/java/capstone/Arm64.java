// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.Union;
import com.sun.jna.NativeLong;

import java.util.List;
import java.util.Arrays;

import static capstone.Arm64_const.*;

public class Arm64 {

  public static class MemType extends Structure {
    public int base;
    public int index;
    public int disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public double fp;
    public MemType mem;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem");
    }
  }

  public static class OpShift extends Structure {
    public int type;
    public int value;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type","value");
    }
  }

  public static class Operand extends Structure {
    public OpShift shift;
    public int ext;
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == ARM64_OP_MEM)
        value.setType(MemType.class);
      if (type == ARM64_OP_FP)
        value.setType(Double.TYPE);
      if (type == ARM64_OP_IMM || type == ARM64_OP_CIMM || type == ARM64_OP_REG)
        value.setType(Integer.TYPE);
      if (type == ARM64_OP_INVALID)
        return;
      readField("value");
      readField("ext");
      readField("shift");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("shift", "ext", "type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int cc;
    public byte _update_flags;
    public byte _writeback;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public UnionOpInfo(Pointer p) {
      op = new Operand[8];
      useMemory(p);
      read();
    }

    public static int getSize() {
      return (new UnionOpInfo()).size();
    }

    public void read() {
      readField("cc");
      readField("_update_flags");
      readField("_writeback");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("cc", "_update_flags", "_writeback", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int cc;
    public boolean updateFlags;
    public boolean writeback;
    public Operand [] op = null;

    public OpInfo(UnionOpInfo op_info) {
      cc = op_info.cc;
      updateFlags = (op_info._update_flags > 0);
      writeback = (op_info._writeback > 0);
      op = op_info.op;
    }
  }
}
