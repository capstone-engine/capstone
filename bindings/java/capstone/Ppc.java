// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Ppc_const.*;

public class Ppc {

  public static class MemType extends Structure {
    public int base;
    public int disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class CrxType extends Structure {
    public int scale;
    public int reg;
    public int cond;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("scale", "reg", "cond");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public int imm;
    public MemType mem;
    public CrxType crx;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      readField("type");
      if (type == PPC_OP_MEM)
        value.setType(MemType.class);
      if (type == PPC_OP_CRX)
        value.setType(CrxType.class);
      if (type == PPC_OP_IMM || type == PPC_OP_REG)
        value.setType(Integer.TYPE);
      if (type == PPC_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public int bc;
    public int bh;
    public byte update_cr0;
    public byte op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
    }

    public void read() {
      readField("bc");
      readField("bh");
      readField("update_cr0");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("bc", "bh", "update_cr0", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public int bc;
    public int bh;
    public boolean updateCr0;

    public Operand [] op;

    public OpInfo(UnionOpInfo op_info) {
      bc = op_info.bc;
      bh = op_info.bh;
      updateCr0 = (op_info.update_cr0 > 0);
      op = op_info.op;
    }
  }
}
