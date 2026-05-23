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
    public int offset;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("base", "disp", "offset");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public MemType mem;
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;
    public int access;

    public void read() {
      readField("type");
      if (type == PPC_OP_MEM)
        value.setType(MemType.class);
      if (type == PPC_OP_IMM || type == PPC_OP_REG)
        value.setType(Integer.TYPE);
      if (type == PPC_OP_INVALID)
        return;
      readField("value");
      readField("access");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("type", "value", "access");
    }
  }

  public static class PPC_BC extends Structure {
    public byte bo; // BO field of branch condition. UINT8_MAX if invalid.
    public byte bi; // BI field of branch condition. UINT8_MAX if invalid.
    public int crX_bit; // CR field bit to test.
    public int crX; // The CR field accessed.
    public int hint; // The encoded hint.
    public int pred_cr; // CR-bit branch predicate
    public int pred_ctr; // CTR branch predicate
    public int bh; // The BH field hint if any is present.

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("bo", "bi", "crX_bit", "crX", "hint", "pred_cr", "pred_ctr", "bh");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public PPC_BC bc;
    public byte update_cr0;
    public int format;
    public byte op_count;

    public Operand [] operands;

    public UnionOpInfo() {
      operands = new Operand[8];
    }

    public void read() {
      readField("bc");
      readField("update_cr0");
      readField("format");
      readField("op_count");
      operands = new Operand[op_count];
      if (op_count != 0)
        readField("operands");
    }

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("bc", "update_cr0", "format", "op_count", "operands");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public PPC_BC bc;
    public boolean updateCr0;
    public int format;

    public Operand [] operands;

    public OpInfo(UnionOpInfo op_info) {
      bc = op_info.bc;
      updateCr0 = op_info.update_cr0 > 0;
      format = op_info.format;
      operands = op_info.operands;
    }
  }
}
