// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.Union;
import com.sun.jna.NativeLong;

import java.util.List;
import java.util.Arrays;

import static capstone.X86_const.*;

public class X86 {

  public static class MemType extends Structure {
    public int base;
    public int index;
    public int scale;
    public long disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "index", "scale", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public double fp;
    public MemType mem;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public OpValue value;

    public void read() {
      super.read();
      if (type == X86_OP_MEM)
        value.setType(MemType.class);
      if (type == X86_OP_FP)
        value.setType(Double.TYPE);
      if (type == X86_OP_IMM)
        value.setType(Long.TYPE);
      if (type == X86_OP_REG)
        value.setType(Integer.TYPE);
      if (type == X86_OP_INVALID)
        return;
      readField("value");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte [] prefix;
    public int segment;
    public byte [] opcode;
    public byte op_size;
    public byte addr_size;
    public byte disp_size;
    public byte imm_size;
    public byte modrm;
    public byte sib;
    public int disp;
    public int sib_index;
    public byte sib_scale;
    public int sib_base;

    public char op_count;

    public Operand [] op;

    public UnionOpInfo() {
      op = new Operand[8];
      opcode = new byte[3];
      prefix = new byte[5];
    }

    public UnionOpInfo(Pointer p) {
      op = new Operand[8];
      opcode = new byte[3];
      prefix = new byte[5];
      useMemory(p);
      read();
    }

    public static int getSize() {
      return (new UnionOpInfo()).size();
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("prefix", "segment", "opcode", "op_size", "addr_size", "disp_size",
          "imm_size", "modrm", "sib", "disp", "sib_index", "sib_scale", "sib_base", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public byte [] prefix;
    public int segment;
    public byte [] opcode;
    public byte opSize;
    public byte addrSize;
    public byte dispSize;
    public byte immSize;
    public byte modrm;
    public byte sib;
    public int disp;
    public int sibIndex;
    public byte sibScale;
    public int sibBase;

    public Operand[] op;

    public OpInfo(UnionOpInfo e) {
      prefix = e.prefix;
      segment = e.segment;
      opcode = e.opcode;
      opSize = e.op_size;
      addrSize = e.addr_size;
      dispSize = e.disp_size;
      immSize = e.imm_size;
      modrm = e.modrm;
      sib = e.sib;
      disp = e.disp;
      sibIndex = e.sib_index;
      sibScale = e.sib_scale;
      sibBase = e.sib_base;
      op = new Operand[e.op_count];
      for (int i=0; i<e.op_count; i++)
        op[i] = e.op[i];
    }
  }
}
