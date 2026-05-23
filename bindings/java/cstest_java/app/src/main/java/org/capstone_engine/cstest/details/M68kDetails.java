// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.M68k;

import static capstone.M68k_const.*;

public class M68kDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        M68k.OpInfo m68k = (M68k.OpInfo) actual.operands;
        if (!Compare.compareEnum(m68k.op_size.type, (String) expected.get("op_size_type"), "op_size_type")) {
            return false;
        }
        if (!Compare.compareEnum(m68k.op_size.size, (String) expected.get("op_size_fpu"), "op_size_fpu")) {
            return false;
        }
        if (!Compare.compareEnum(m68k.op_size.size, (String) expected.get("op_size_cpu"), "op_size_cpu")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(m68k.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < m68k.op.length; i++) {
            M68k.Operand aop = m68k.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.address_mode, (String) eop.get("address_mode"), "address_mode")) {
                return false;
            }

            switch (aop.type) {
                case M68K_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case M68K_OP_REG_PAIR:
                    if (!Compare.compareReg(actual, aop.value.reg_pair.reg_0, (String) eop.get("reg_pair_0"), "reg_pair_0")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.reg_pair.reg_1, (String) eop.get("reg_pair_1"), "reg_pair_1")) {
                        return false;
                    }
                    break;
                case M68K_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case M68K_OP_BR_DISP:
                    if (!Compare.compareInt32(aop.br_disp.disp, (Integer) eop.get("br_disp"), "br_disp")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.br_disp.disp_size, (Integer) eop.get("br_disp_size"), "br_disp_size")) {
                        return false;
                    }
                    break;
                case M68K_OP_REG_BITS:
                    if (!Compare.compareUInt32(aop.register_bits, (Integer) eop.get("register_bits"), "register_bits")) {
                        return false;
                    }
                    break;
                case M68K_OP_FP_DOUBLE:
                    if (!Compare.compareDp(aop.value.dimm, Details.getDoubleFromMap(eop, "dimm"), "dimm")) {
                        return false;
                    }
                    break;
                case M68K_OP_FP_SINGLE:
                    if (!Compare.compareFp(aop.value.simm, Details.getFloatFromMap(eop, "simm"), "simm")) {
                        return false;
                    }
                    break;
                case M68K_OP_MEM:
                    Map<String, Object> emem = (Map<String, Object>) eop.get("mem");
                    if (emem == null) {
                        continue;
                    }

                    if (!Compare.compareReg(actual, aop.mem.base_reg, (String) emem.get("base_reg"), "base_reg")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.mem.index_reg, (String) emem.get("index_reg"), "index_reg")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.mem.in_base_reg, (String) emem.get("in_base_reg"), "in_base_reg")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.mem.index_size != 0, (Integer) emem.get("index_size"), "index_size")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.mem.in_disp_size != 0, (Integer) emem.get("in_disp_size"), "in_disp_size")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.mem.out_disp_size != 0, (Integer) emem.get("out_disp_size"), "out_disp_size")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.mem.disp_size != 0, (Integer) emem.get("disp_size"), "disp_size")) {
                        return false;
                    }
                    if (!Compare.compareInt16(aop.mem.disp, (Integer) emem.get("disp"), "disp")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.mem.in_disp, (Integer) emem.get("in_disp"), "in_disp")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.mem.out_disp, (Integer) emem.get("out_disp"), "out_disp")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.mem.scale, (Integer) emem.get("scale"), "scale")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.mem.bitfield, (Integer) emem.get("bitfield"), "bitfield")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.mem.width, (Integer) emem.get("width"), "width")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.mem.offset, (Integer) emem.get("offset"), "offset")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("M68K operand type not handled");
            }
        }
        return true;
    }
}
