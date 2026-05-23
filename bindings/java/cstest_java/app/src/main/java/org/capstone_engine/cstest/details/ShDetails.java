// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Sh;
import static capstone.Sh_const.*;

public class ShDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Sh.OpInfo sh = (Sh.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(sh.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < sh.op.length; i++) {
            Sh.Operand aop = sh.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }

            switch (aop.type) {
                case SH_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case SH_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case SH_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.reg, (String) eop.get("mem_reg"), "mem_reg")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.address, (String) eop.get("mem_address"), "mem_address")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Sh operand type not handled");
            }
        }
        return true;
    }
}
