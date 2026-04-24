// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Loongarch;
import static capstone.Loongarch_const.*;

public class LoongarchDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Loongarch.OpInfo loongarch = (Loongarch.OpInfo) actual.operands;
        if (!Compare.compareEnum(loongarch.format, (String) expected.get("format"), "format")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(loongarch.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < loongarch.op.length; i++) {
            Loongarch.Operand aop = loongarch.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.getType(), (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.getType()) {
                case LOONGARCH_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case LOONGARCH_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case LOONGARCH_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Loongarch operand type not handled");
            }
        }
        return true;
    }
}
