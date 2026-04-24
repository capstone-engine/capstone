// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Tricore;
import static capstone.Tricore_const.*;

public class TricoreDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Tricore.OpInfo tricore = (Tricore.OpInfo) actual.operands;
        if (!Compare.compareTBool(tricore.update_flags, (Integer) expected.get("update_flags"), "update_flags")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(tricore.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < tricore.op.length; i++) {
            Tricore.Operand aop = tricore.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.type) {
                case TRICORE_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case TRICORE_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case TRICORE_OP_MEM:
                    if (!Compare.compareReg(actual,aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Tricore operand type not handled");
            }
        }
        return true;
    }
}
