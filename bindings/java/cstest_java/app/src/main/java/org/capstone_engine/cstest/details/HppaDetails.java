// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Hppa;
import static capstone.Hppa_const.*;

public class HppaDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Hppa.OpInfo hppa = (Hppa.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(hppa.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < hppa.op.length; i++) {
            Hppa.Operand aop = hppa.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.getType(), (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.getType()) {
                case HPPA_OP_REG:
                case HPPA_OP_IDX_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case HPPA_OP_IMM:
                case HPPA_OP_DISP:
                case HPPA_OP_TARGET:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case HPPA_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.space, (String) eop.get("mem_space"), "mem_space")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Hppa operand type not handled");
            }
        }
        return true;
    }
}
