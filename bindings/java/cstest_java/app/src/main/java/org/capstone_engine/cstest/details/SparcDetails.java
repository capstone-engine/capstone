// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Sparc;
import static capstone.Sparc_const.*;

public class SparcDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Sparc.OpInfo sparc = (Sparc.OpInfo) actual.operands;
        if (!Compare.compareEnum(sparc.cc, (String) expected.get("cc"), "cc")) {
            return false;
        }
        if (!Compare.compareEnum(sparc.hint, (String) expected.get("hint"), "hint")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(sparc.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < sparc.op.length; i++) {
            Sparc.Operand aop = sparc.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.type) {
                case SPARC_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case SPARC_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case SPARC_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt16(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                case SPARC_OP_ASI:
                    if (!Compare.compareEnum(aop.value.asi, (String) eop.get("asi"), "asi")) {
                        return false;
                    }
                    break;
                case SPARC_OP_MEMBAR_TAG:
                    if (!Compare.compareEnum(aop.value.membar_tag, (String) eop.get("membar_tag"), "membar_tag")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Sparc operand type not handled");
            }
        }
        return true;
    }
}
