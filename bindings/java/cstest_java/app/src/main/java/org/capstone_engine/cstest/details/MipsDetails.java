// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Mips;
import static capstone.Mips_const.*;

public class MipsDetails {

    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Mips.OpInfo mips = (Mips.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(mips.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < mips.op.length; i++) {
            Mips.Operand aop = mips.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }
            if (!Compare.compareTBool(aop.is_reglist != 0, (Integer) eop.get("is_reglist"), "is_reglist")) {
                return false;
            }
            if (!Compare.compareTBool(aop.is_unsigned != 0, (Integer) eop.get("is_unsigned"), "is_unsigned")) {
                return false;
            }

            switch (aop.type) {
                case MIPS_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case MIPS_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case MIPS_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Mips operand type not handled");
            }
        }
        return true;
    }
}
