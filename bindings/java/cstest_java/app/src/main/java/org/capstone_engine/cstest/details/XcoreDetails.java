// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Xcore;
import static capstone.Xcore_const.*;

public class XcoreDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Xcore.OpInfo xcore = (Xcore.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(xcore.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < xcore.op.length; i++) {
            Xcore.Operand aop = xcore.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }

            switch (aop.type) {
                case XCORE_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case XCORE_OP_IMM:
                    if (!Compare.compareInt32(aop.value.imm, (Integer) eop.get("imm"), "imm")) {
                        return false;
                    }
                    break;
                case XCORE_OP_MEM:
                    if (!Compare.compareReg(actual,aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual,aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.direct, (Integer) eop.get("mem_direct"), "mem_direct")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Xcore operand type not handled");
            }
        }
        return true;
    }
}
