// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Arc;
import static capstone.Arc_const.*;

public class ArcDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Arc.OpInfo arc = (Arc.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(arc.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < arc.op.length; i++) {
            Arc.Operand aop = arc.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.type) {
                case ARC_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case ARC_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Arc operand type not handled");
            }
        }
        return true;
    }
}
