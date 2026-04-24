// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Mos65xx;
import static capstone.Mos65xx_const.*;

public class Mos65xxDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Mos65xx.OpInfo mos65xx = (Mos65xx.OpInfo) actual.operands;
        if (!Compare.compareEnum(mos65xx.am, (String) expected.get("am"), "am")) {
            return false;
        }
        if (!Compare.compareTBool(mos65xx.modifies_flags != 0, (Integer) expected.get("modifies_flags"), "modifies_flags")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(mos65xx.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < mos65xx.op.length; i++) {
            Mos65xx.Operand aop = mos65xx.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.getType(), (String) eop.get("type"), "type")) {
                return false;
            }

            switch (aop.getType()) {
                case MOS65XX_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case MOS65XX_OP_IMM:
                    if (!Compare.compareUInt16(aop.value.imm, (Integer) eop.get("imm"), "imm")) {
                        return false;
                    }
                    break;
                case MOS65XX_OP_MEM:
                    if (!Compare.compareUInt32(aop.value.mem, (Integer) eop.get("mem"), "mem")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("MOS65XX operand type not handled");
            }
        }
        return true;
    }
}
