// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;
import static java.util.Map.entry;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Systemz;
import static capstone.Systemz_const.*;

public class SystemzDetails {

    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Systemz.OpInfo systemz = (Systemz.OpInfo) actual.operands;
        if (!Compare.compareEnum(systemz.cc, (String) expected.get("cc"), "cc")) {
            return false;
        }
        if (!Compare.compareEnum(systemz.format, (String) expected.get("format"), "format")) {
            return false;
        }

        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(systemz.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < systemz.op.length; i++) {
            Systemz.Operand aop = systemz.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }
            switch (aop.type) {
                case SYSTEMZ_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case SYSTEMZ_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.imm_width, (Integer) eop.get("imm_width"), "imm_width")) {
                        return false;
                    }
                    break;
                case SYSTEMZ_OP_MEM:
                    if (!Compare.compareEnum(aop.value.mem.am, (String) eop.get("mem_am"), "mem_am")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.getBase(), (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.getIndex(), (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    if (!Compare.compareUInt64(aop.value.mem.length, Details.getLongFromMap(eop, "mem_length"), "mem_length")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Systemz operand type not handled");
            }
        }
        return true;
    }
}
