// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Ppc;
import static capstone.Ppc_const.*;

import java.util.List;
import java.util.Map;

public class PpcDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Ppc.OpInfo ppc = (Ppc.OpInfo) actual.operands;
        if (expected.containsKey("bc")) {
            Map<String, Object> bc = (Map<String, Object>) expected.get("bc");
            if (!Compare.compareUInt8(ppc.bc.bo, (Integer) bc.get("bo"), "bo")) return false;
            if (!Compare.compareUInt8(ppc.bc.bi, (Integer) bc.get("bi"), "bi")) return false;
            if (!Compare.compareEnum(ppc.bc.crX_bit, (String) bc.get("crX_bit"), "crX_bit")) return false;
            if (!Compare.compareReg(actual, ppc.bc.crX, (String) bc.get("crX"), "crX")) return false;
            if (!Compare.compareEnum(ppc.bc.hint, (String) bc.get("hint"), "hint")) return false;
            if (!Compare.compareEnum(ppc.bc.pred_cr, (String) bc.get("pred_cr"), "pred_cr")) return false;
            if (!Compare.compareEnum(ppc.bc.pred_ctr, (String) bc.get("pred_ctr"), "pred_ctr")) return false;
            if (!Compare.compareEnum(ppc.bc.bh, (String) bc.get("bh"), "bh")) return false;
        }

        if (!Compare.compareTBool(ppc.updateCr0, (Integer) expected.get("update_cr0"), "update_cr0")) return false;
        if (!Compare.compareEnum(ppc.format, (String) expected.get("format"), "format")) return false;

        if (!expected.containsKey("operands")) {
            return true;
        } else if (!Compare.compareUInt32(ppc.operands.length, ((List<?>) expected.get("operands")).size(), "operands_count")) {
            return false;
        }

        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        for (int i = 0; i < ppc.operands.length; i++) {
            Ppc.Operand aop = ppc.operands[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) return false;
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) return false;

            switch (aop.type) {
                case PPC_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) return false;
                    break;
                case PPC_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) return false;
                    break;
                case PPC_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) return false;
                    if (!Compare.compareReg(actual, aop.value.mem.offset, (String) eop.get("mem_offset"), "mem_offset")) return false;
                    if (!Compare.compareInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) return false;
                    break;
            }
        }
        return true;
    }
}
