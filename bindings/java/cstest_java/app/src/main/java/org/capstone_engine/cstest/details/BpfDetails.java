// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Bpf;
import static capstone.Bpf_const.*;

public class BpfDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Bpf.OpInfo bpf = (Bpf.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }

        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(bpf.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < bpf.op.length; i++) {
            Bpf.Operand aop = bpf.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }
            if (!Compare.compareTBool(aop.is_pkt != 0, (Integer) eop.get("is_pkt"), "is_pkt")) {
                return false;
            }
            if (!Compare.compareTBool(aop.is_signed != 0, (Integer) eop.get("is_signed"), "is_signed")) {
                return false;
            }

            switch (aop.type) {
                case BPF_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case BPF_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case BPF_OP_OFF:
                    if (!Compare.compareUInt32(aop.value.off, (Integer) eop.get("off"), "off")) {
                        return false;
                    }
                    break;
                case BPF_OP_MMEM:
                    if (!Compare.compareUInt32(aop.value.mmem, (Integer) eop.get("mmem"), "mmem")) {
                        return false;
                    }
                    break;
                case BPF_OP_MSH:
                    if (!Compare.compareUInt32(aop.value.msh, (Integer) eop.get("msh"), "msh")) {
                        return false;
                    }
                    break;
                case BPF_OP_EXT:
                    if (!Compare.compareEnum(aop.value.ext, (String) eop.get("ext"), "ext")) {
                        return false;
                    }
                    break;
                case BPF_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareUInt32(aop.value.mem.disp, Details.getIntegerFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Bpf operand type not handled");
            }
        }
        return true;
    }
}
