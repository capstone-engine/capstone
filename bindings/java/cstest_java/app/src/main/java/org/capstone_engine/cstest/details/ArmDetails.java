// Copyright © 2025-2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Arm;
import static capstone.Arm_const.*;

public class ArmDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Arm.OpInfo arm = (Arm.OpInfo) actual.operands;
        if (!Compare.compareInt32(arm.vectorSize, (Integer) expected.get("vector_size"), "vector_size")) {
            return false;
        }
        if (!Compare.compareEnum(arm.vectorData, (String) expected.get("vector_data"), "vector_data")) {
            return false;
        }
        if (!Compare.compareEnum(arm.cpsMode, (String) expected.get("cps_mode"), "cps_mode")) {
            return false;
        }
        if (!Compare.compareEnum(arm.cpsFlag, (String) expected.get("cps_flag"), "cps_flag")) {
            return false;
        }
        if (!Compare.compareEnum(arm.cc, (String) expected.get("cc"), "cc")) {
            return false;
        }
        if (!Compare.compareEnum(arm.vcc, (String) expected.get("vcc"), "vcc")) {
            return false;
        }
        if (!Compare.compareEnum(arm.memBarrier, (String) expected.get("mem_barrier"), "mem_barrier")) {
            return false;
        }
        if (!Compare.compareUInt8(arm.predMask, (Integer) expected.get("pred_mask"), "pred_mask")) {
            return false;
        }

        if (!Compare.compareTBool(arm.usermode, (Integer) expected.get("usermode"), "usermode")) {
            return false;
        }
        if (!Compare.compareTBool(arm.updateFlags, (Integer) expected.get("update_flags"), "update_flags")) {
            return false;
        }
        if (!Compare.compareTBool(arm.postIndex, (Integer) expected.get("post_indexed"), "post_indexed")) {
            return false;
        }

        if (!expected.containsKey("operands")) {
            return true;
        } else if (!Compare.compareUInt32(arm.operands.length, (Integer) expected.get("operands_count"), "operands_count")) {
            return false;
        }

        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        for (int i = 0; i < arm.operands.length; i++) {
            Arm.Operand aop = arm.operands[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.type) {
                case ARM_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case ARM_OP_IMM:
                case ARM_OP_PIMM:
                case ARM_OP_CIMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case ARM_OP_SETEND:
                    if (!Compare.compareEnum(aop.value.setend, (String) eop.get("setend"), "setend")) {
                        return false;
                    }
                    break;
                case ARM_OP_PRED:
                    if (!Compare.compareInt32(aop.value.pred, (Integer) eop.get("pred"), "pred")) {
                        return false;
                    }
                    break;
                case ARM_OP_FP:
                    if (!Compare.compareDp(aop.value.fp, (Double) eop.get("fp"), "fp")) {
                        return false;
                    }
                    break;
                case ARM_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.scale, (Integer) eop.get("mem_scale"), "mem_scale")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    if (!Compare.compareUInt32(aop.value.mem.align, (Integer) eop.get("mem_align"), "mem_align")) {
                        return false;
                    }
                    break;
                case ARM_OP_SYSREG:
                    if (!Compare.compareEnum(aop.value.sysop.reg.mclasssysreg, (String) eop.get("sys_reg"), "sys_reg")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.sysm, (Integer) eop.get("sys_sysm"), "sys_sysm")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.msr_mask, (Integer) eop.get("sys_msr_mask"), "sys_msr_mask")) {
                        return false;
                    }
                    break;
                case ARM_OP_BANKEDREG:
                    if (!Compare.compareEnum(aop.value.sysop.reg.bankedreg, (String) eop.get("sys_reg"), "sys_reg")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.sysm, (Integer) eop.get("sys_sysm"), "sys_sysm")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.msr_mask, (Integer) eop.get("sys_msr_mask"), "sys_msr_mask")) {
                        return false;
                    }
                    break;
                case ARM_OP_SPSR:
                case ARM_OP_CPSR:
                    if (!Compare.compareBitFlags(aop.value.sysop.psr_bits, (List<String>) eop.get("sys_psr_bits"), "sys_psr_bits")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.sysm, (Integer) eop.get("sys_sysm"), "sys_sysm")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.msr_mask, (Integer) eop.get("sys_msr_mask"), "sys_msr_mask")) {
                        return false;
                    }
                    break;
                case ARM_OP_SYSM:
                    if (!Compare.compareInt32(aop.value.sysop.sysm, (Integer) eop.get("sys_sysm"), "sys_sysm")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.sysop.msr_mask, (Integer) eop.get("sys_msr_mask"), "sys_msr_mask")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("ARM operand type not handled");
            }

            if (!Compare.compareEnum(aop.shift.type, (String) eop.get("shift_type"), "shift_type")) {
                return false;
            }
            if (!Compare.compareUInt32(aop.shift.value, (Integer) eop.get("shift_value"), "shift_value")) {
                return false;
            }

            if (!Compare.compareInt8(aop.neon_lane, (Integer) eop.get("neon_lane"), "neon_lane")) {
                return false;
            }

            if (!Compare.compareInt32(aop.vector_index, (Integer) eop.get("vector_index"), "vector_index")) {
                return false;
            }

            if (!Compare.compareTBool(aop.subtracted != 0, (Integer) eop.get("subtracted"), "subtracted")) {
                return false;
            }
        }
        return true;
    }
}
