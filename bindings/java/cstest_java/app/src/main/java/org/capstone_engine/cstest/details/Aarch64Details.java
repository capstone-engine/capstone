// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.AArch64;
import static capstone.AArch64_const.*;

public class Aarch64Details {

    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        AArch64.OpInfo aarch64 = (AArch64.OpInfo)actual.operands;

        if (!Compare.compareEnum(aarch64.cc, (String) expected.get("cc"), "cc")) {
            return false;
        }
        if (!Compare.compareTBool(aarch64.updateFlags, (Integer) expected.get("update_flags"), "update_flags")) {
            return false;
        }
        if (!Compare.compareTBool(aarch64.postIndex, (Integer) expected.get("post_indexed"), "post_indexed")) {
            return false;
        }

        if (!expected.containsKey("operands")) {
            return true;
        } else if (!Compare.compareUInt32(aarch64.operands.length, ((List<?>) expected.get("operands")).size(), "operands_count")) {
            return false;
        }

        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        for (int i = 0; i < aarch64.operands.length; i++) {
            AArch64.Operand aop = aarch64.operands[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            if (!Compare.compareEnum(aop.shift.type, (String) eop.get("shift_type"), "shift_type")) {
                return false;
            }
            if (!Compare.compareUInt32(aop.shift.value, (Integer) eop.get("shift_value"), "shift_value")) {
                return false;
            }
            if (!Compare.compareEnum(aop.ext, (String) eop.get("ext"), "ext")) {
                return false;
            }

            if (!Compare.compareEnum(aop.vas, (String) eop.get("vas"), "vas")) {
                return false;
            }
            if (!Compare.compareTBool(aop.is_vreg != 0, (Integer) eop.get("is_vreg"), "is_vreg")) {
                return false;
            }

            if (!Compare.compareInt32(aop.vector_index, (Integer) eop.get("vector_index"), "vector_index")) {
                return false;
            }

            if (!Compare.compareTBool(aop.is_list_member != 0, (Integer) eop.get("is_list_member"), "is_list_member")) {
                return false;
            }

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "op type")) {
                return false;
            }

            switch (aop.type) {
                case AARCH64_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_IMM_RANGE:
                    if (!Compare.compareInt8(aop.value.imm_range.first, (Integer) eop.get("imm_range_first"), "imm_range_first")) {
                        return false;
                    }
                    if (!Compare.compareInt8(aop.value.imm_range.offset, (Integer) eop.get("imm_range_offset"), "imm_range_offset")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_FP:
                    if (!Compare.compareDp(aop.value.fp, (Double)eop.get("fp"), "fp")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_SYSREG:
                    if (!Compare.compareEnum(aop.sysop.sub_type, (String) eop.get("sub_type"), "sub_type")) {
                        return false;
                    }
                    if (!Compare.compareUInt64(aop.sysop.reg.raw_val, Details.getLongFromMap(eop, "sys_raw_val"), "sys_raw_val")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_SYSIMM:
                    if (!Compare.compareEnum(aop.sysop.sub_type, (String) eop.get("sub_type"), "sub_type")) {
                        return false;
                    }
                    if (!Compare.compareUInt64(aop.sysop.imm.raw_val, Details.getLongFromMap(eop, "sys_raw_val"), "sys_raw_val")) {
                        return false;
                    }
                    if (!Compare.compareDp(aop.value.fp, (Double) eop.get("fp"), "fp")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_SYSALIAS:
                    if (!Compare.compareEnum(aop.sysop.sub_type, (String) eop.get("sub_type"), "sub_type")) {
                        return false;
                    }
                    if (!Compare.compareUInt64(aop.sysop.alias.raw_val, Details.getLongFromMap(eop, "sys_raw_val"), "sys_raw_val")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_PRED:
                    if (!Compare.compareReg(actual, aop.value.pred.reg, (String) eop.get("pred_reg"), "pred_reg")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.pred.vec_select, (String) eop.get("pred_vec_select"), "pred_vec_select")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.pred.imm_index, (Integer) eop.get("pred_imm_index"), "pred_imm_index")) {
                        return false;
                    }
                    break;
                case AARCH64_OP_SME:
                    if (!eop.containsKey("sme")) {
                        continue;
                    }
                    Map<String, Object> sme = (Map<String, Object>) eop.get("sme");
                    if (!Compare.compareEnum(aop.value.sme.type, (String) sme.get("type"), "type")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.sme.tile, (String) sme.get("tile"), "tile")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.sme.slice_reg, (String) sme.get("slice_reg"), "slice_reg")) {
                        return false;
                    }
                    if (!Compare.compareInt8(aop.value.sme.slice_offset.imm, (Integer) sme.get("slice_offset_imm"), "slice_offset_imm")) {
                        return false;
                    }
                    if (!Compare.compareInt8(aop.value.sme.slice_offset.imm_range.first, (Integer) sme.get("slice_offset_ir_first"), "slice_offset_ir_first")) {
                        return false;
                    }
                    if (!Compare.compareInt8(aop.value.sme.slice_offset.imm_range.offset, (Integer) sme.get("slice_offset_ir_offset"), "slice_offset_ir_offset")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.value.sme.has_range_offset != 0, (Integer) sme.get("has_range_offset"), "has_range_offset")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.value.sme.is_vertical != 0, (Integer) sme.get("is_vertical"), "is_vertical")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Operand type not handled: " + aop.type);
            }
        }
        return true;
    }
}
