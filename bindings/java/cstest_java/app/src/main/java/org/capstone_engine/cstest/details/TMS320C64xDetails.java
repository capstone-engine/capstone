// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.TMS320C64x;
import static capstone.TMS320C64x_const.*;

public class TMS320C64xDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        TMS320C64x.OpInfo tms320c64x = (TMS320C64x.OpInfo) actual.operands;
        if (!Compare.compareReg(actual, tms320c64x.condition.reg, (String) expected.get("cond_reg"), "cond_reg")) {
            return false;
        }
        if (!Compare.compareTBool(tms320c64x.condition.zero != 0, (Integer) expected.get("cond_zero"), "cond_zero")) {
            return false;
        }

        
        if (!Compare.compareEnum(tms320c64x.funit.unit, (String) expected.get("funit_unit"), "funit_unit")) {
            return false;
        }
        if (!Compare.compareUInt8(tms320c64x.funit.side, (Integer) expected.get("funit_side"), "funit_side")) {
            return false;
        }
        if (!Compare.compareUInt8(tms320c64x.funit.crosspath, (Integer) expected.get("funit_crosspath"), "funit_crosspath")) {
            return false;
        }

        if (!Compare.compareInt8(tms320c64x.parallel, (Integer) expected.get("parallel"), "parallel")) {
            return false;
        }

        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(tms320c64x.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < tms320c64x.op.length; i++) {
            TMS320C64x.Operand aop = tms320c64x.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }

            switch (aop.type) {
                case TMS320C64X_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case TMS320C64X_OP_REGPAIR:
                    if (!Compare.compareReg(actual, aop.value.reg + 1, (String) eop.get("reg_pair_0"), "reg_pair_0")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg_pair_1"), "reg_pair_1")) {
                        return false;
                    }
                    break;
                case TMS320C64X_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case TMS320C64X_OP_MEM:
                    if (!Compare.compareReg(actual,aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.value.mem.scaled != 0, (Integer) eop.get("mem_scaled"), "mem_scaled")) {
                        return false;
                    }
                    if (!Compare.compareEnum(aop.value.mem.disptype, (String) eop.get("mem_disptype"), "mem_disptype")) {
                        return false;
                    }
                    if (!Compare.compareEnum(aop.value.mem.direction, (String) eop.get("mem_direction"), "mem_direction")) {
                        return false;
                    }
                    if (!Compare.compareEnum(aop.value.mem.modify, (String) eop.get("mem_modify"), "mem_modify")) {
                        return false;
                    }
                    if (!Compare.compareInt16(aop.value.mem.disp, (Integer) eop.get("mem_disp"), "mem_disp")) {
                        return false;
                    }
                    if (aop.value.mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
                        if (!Compare.compareReg(actual, aop.value.mem.disp, (String) eop.get("mem_disp_reg"), "mem_disp_reg")) {
                            return false;
                        }
                    } else if (aop.value.mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
                        if (!Compare.compareUInt32(aop.value.mem.disp, (Integer) eop.get("mem_disp_const"), "mem_disp_const")) {
                            return false;
                        }
                    } else {
                        throw new IllegalArgumentException("TMS320c64x memory offset type not handled.");
                    }
                    break;
                default:
                    throw new IllegalArgumentException("TMS320c64x operand type not handled");
            }
        }
        return true;
    }
}


/*
def test_expected_tms320c64x(actual: CsInsn, expected: dict) -> bool:
    if not compare_reg(
        actual, actual.condition.reg, expected.get("cond_reg"), "cond_reg"
    ):
        return False
    if not compare_tbool(actual.condition.zero, expected.get("cond_zero"), "cond_zero"):
        return False

    if not compare_enum(actual.funit.unit, expected.get("funit_unit"), "funit_unit"):
        return False
    if not compare_uint8(actual.funit.side, expected.get("funit_side"), "funit_side"):
        return False
    if not compare_uint8(
        actual.funit.crosspath, expected.get("funit_crosspath"), "funit_crosspath"
    ):
        return False

    if not compare_int8(actual.parallel, expected.get("parallel"), "parallel"):
        return False

    if "operands" not in expected:
        return True
    elif not compare_uint32(
        len(actual.operands), len(expected.get("operands")), "operands_count"
    ):
        return False

    for aop, eop in zip(actual.operands, expected["operands"]):
        if not compare_enum(aop.type, eop.get("type"), "type"):
            return False

        if aop.type == TMS320C64X_OP_REG:
            if not compare_reg(actual, aop.reg, eop.get("reg"), "reg"):
                return False
        elif aop.type == TMS320C64X_OP_REGPAIR:
            if not compare_reg(
                actual, aop.reg + 1, eop.get("reg_pair_0"), "reg_pair_0"
            ):
                return False
            if not compare_reg(actual, aop.reg, eop.get("reg_pair_1"), "reg_pair_1"):
                return False
        elif aop.type == TMS320C64X_OP_IMM:
            if not compare_int32(aop.imm, eop.get("imm"), "imm"):
                return False
        elif aop.type == TMS320C64X_OP_MEM:
            if not compare_reg(actual, aop.mem.base, eop.get("mem_base"), "mem_base"):
                return False
            if not compare_tbool(aop.mem.scaled, eop.get("mem_scaled"), "mem_scaled"):
                return False
            if not compare_enum(
                aop.mem.disptype, eop.get("mem_disptype"), "mem_disptype"
            ):
                return False
            if not compare_enum(
                aop.mem.direction, eop.get("mem_direction"), "mem_direction"
            ):
                return False
            if not compare_enum(aop.mem.modify, eop.get("mem_modify"), "mem_modify"):
                return False
            if aop.mem.disptype == TMS320C64X_MEM_DISP_REGISTER:
                if not compare_reg(
                    actual, aop.mem.disp, eop.get("mem_disp_reg"), "mem_disp_reg"
                ):
                    return False
            elif aop.mem.disptype == TMS320C64X_MEM_DISP_CONSTANT:
                if not compare_uint32(
                    aop.mem.disp, eop.get("mem_disp_const"), "mem_disp_const"
                ):
                    return False
            else:
                raise ValueError("TMS320c64x memory offset type not handled.")

            if not compare_uint32(aop.mem.unit, eop.get("mem_unit"), "mem_unit"):
                return False
        else:
            raise ValueError("Operand type not handled.")

    return True
*/
