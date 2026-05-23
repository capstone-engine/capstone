// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.M680x;
import static capstone.M680x_const.*;

public class M680xDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        M680x.OpInfo m680x = (M680x.OpInfo) actual.operands;
        if (!Compare.compareBitFlags(m680x.flags, (List<String>) expected.get("flags"), "flags")) {
            return false;
        }
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(m680x.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < m680x.op.length; i++) {
            M680x.Operand aop = m680x.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }
            if (!Compare.compareUInt8(aop.size, (Integer) eop.get("size"), "size")) {
                return false;
            }

            switch (aop.type) {
                case M680X_OP_INDEXED:
                    Map<String, Object> idx = (Map<String, Object>) eop.get("idx");
                    if (idx == null) {
                        continue;
                    }
                    if (!Compare.compareReg(actual, aop.value.idx.base_reg, (String) idx.get("base_reg"), "base_reg")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.idx.offset_reg, (String) idx.get("offset_reg"), "offset_reg")) {
                        return false;
                    }
                    if (!Compare.compareInt16(aop.value.idx.offset, (Integer) idx.get("offset"), "offset")) {
                        return false;
                    }
                    if (!Compare.compareUInt16(aop.value.idx.offset_addr, (Integer) idx.get("offset_addr"), "offset_addr")) {
                        return false;
                    }
                    if (!Compare.compareUInt8(aop.value.idx.offset_bits, (Integer) idx.get("offset_bits"), "offset_bits")) {
                        return false;
                    }
                    if (!Compare.compareInt8(aop.value.idx.inc_dec, (Integer) idx.get("inc_dec"), "inc_dec")) {
                        return false;
                    }
                    if (!Compare.compareBitFlags(aop.value.idx.flags, (List<String>) idx.get("flags"), "flags")) {
                        return false;
                    }
                    break;
                case M680X_OP_REGISTER:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case M680X_OP_IMMEDIATE:
                    if (!Compare.compareInt32(aop.value.imm, (Integer) eop.get("imm"), "imm")) {
                        return false;
                    }
                    break;
                case M680X_OP_RELATIVE:
                    if (!Compare.compareUInt16(aop.value.rel.address, (Integer) eop.get("rel_address"), "rel_address")) {
                        return false;
                    }
                    if (!Compare.compareInt16(aop.value.rel.offset, (Integer) eop.get("rel_offset"), "rel_offset")) {
                        return false;
                    }
                    break;
                case M680X_OP_EXTENDED:
                    if (!Compare.compareUInt16(aop.value.ext.address, (Integer) eop.get("ext_address"), "ext_address")) {
                        return false;
                    }
                    if (!Compare.compareTBool(aop.value.ext.indirect != 0, (Integer) eop.get("ext_indirect"), "ext_indirect")) {
                        return false;
                    }
                    break;
                case M680X_OP_DIRECT:
                    if (!Compare.compareUInt8(aop.value.direct_addr, (Integer) eop.get("direct_addr"), "direct_addr")) {
                        return false;
                    }
                    break;
                case M680X_OP_CONSTANT:
                    if (!Compare.compareUInt8(aop.value.const_val, (Integer) eop.get("const_val"), "const_val")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("M680X operand type not handled");
            }
        }
        return true;
    }
}
