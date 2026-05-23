// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Wasm;
import static capstone.Wasm_const.*;

public class WasmDetails {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Wasm.OpInfo wasm = (Wasm.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(wasm.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < wasm.op.length; i++) {
            Wasm.Operand aop = wasm.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareUInt32(aop.size, (Integer) eop.get("size"), "size")) {
                return false;
            }

            switch (aop.type) {
                case WASM_OP_INT7:
                    if (!Compare.compareInt8(aop.value.int7, (Integer) eop.get("int7"), "int7")) {
                        return false;
                    }
                    break;
                case WASM_OP_VARUINT32:
                    if (!Compare.compareUInt32(aop.value.varuint32, (Integer) eop.get("varuint32"), "varuint32")) {
                        return false;
                    }
                    break;
                case WASM_OP_VARUINT64:
                    if (!Compare.compareUInt64(aop.value.varuint64, Details.getLongFromMap(eop, "varuint64"), "varuint64")) {
                        return false;
                    }
                    break;
                case WASM_OP_UINT32:
                    if (!Compare.compareUInt32(aop.value.uint32, (Integer) eop.get("uint32"), "uint32")) {
                        return false;
                    }
                    break;
                case WASM_OP_UINT64:
                    if (!Compare.compareUInt64(aop.value.uint64, Details.getLongFromMap(eop, "uint64"), "uint64")) {
                        return false;
                    }
                    break;
                case WASM_OP_IMM:
                    if (!Compare.compareUInt32(aop.value.immediate[0], (Integer) eop.get("immediate_0"), "immediate_0")) {
                        return false;
                    }
                    if (!Compare.compareUInt32(aop.value.immediate[1], (Integer) eop.get("immediate_1"), "immediate_1")) {
                        return false;
                    }
                    break;
                case WASM_OP_BRTABLE:
                    if (!Compare.compareUInt32(aop.value.brtable.length, (Integer) eop.get("brt_length"), "brt_length")) {
                        return false;
                    }
                    if (!Compare.compareUInt64(aop.value.brtable.address, Details.getLongFromMap(eop, "brt_address"), "brt_address")) {
                        return false;
                    }
                    if (!Compare.compareUInt32(aop.value.brtable.default_target, (Integer) eop.get("brt_default_target"), "brt_default_target")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Wasm operand type not handled");
            }
        }
        return true;
    }
}
