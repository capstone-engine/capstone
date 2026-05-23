// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.X86;
import static capstone.X86_const.*;

public class X86Details {
    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        X86.OpInfo x86 = (X86.OpInfo)actual.operands;

        if (!Compare.compareReg(actual, x86.sibIndex, (String) expected.get("sib_index"), "sib_index")) {
            return false;
        }
        if (!Compare.compareReg(actual, x86.sibBase, (String) expected.get("sib_base"), "sib_base")) {
            return false;
        }
        if (!Compare.compareEnum(x86.xopCC, (String) expected.get("xop_cc"), "xop_cc")) {
            return false;
        }
        if (!Compare.compareEnum(x86.sseCC, (String) expected.get("sse_cc"), "sse_cc")) {
            return false;
        }
        if (!Compare.compareEnum(x86.avxCC, (String) expected.get("avx_cc"), "avx_cc")) {
            return false;
        }
        if (!Compare.compareEnum(x86.avxRm, (String) expected.get("avx_rm"), "avx_rm")) {
            return false;
        }
    
        if (expected.containsKey("prefix")) {
            List<String> prefixes = (List<String>) expected.get("prefix");
            for (int i = 0; i < prefixes.size(); i++) {
                if (!Compare.compareEnum(x86.prefix[i] & 0xff, prefixes.get(i), "prefix")) {
                    return false;
                }
            }
        }
    
        if (expected.containsKey("opcode")) {
            List<Integer> opcodes = (List<Integer>) expected.get("opcode");
            for (int i = 0; i < opcodes.size(); i++) {
                if (!Compare.compareUInt8(x86.opcode[i], opcodes.get(i), "opcode")) {
                    return false;
                }
            }
        }
    
        if (!Compare.compareUInt8(x86.rex, (Integer) expected.get("rex"), "rex")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.addrSize, (Integer) expected.get("addr_size"), "addr_size")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.modrm, (Integer) expected.get("modrm"), "modrm")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.sib, (Integer) expected.get("sib"), "sib")) {
            return false;
        }
        if (!Compare.compareInt64(x86.disp, Details.getLongFromMap(expected, "disp"), "disp")) {
            return false;
        }
        if (!Compare.compareInt8(x86.sibScale, (Integer) expected.get("sib_scale"), "sib_scale")) {
            return false;
        }
        if (!Compare.compareTBool(x86.avxSae, (Integer) expected.get("avx_sae"), "avx_sae")) {
            return false;
        }
    
        if (!Compare.compareBitFlags(x86.eflags, (List<String>) expected.get("eflags"), "eflags")) {
            return false;
        }
        if (!Compare.compareBitFlags(x86.fpuFlags, (List<String>) expected.get("fpu_flags"), "fpu_flags")) {
            return false;
        }
    
        if (!Compare.compareUInt8(x86.encoding.modrmOffset, (Integer) expected.get("enc_modrm_offset"), "enc_modrm_offset")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.encoding.dispOffset, (Integer) expected.get("enc_disp_offset"), "enc_disp_offset")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.encoding.dispSize, (Integer) expected.get("enc_disp_size"), "enc_disp_size")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.encoding.immOffset, (Integer) expected.get("enc_imm_offset"), "enc_imm_offset")) {
            return false;
        }
        if (!Compare.compareUInt8(x86.encoding.immSize, (Integer) expected.get("enc_imm_size"), "enc_imm_size")) {
            return false;
        }
    
        if (!expected.containsKey("operands")) {
            return true;
        } else if (!Compare.compareUInt32(x86.op.length, ((List<?>) expected.get("operands")).size(), "operands_count")) {
            return false;
        }
    
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        for (int i = 0; i < x86.op.length; i++) {
            X86.Operand aop = x86.op[i];
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
            if (!Compare.compareEnum(aop.avx_bcast, (String) eop.get("avx_bcast"), "avx_bcast")) {
                return false;
            }
            if (!Compare.compareTBool(aop.avx_zero_opmask != 0, (Integer) eop.get("avx_zero_opmask"), "avx_zero_opmask")) {
                return false;
            }
    
            switch (aop.type) {
                case X86_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case X86_OP_IMM:
                    if (!Compare.compareInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case X86_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.segment, (String) eop.get("mem_segment"), "mem_segment")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareReg(actual, aop.value.mem.index, (String) eop.get("mem_index"), "mem_index")) {
                        return false;
                    }
                    if (!Compare.compareInt32(aop.value.mem.scale, (Integer) eop.get("mem_scale"), "mem_scale")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("x86 operand type not handled");
            }
        }
    
        return true;
    }
}
