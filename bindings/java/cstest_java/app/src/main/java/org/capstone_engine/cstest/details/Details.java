// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;


public class Details {

    public static boolean testRegRwAccess(Capstone.CsInsn insn, Map<String, Object> expected) {
        if ((!expected.containsKey("regs_read") || !(expected.get("regs_read") instanceof List)) &&
            (!expected.containsKey("regs_write") || !(expected.get("regs_write") instanceof List))) {
            return true;
        }

        Capstone.CsRegsAccess regsAccess = insn.regsAccess();
        short[] regsRead = regsAccess.regsRead;
        short[] regsWrite = regsAccess.regsWrite;

        if (expected.containsKey("regs_read")) {
            List<String> regsReadExpect = (List<String>) expected.get("regs_read");
            if (!Compare.compareUInt32(regsRead.length, regsReadExpect.size(), "regs_read_count")) {
                return false;
            }
            for (int i = 0; i < regsRead.length; i++) {
                if (!Compare.compareReg(insn, regsRead[i], regsReadExpect.get(i), "regs_read")) {
                    return false;
                }
            }
        }

        if (expected.containsKey("regs_write")) {
            List<String> regsWriteExpect = (List<String>) expected.get("regs_write");
            if (!Compare.compareUInt32(regsWrite.length, regsWriteExpect.size(), "regs_write_count")) {
                return false;
            }
            for (int i = 0; i < regsWrite.length; i++) {
                if (!Compare.compareReg(insn, regsWrite[i], regsWriteExpect.get(i), "regs_write")) {
                    return false;
                }
            }
        }

        return true;
    }

    public static boolean testImplRegRwAccess(Capstone.CsInsn insn, Map<String, Object> expected) {
        if ((!expected.containsKey("regs_impl_read") || !(expected.get("regs_impl_read") instanceof List)) &&
            (!expected.containsKey("regs_impl_write") || !(expected.get("regs_impl_write") instanceof List))) {
            return true;
        }

        short[] regsImplRead = insn.regsRead;
        short[] regsImplWrite = insn.regsWrite;

        if (expected.containsKey("regs_impl_read")) {
            List<String> regsImplReadExpect = (List<String>) expected.get("regs_impl_read");
            if (!Compare.compareUInt32(regsImplRead.length, regsImplReadExpect.size(), "regs_impl_read_count")) {
                return false;
            }
            for (int i = 0; i < regsImplRead.length; i++) {
                if (!Compare.compareReg(insn, regsImplRead[i], regsImplReadExpect.get(i), "regs_impl_read")) {
                    return false;
                }
            }
        }

        if (expected.containsKey("regs_impl_write")) {
            List<String> regsImplWriteExpect = (List<String>) expected.get("regs_impl_write");
            if (!Compare.compareUInt32(regsImplWrite.length, regsImplWriteExpect.size(), "regs_impl_write_count")) {
                return false;
            }
            for (int i = 0; i < regsImplWrite.length; i++) {
                if (!Compare.compareReg(insn, regsImplWrite[i], regsImplWriteExpect.get(i), "regs_impl_write")) {
                    return false;
                }
            }
        }

        return true;
    }

    public static boolean compareDetails(Capstone.CsInsn insn, Map<String, Object> expected) {
        if (expected == null) {
            return true;
        }

        if (!testRegRwAccess(insn, expected)) {
            return false;
        }

        if (!testImplRegRwAccess(insn, expected)) {
            return false;
        }

        if (expected.containsKey("groups") && expected.get("groups") instanceof List) {
            List<String> expectedGroups = (List<String>) expected.get("groups");
            if (!Compare.compareUInt32(insn.groups.length, expectedGroups.size(), "group")) {
                return false;
            }

            for (int i = 0; i < insn.groups.length; i++) {
                int group = insn.groups[i] & 0xff;
                String actualGroupName = insn.groupName(group);
                String expectedGroupName = expectedGroups.get(i);
                if (expectedGroupName.equals(actualGroupName)) {
                    continue;
                }
                if (!Compare.compareEnum(group, expectedGroupName, "group")) {
                    return false;
                }
            }
        }

        if (expected.containsKey("writeback") && !Compare.compareTBool(insn.writeback, (Integer)expected.get("writeback"), "writeback")) {
            return false;
        }

        if (expected.containsKey("x86")) {
            return X86Details.testExpected(insn, (Map<String, Object>)expected.get("x86"));
        }
        if (expected.containsKey("aarch64")) {
            return Aarch64Details.testExpected(insn, (Map<String, Object>)expected.get("aarch64"));
        }
        if (expected.containsKey("ppc")) {
            return PpcDetails.testExpected(insn, (Map<String, Object>)expected.get("ppc"));
        }
        if (expected.containsKey("arm")) {
            return ArmDetails.testExpected(insn, (Map<String, Object>)expected.get("arm"));
        }
        if (expected.containsKey("m680x")) {
            return M680xDetails.testExpected(insn, (Map<String, Object>)expected.get("m680x"));
        }
        if (expected.containsKey("sparc")) {
            return SparcDetails.testExpected(insn, (Map<String, Object>)expected.get("sparc"));
        }
        if (expected.containsKey("tricore")) {
            return TricoreDetails.testExpected(insn, (Map<String, Object>)expected.get("tricore"));
        }
        if (expected.containsKey("alpha")) {
            return AlphaDetails.testExpected(insn, (Map<String, Object>)expected.get("alpha"));
        }
        if (expected.containsKey("xcore")) {
            return XcoreDetails.testExpected(insn, (Map<String, Object>)expected.get("xcore"));
        }
        if (expected.containsKey("tms320c64x")) {
            return TMS320C64xDetails.testExpected(insn, (Map<String, Object>)expected.get("tms320c64x"));
        }
        if (expected.containsKey("m68k")) {
            return M68kDetails.testExpected(insn, (Map<String, Object>)expected.get("m68k"));
        }
        if (expected.containsKey("bpf")) {
            return BpfDetails.testExpected(insn, (Map<String, Object>)expected.get("bpf"));
        }
        if (expected.containsKey("sh")) {
            return ShDetails.testExpected(insn, (Map<String, Object>)expected.get("sh"));
        }
        if (expected.containsKey("hppa")) {
            return HppaDetails.testExpected(insn, (Map<String, Object>)expected.get("hppa"));
        }
        if (expected.containsKey("riscv")) {
            return RiscvDetails.testExpected(insn, (Map<String, Object>)expected.get("riscv"));
        }
        if (expected.containsKey("mips")) {
            return MipsDetails.testExpected(insn, (Map<String, Object>)expected.get("mips"));
        }
        if (expected.containsKey("systemz")) {
            return SystemzDetails.testExpected(insn, (Map<String, Object>)expected.get("systemz"));
        }
        if (expected.containsKey("mos65xx")) {
            return Mos65xxDetails.testExpected(insn, (Map<String, Object>)expected.get("mos65xx"));
        }
        if (expected.containsKey("loongarch")) {
            return LoongarchDetails.testExpected(insn, (Map<String, Object>)expected.get("loongarch"));
        }
        if (expected.containsKey("wasm")) {
            return WasmDetails.testExpected(insn, (Map<String, Object>)expected.get("wasm"));
        }
        if (expected.containsKey("arc")) {
            return ArcDetails.testExpected(insn, (Map<String, Object>)expected.get("arc"));
        }
        return true;
    }

    public static Integer getIntegerFromMap(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Long) {
            Long l = (Long) value;
            if ((l & 0xFFFFFFFFL) == (l & 0xFFFFFFFFFFFFFFFFL)) {
                return l.intValue();
            }
            throw new IllegalArgumentException("Value for key " + key + " is out of range for Integer: " + l);
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        throw new IllegalArgumentException("Expected a number for key " + key);
    }

    public static Long getLongFromMap(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        throw new IllegalArgumentException("Expected a number for key " + key);
    }

    public static Float getFloatFromMap(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return Float.parseFloat(((String) value).toLowerCase().replace("inf", "Infinity").replace("nan", "NaN"));
        }
        if (value instanceof Number) {
            return ((Number) value).floatValue();
        }
        throw new IllegalArgumentException("Expected a number for key " + key);
    }

    public static Double getDoubleFromMap(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return Double.parseDouble(((String) value).toLowerCase().replace("inf", "Infinity").replace("nan", "NaN"));
        }
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        throw new IllegalArgumentException("Expected a number for key " + key);
    }
}
