// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import capstone.Capstone;
import capstone.Arm_const;
import capstone.AArch64_const;
import capstone.M68k_const;
import capstone.Mips_const;
import capstone.Ppc_const;
import capstone.Sparc_const;
import capstone.Systemz_const;
import capstone.X86_const;
import capstone.Xcore_const;
import capstone.TMS320C64x_const;
import capstone.M680x_const;
import capstone.Evm_const;
import capstone.Mos65xx_const;
import capstone.Wasm_const;
import capstone.Bpf_const;
import capstone.Riscv_const;
import capstone.Sh_const;
import capstone.Tricore_const;
import capstone.Alpha_const;
import capstone.Hppa_const;
import capstone.Loongarch_const;
import capstone.Xtensa_const;
import capstone.Arc_const;


public class Compare {
    private static final Logger log = Logger.getLogger(Compare.class.getName());

    private static Long getLongAttr(Class<?> klass, String attr) {
        try {
            return klass.getField(attr).getLong(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return null;
        }
    }

    public static long cs_const_getattr(String identifier) {
        Long attr = getLongAttr(Capstone.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Arm_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(AArch64_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(M68k_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Mips_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Ppc_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Sparc_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Systemz_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(X86_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Xcore_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(TMS320C64x_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(M680x_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Evm_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Mos65xx_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Wasm_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Bpf_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Riscv_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Sh_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Tricore_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Alpha_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Hppa_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Loongarch_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Xtensa_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        attr = getLongAttr(Arc_const.class, identifier);
        if (attr != null) {
            return attr;
        }
        throw new IllegalArgumentException("Java capstone doesn't have the constant: " + identifier);
    }

    public static long twosComplement(long val, long bits) {
        if ((val & (1L << (bits - 1L))) != 0L) {
            val = val - (1L << bits);
        }
        return val & ((1L << bits) - 1L);
    }

    public static String normalizeAsmText(String text, int archBits) {
        text = text.trim();
        text = text.replaceAll("\\s+", " ");

        // Replace hex numbers with decimals
        Pattern hexPattern = Pattern.compile("0x[0-9a-fA-F]+");
        Matcher hexMatcher = hexPattern.matcher(text);
        while (hexMatcher.find()) {
            String hexNum = hexMatcher.group();
            long decimalValue = new BigInteger(hexNum.substring(2), 16).longValue();
            text = text.replaceFirst(hexNum, String.valueOf(decimalValue));
        }

        // Replace negatives with two's complement
        Pattern numPattern = Pattern.compile("-\\d+");
        Matcher numMatcher = numPattern.matcher(text);
        while (numMatcher.find()) {
            String num = numMatcher.group();
            long n = twosComplement(Long.parseLong(num), archBits);
            text = text.replaceFirst(Pattern.quote(num), String.valueOf(n));
        }

        text = text.toLowerCase();
        return text;
    }

    public static boolean compareAsmText(Capstone.CsInsn aInsn, String expected, int archBits) {
        if (expected == null) {
            return true;
        }

        String actual = aInsn.mnemonic + " " + aInsn.opStr;
        actual = normalizeAsmText(actual, archBits);
        expected = normalizeAsmText(expected, archBits);

        if (!actual.equals(expected)) {
            log.severe("Normalized asm-text doesn't match:\n" +
                    "decoded:  '" + actual + "'\n" +
                    "expected: '" + expected + "'");
            return false;
        }
        return true;
    }
    
    public static boolean compareStr(String actual, String expected, String msg) {
        if (expected == null) {
            return true;
        }

        if (!actual.equals(expected)) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareTBool(boolean actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        if (expected == 0) {
            // Unset
            return true;
        }

        if ((expected < 0 && actual) || (expected > 0 && !actual)) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareUInt8(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFF;
        expected = expected & 0xFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareInt8(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFF;
        expected = expected & 0xFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareUInt16(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFF;
        expected = expected & 0xFFFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareInt16(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFF;
        expected = expected & 0xFFFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareUInt32(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFFFFFF;
        expected = expected & 0xFFFFFFFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareInt32(int actual, Integer expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFFFFFF;
        expected = expected & 0xFFFFFFFF;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareUInt64(long actual, Long expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFFFFFFFFFFFFFFL;
        expected = expected & 0xFFFFFFFFFFFFFFFFL;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareInt64(long actual, Long expected, String msg) {
        if (expected == null) {
            return true;
        }

        actual = actual & 0xFFFFFFFFFFFFFFFFL;
        expected = expected & 0xFFFFFFFFFFFFFFFFL;
        if (actual != expected) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareFp(float actual, Float expected, String msg) {
        if (expected == null) {
            return true;
        }

        if (Float.floatToIntBits(actual) != Float.floatToIntBits(expected)) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareDp(double actual, Double expected, String msg) {
        if (expected == null) {
            return true;
        }

        if (Double.doubleToLongBits(actual) != Double.doubleToLongBits(expected)) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }

    public static boolean compareEnum(long actual, String expected, String msg) {
        if (expected == null) {
            return true;
        }

        long enumVal = cs_const_getattr(expected);
        if (actual != enumVal) {
            log.severe(msg + ": " + actual + " != " + expected + " (" + enumVal + ")");
            return false;
        }
        return true;
    }

    public static boolean compareBitFlags(long actual, List<String> expected, String msg) {
        if (expected == null) {
            return true;
        }

        for (String flag : expected) {
            long enumVal = cs_const_getattr(flag);
            if ((actual & enumVal) == 0L) {
                log.severe(msg + ": In " + Long.toHexString(actual) + " the flag " + flag + " isn't set.");
                return false;
            }
        }
        return true;
    }

    public static boolean compareReg(Capstone.CsInsn insn, int actual, String expected, String msg) {
        if (expected == null) {
            return true;
        }

        if (insn.regName(actual) == null) {
            log.severe(msg + ": " + actual + " isn't a valid register id");
            return false;
        }

        if (!insn.regName(actual).equals(expected)) {
            log.severe(msg + ": " + actual + " != " + expected);
            return false;
        }
        return true;
    }
}
