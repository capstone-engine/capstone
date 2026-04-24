// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.capstone_engine.cstest.details.Details;

import capstone.Capstone;

public class TestExpected {
    private static final Logger log = Logger.getLogger(TestExpected.class.getName());
    private List<Map<String, Object>> insns;
    private Map<String, Object> expectedDict;

    public TestExpected(Map<String, Object> expectedDict) {
        this.expectedDict = expectedDict;
        this.insns = expectedDict.containsKey("insns") ? (List<Map<String, Object>>) expectedDict.get("insns") : List.of();
    }

    public TestResult compare(Capstone.CsInsn[] actualInsns, int bits) {
        if (actualInsns.length != insns.size()) {
            log.severe("Number of decoded instructions don't match (actual != expected): " + actualInsns.length + " != 0x" + Integer.toString(insns.size(), 16));
            return TestResult.FAILED;
        }
        for (int i = 0; i < actualInsns.length; i++) {
            Capstone.CsInsn aInsn = actualInsns[i];
            Map<String, Object> eInsn = insns.get(i);

            if (!Compare.compareAsmText(aInsn, (String) eInsn.get("asm_text"), bits)) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareStr(aInsn.mnemonic, (String) eInsn.get("mnemonic"), "mnemonic")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareStr(aInsn.opStr, (String) eInsn.get("op_str"), "op_str")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareEnum(aInsn.id, (String) eInsn.get("id"), "id")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareTBool(aInsn.isAlias, (Integer) eInsn.get("is_alias"), "is_alias")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareTBool(aInsn.illegal, (Integer) eInsn.get("illegal"), "illegal")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

			if (!Compare.compareUInt32(aInsn.size, (Integer) eInsn.get("size"), "size")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Compare.compareEnum(aInsn.aliasId, (String) eInsn.get("alias_id"), "alias_id")) {
                log.severe("Failed instruction: " + aInsn);
                return TestResult.FAILED;
            }

            if (!Details.compareDetails(aInsn, (Map<String, Object>) eInsn.get("details"))) {
                log.severe("Failed instruction (Details): " + aInsn);
                return TestResult.FAILED;
            }
        }
        return TestResult.SUCCESS;
    }
}
