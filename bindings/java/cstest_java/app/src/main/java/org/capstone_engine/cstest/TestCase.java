// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.util.Map;
import java.util.logging.Logger;
import capstone.Capstone;

public class TestCase {
    private static final Logger log = Logger.getLogger(TestCase.class.getName());

    private Map<String, Object> tcDict;
    private TestInput input;
    private TestExpected expected;
    private boolean skip;
    private String skipReason;

    public TestCase(Map<String, Object> testCaseDict) {
        this.tcDict = testCaseDict;
        if (!tcDict.containsKey("input")) {
            throw new IllegalArgumentException("Mandatory field 'input' missing");
        }
        if (!tcDict.containsKey("expected")) {
            throw new IllegalArgumentException("Mandatory field 'expected' missing");
        }
        this.input = new TestInput((Map<String, Object>) tcDict.get("input"));
        this.expected = new TestExpected((Map<String, Object>) tcDict.get("expected"));
        this.skip = tcDict.containsKey("skip");
        if (this.skip && !tcDict.containsKey("skip_reason")) {
            throw new IllegalArgumentException("If 'skip' field is set a 'skip_reason' field must be set as well.");
        }
        this.skipReason = this.skip ? (String) tcDict.get("skip_reason") : "";
    }

    @Override
    public String toString() {
        return input.toString();
    }

    public TestResult test() {
        if (this.skip) {
            log.info("Skip " + this + "\nReason: " + this.skipReason);
            return TestResult.SKIPPED;
        }

        try {
            this.input.setup();
        } catch (Exception e) {
            log.severe("Setup failed with: " + e);
            e.printStackTrace();
            return TestResult.ERROR;
        }

        Capstone.CsInsn[] insns;
        try {
            insns = this.input.decode();
        } catch (Exception e) {
            log.severe("Decode failed with: " + e);
            e.printStackTrace();
            return TestResult.ERROR;
        }

        try {
            return this.expected.compare(insns, this.input.arch_bits);
        } catch (Exception e) {
            log.severe("Compare expected failed with: " + e);
            e.printStackTrace();
            return TestResult.ERROR;
        }
    }
}
