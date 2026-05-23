// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

public enum TestResult {
    SUCCESS(0),
    FAILED(1),
    SKIPPED(2),
    ERROR(3);

    private final int value;

    TestResult(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
