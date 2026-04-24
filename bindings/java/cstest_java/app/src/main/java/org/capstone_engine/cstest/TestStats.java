// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.List;

public class TestStats {
    private static final Logger log = Logger.getLogger(TestStats.class.getName());

    private int totalFileCount;
    private int validTestFiles;
    private int testCaseCount;
    private int success;
    private int failed;
    private int skipped;
    private int errors;
    private int invalidFiles;
    private int totalValidFiles;
    private List<String> errMsgs;
    private Set<Path> failingFiles;

    public TestStats(int totalFileCount) {
        this.totalFileCount = totalFileCount;
        this.validTestFiles = 0;
        this.testCaseCount = 0;
        this.success = 0;
        this.failed = 0;
        this.skipped = 0;
        this.errors = 0;
        this.invalidFiles = 0;
        this.totalValidFiles = 0;
        this.errMsgs = new ArrayList<>();
        this.failingFiles = new HashSet<>();
    }

    public void addFailingFile(Path testFile) {
        this.failingFiles.add(testFile);
    }

    public void addErrorMsg(String msg) {
        this.errMsgs.add(msg);
    }

    public void addInvalidFileDp(Path tfile) {
        this.invalidFiles++;
        this.errors++;
        this.addFailingFile(tfile);
    }

    public void addTestCaseDataPoint(TestResult dp) {
        switch (dp) {
            case SUCCESS:
                this.success++;
                break;
            case FAILED:
                this.failed++;
                break;
            case SKIPPED:
                this.skipped++;
                break;
            case ERROR:
                this.errors++;
                this.failed++;
                break;
            default:
                throw new IllegalArgumentException("Unhandled TestResult: " + dp);
        }
    }

    public void setTotalValidFiles(int totalValidFiles) {
        this.totalValidFiles = totalValidFiles;
    }

    public void setTotalTestCases(int totalTestCases) {
        this.testCaseCount = totalTestCases;
    }

    public int getTestCaseCount() {
        return this.testCaseCount;
    }

    public void printEvaluate() {
        if (this.totalFileCount == 0) {
            log.severe("No test files found!");
            System.exit(-1);
        }
        if (this.testCaseCount == 0) {
            log.severe("No test cases found!");
            System.exit(-1);
        }
        if (!this.failingFiles.isEmpty()) {
            System.out.println("Test files with failures:");
            for (Path tf : this.failingFiles) {
                System.out.println(" - " + tf);
            }
            System.out.println();
        }
        if (!this.errMsgs.isEmpty()) {
            System.out.println("Error messages:");
            for (String error : this.errMsgs) {
                System.out.println(" - " + error);
            }
        }

        System.out.println("\n-----------------------------------------");
        System.out.println("Test run statistics\n");
        System.out.println("Valid files: " + this.totalValidFiles);
        System.out.println("Invalid files: " + this.invalidFiles);
        System.out.println("Errors: " + this.errors + "\n");
        System.out.println("Test cases:");
        System.out.println("\tTotal: " + this.testCaseCount);
        System.out.println("\tSuccessful: " + this.success);
        System.out.println("\tSkipped: " + this.skipped);
        System.out.println("\tFailed: " + this.failed);
        System.out.println("-----------------------------------------");
        System.out.println("");

        if (this.testCaseCount != this.success + this.failed + this.skipped) {
            log.severe("Inconsistent statistics: total != successful + failed + skipped\n");
            System.exit(-1);
        }

        if (this.errors != 0) {
            log.severe("Failed with errors\n");
            System.exit(-1);
        } else if (this.failed != 0) {
            log.severe("Not all tests succeeded\n");
            System.exit(-1);
        }
        log.info("All tests succeeded.\n");
        System.exit(0);
    }
}
