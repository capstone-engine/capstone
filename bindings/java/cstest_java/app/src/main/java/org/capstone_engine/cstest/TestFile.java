// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

public class TestFile {
    private Path path;
    private List<TestCase> testCases;

    public TestFile(Path tfilePath) throws IOException, YAMLException {
        this.path = tfilePath;
        this.testCases = new ArrayList<>();
        Yaml yaml = new Yaml();
        try {
            String content = Files.readString(tfilePath);
            Map<String, Object> yamlContent = yaml.load(content);
            if (yamlContent == null) {
                throw new IllegalArgumentException("Empty file");
            }
            List<Map<String, Object>> testCasesList = (List<Map<String, Object>>) yamlContent.get("test_cases");
            for (Map<String, Object> tcDict : testCasesList) {
                TestCase tc = new TestCase(tcDict);
                this.testCases.add(tc);
            }
        } catch (YAMLException e) {
            throw e;
        }
    }

    public Path getPath() {
        return this.path;
    }

    public List<TestCase> getTestCases() {
        return this.testCases;
    }

    public int numTestCases() {
        return this.testCases.size();
    }

    @Override
    public String toString() {
        return this.path.toString();
    }
}
