// Capstone Test runner for Java
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import static java.util.Map.entry;

import org.apache.commons.cli.*;
import org.yaml.snakeyaml.error.YAMLException;
import capstone.Capstone;

class CSTest {
    private static final Logger log = Logger.getLogger(CSTest.class.getName());

    private List<Path> yamlPaths;
    private TestStats stats;
    private List<TestFile> testFiles;

    public CSTest(Path path, String[] exclude, String[] include) {
        this.yamlPaths = new ArrayList<>();
        List<String> excludeList = exclude != null ? List.of(exclude) : new ArrayList<>();
        List<String> includeList = include != null ? List.of(include) : new ArrayList<>();

        log.info("Search test files in " + path);
        if (Files.isRegularFile(path)) {
            yamlPaths.add(path);
        } else {
            try {
                Files.walk(path)
                        .filter(Files::isRegularFile)
                        .filter(f -> f.toString().endsWith(".yaml") || f.toString().endsWith(".yml"))
                        .filter(f -> !excludeList.contains(f.getFileName().toString()))
                        .filter(f -> includeList.isEmpty() || includeList.contains(f.getFileName().toString()))
                        .forEach(yamlPaths::add);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        log.info("Test files found: " + yamlPaths.size());
        this.stats = new TestStats(yamlPaths.size());
        this.testFiles = new ArrayList<>();
    }

    public void parseFiles() {
        int totalTestCases = 0;
        int totalFiles = yamlPaths.size();
        int count = 1;
        for (Path tfile : yamlPaths) {
            System.out.print("Parse " + count + "/" + totalFiles + ": " + tfile.getFileName() + "                    \r");
            System.out.flush();
            try {
                TestFile tf = new TestFile(tfile);
                totalTestCases += tf.numTestCases();
                testFiles.add(tf);
            } catch (YAMLException e) {
                stats.addErrorMsg(e.getMessage());
                stats.addInvalidFileDp(tfile);
                log.severe("Error: snakeyaml parser error");
                e.printStackTrace();
                log.severe("Failed to parse test file '" + tfile + "'");
            } catch (Exception e) {
                stats.addErrorMsg(e.getMessage());
                stats.addInvalidFileDp(tfile);
                log.severe("Error: Exception " + e);
                e.printStackTrace();
                log.severe("Failed to parse test file '" + tfile + "'");
            } finally {
                count++;
            }
        }
        stats.setTotalValidFiles(testFiles.size());
        stats.setTotalTestCases(totalTestCases);
        System.out.println("Found " + stats.getTestCaseCount() + " test cases.");
    }

    public void runTests() {
        parseFiles();
        for (TestFile tf : testFiles) {
            log.info("Test file: " + tf);
            for (TestCase tc : tf.getTestCases()) {
                log.info("Run test: " + tc);
                TestResult result;
                try {
                    result = tc.test();
                } catch (Exception e) {
                    result = TestResult.ERROR;
                    stats.addErrorMsg(e.getMessage());
                }
                if (result == TestResult.FAILED || result == TestResult.ERROR) {
                    stats.addFailingFile(tf.getPath());
                }
                stats.addTestCaseDataPoint(result);
                log.info(result.name());
            }
        }
        stats.printEvaluate();
    }
}

public class App {
    private static final Logger log = Logger.getLogger(App.class.getName());

    public static final Map<String, Map<String, Integer>> configs = Map.ofEntries(
        entry("CS_OPT_DETAIL", Map.of("type", Capstone.CS_OPT_DETAIL, "val", Capstone.CS_OPT_ON)),
        entry("CS_OPT_DETAIL_REAL", Map.of("type", Capstone.CS_OPT_DETAIL, "val", Capstone.CS_OPT_DETAIL_REAL | Capstone.CS_OPT_ON)),
        entry("CS_OPT_SKIPDATA", Map.of("type", Capstone.CS_OPT_SKIPDATA, "val", Capstone.CS_OPT_ON)),
        entry("CS_OPT_UNSIGNED", Map.of("type", Capstone.CS_OPT_UNSIGNED, "val", Capstone.CS_OPT_ON)),
        entry("CS_OPT_ONLY_OFFSET_BRANCH", Map.of("type", Capstone.CS_OPT_ONLY_OFFSET_BRANCH, "val", Capstone.CS_OPT_ON)),
        entry("CS_OPT_SYNTAX_DEFAULT", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_DEFAULT)),
        entry("CS_OPT_SYNTAX_INTEL", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_INTEL)),
        entry("CS_OPT_SYNTAX_ATT", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_ATT)),
        entry("CS_OPT_SYNTAX_NOREGNAME", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_NOREGNAME)),
        entry("CS_OPT_SYNTAX_MASM", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_MASM)),
        entry("CS_OPT_SYNTAX_MOTOROLA", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_MOTOROLA)),
        entry("CS_OPT_SYNTAX_CS_REG_ALIAS", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_CS_REG_ALIAS)),
        entry("CS_OPT_SYNTAX_PERCENT", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_PERCENT)),
        entry("CS_OPT_SYNTAX_NO_DOLLAR", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_NO_DOLLAR)),
        entry("CS_OPT_SYNTAX_NO_ALIAS_TEXT", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_NO_ALIAS_TEXT)),
        entry("CS_OPT_SYNTAX_NO_ALIAS_TEXT_COMPRESSED", Map.of("type", Capstone.CS_OPT_SYNTAX, "val", Capstone.CS_OPT_SYNTAX_NO_ALIAS_TEXT_COMPRESSED))

    );

    public static Integer getCsIntAttr(String attr, String errMsgPre) {
        return getCsIntAttr(attr, errMsgPre, true);
    }

    public static Integer getCsIntAttr(String attr, String errMsgPre, boolean logWarning) {
        try {
            return Capstone.class.getField(attr).getInt(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            if (logWarning)
                log.warning(errMsgPre + ": Capstone doesn't have the attribute '" + attr + "'");
            return null;
        }
    }

    public static int archBits(int arch, int mode) {
        if (arch == Capstone.CS_ARCH_AARCH64 || (mode & Capstone.CS_MODE_64) != 0) {
            return 64;
        } else if ((mode & Capstone.CS_MODE_16) != 0) {
            return 16;
        }
        return 32;
    }

    public static String getRepoRoot() {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("git", "rev-parse", "--show-toplevel");
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            String result = new String(process.getInputStream().readAllBytes());
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                log.severe("Could not get repository root directory.");
                return null;
            }
            return result.strip();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static CommandLine parseArgs(String[] args) {
        Options options = new Options();
        

        // String repoRoot = getRepoRoot();
        // if (repoRoot != null) {
        //     options.addOption(Option.builder()
        //             .desc("Directory to search for .yaml test files.")
        //             .hasArg()
        //             .argName("search_dir")
        //             .get());
        // } else {
        //     options.addOption(Option.builder()
        //             .desc("Directory to search for .yaml test files.")
        //             .hasArg()
        //             .argName("search_dir")
        //             .required()
        //             .get());
        // }

        options.addOption(Option.builder("e")
                .longOpt("exclude")
                .desc("List of file names to exclude.")
                .hasArgs()
                .argName("exclude")
                .numberOfArgs(Option.UNLIMITED_VALUES)
                .get());

        options.addOption(Option.builder("i")
                .longOpt("include")
                .desc("List of file names to include.")
                .hasArgs()
                .argName("include")
                .numberOfArgs(Option.UNLIMITED_VALUES)
                .get());

        options.addOption(Option.builder("v")
                .longOpt("verbosity")
                .desc("Verbosity of the log messages.")
                .hasArg()
                .argName("verbosity")
                .get());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("cstest_java [OPTIONS] [SEARCH_DIRECTORY]", options);
            System.exit(1);
        }
        return cmd;
    }
    public static void main(String[] args) {
        CommandLine cmd = parseArgs(args);

        String repoRoot = getRepoRoot();
        String[] additionalArgs = cmd.getArgs();

        if (repoRoot == null && additionalArgs.length == 0) {
            log.warning("Could not get repository root directory. Please provide a search directory.");
            return;
        }
        Path searchPath;
        if (additionalArgs.length == 1) {
            searchPath = Path.of(additionalArgs[0]);
        } else {
            searchPath = Path.of(repoRoot, "/tests/");
        }

        Map<String, java.util.logging.Level> logLevels = Map.of(
            "debug", java.util.logging.Level.FINE,
            "info", java.util.logging.Level.INFO,
            "warning", java.util.logging.Level.WARNING,
            "severe", java.util.logging.Level.SEVERE
        );

        Formatter formatter = new java.util.logging.Formatter() {
            @Override
            public String format(java.util.logging.LogRecord record) {
                return String.format("%-5s - %s%n", record.getLevel().getName(), record.getMessage());
            }
        };

        java.util.logging.ConsoleHandler stderrHandler = new java.util.logging.ConsoleHandler();
        stderrHandler.setFormatter(formatter);
        stderrHandler.setLevel(java.util.logging.Level.WARNING);

        java.util.logging.StreamHandler stdoutHandler = new java.util.logging.StreamHandler(System.out, formatter);
        stdoutHandler.setFilter(new java.util.logging.Filter() {
            @Override
            public boolean isLoggable(LogRecord record) {
                return record.getLevel().intValue() < java.util.logging.Level.WARNING.intValue();
            }
        });
        if (cmd.hasOption("verbosity")) {
            String verbosity = cmd.getOptionValue("verbosity", "info");
            if (logLevels.containsKey(verbosity)) {
                Logger.getLogger("").setLevel(logLevels.get(verbosity));
                stdoutHandler.setLevel(logLevels.get(verbosity));
            } else {
                Logger.getLogger("").setLevel(java.util.logging.Level.INFO);
                stdoutHandler.setLevel(java.util.logging.Level.INFO);
            }
        } else {
            Logger.getLogger("").setLevel(java.util.logging.Level.INFO);
            stdoutHandler.setLevel(java.util.logging.Level.INFO);
        }

        // Remove default handler
        Logger.getLogger("").removeHandler(Logger.getLogger("").getHandlers()[0]);
        Logger.getLogger("").addHandler(stdoutHandler);
        Logger.getLogger("").addHandler(stderrHandler);

        CSTest test = new CSTest(searchPath, cmd.getOptionValues("exclude"), cmd.getOptionValues("include"));
        test.runTests();
    }
}
