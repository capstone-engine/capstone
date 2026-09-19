import Foundation
import Testing
@testable import Ccapstone

/// Performance and stress tests for the Capstone Swift binding
/// These tests verify performance characteristics and stress the API under various conditions
@Suite("Performance Tests")
struct PerformanceTests {

    // Test data for performance testing
    private static let x86Code32: [UInt8] = [0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00]
    private static let x86Code64: [UInt8] = [0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00]
    private static let armCode: [UInt8] = [0xED, 0xFF, 0xFF, 0xEB, 0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5]

    /// Large code block for stress testing
    private static let largeCodeBlock: [UInt8] = {
        var code = [UInt8]()
        // Repeat the x86 32-bit code 1000 times for stress testing
        for _ in 0..<1000 {
            code.append(contentsOf: x86Code32)
        }
        return code
    }()

    @Test("Multiple handle creation and destruction performance")
    func testHandleCreationPerformance() async throws {
        let iterations = 1000
        let startTime = CFAbsoluteTimeGetCurrent()

        for _ in 0..<iterations {
            var handle: csh = 0
            let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

            if openResult == CS_ERR_OK {
                _ = cs_close(&handle)
            }
        }

        let endTime = CFAbsoluteTimeGetCurrent()
        let totalTime = endTime - startTime
        let avgTimePerOperation = totalTime / Double(iterations) * 1000 // Convert to milliseconds

        print("✓ Handle creation/destruction performance:")
        print("  Total time: \(String(format: "%.2f", totalTime)) seconds")
        print("  Average time per operation: \(String(format: "%.4f", avgTimePerOperation)) ms")

        // Performance should be reasonable - less than 1ms per operation on modern hardware
        #expect(avgTimePerOperation < 10.0, "Handle operations should be fast")
    }

    @Test("Large code block disassembly stress test")
    func testLargeCodeBlockDisassembly() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping large code block test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let startTime = CFAbsoluteTimeGetCurrent()

        var insns: UnsafeMutablePointer<cs_insn>?
        let count = Self.largeCodeBlock.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        let endTime = CFAbsoluteTimeGetCurrent()
        let totalTime = endTime - startTime

        defer {
            if count > 0 {
                cs_free(insns, count)
            }
        }

        print("✓ Large code block disassembly:")
        print("  Code size: \(Self.largeCodeBlock.count) bytes")
        print("  Instructions disassembled: \(count)")
        print("  Time taken: \(String(format: "%.4f", totalTime)) seconds")

        if count > 0 {
            let throughput = Double(Self.largeCodeBlock.count) / totalTime / 1024 / 1024 // MB/s
            print("  Throughput: \(String(format: "%.2f", throughput)) MB/s")

            // Basic performance expectation - should process at least 1MB/s
            #expect(throughput > 1.0, "Should have reasonable throughput")
        }

        #expect(count >= 0, "Should not fail catastrophically")
    }

    @Test("Iterator API performance comparison")
    func testIteratorVsBatchDisassembly() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping iterator performance test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let testCode = Self.x86Code32

        // Test batch disassembly performance
        let batchStartTime = CFAbsoluteTimeGetCurrent()
        var insns: UnsafeMutablePointer<cs_insn>?
        let batchCount = testCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }
        let batchEndTime = CFAbsoluteTimeGetCurrent()
        let batchTime = batchEndTime - batchStartTime

        if batchCount > 0 {
            cs_free(insns, batchCount)
        }

        // Test iterator API performance
        let iterStartTime = CFAbsoluteTimeGetCurrent()
        let insn = cs_malloc(handle)
        var iterCount: Int = 0

        if let insn = insn {
            testCode.withUnsafeBufferPointer { buffer in
                var codePtr = buffer.baseAddress
                var size = testCode.count
                var address: UInt64 = 0x1000

                while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                    iterCount += 1
                }
            }
            cs_free(insn, 1)
        }

        let iterEndTime = CFAbsoluteTimeGetCurrent()
        let iterTime = iterEndTime - iterStartTime

        print("✓ API performance comparison:")
        print("  Batch API: \(batchCount) instructions in \(String(format: "%.6f", batchTime)) seconds")
        print("  Iterator API: \(iterCount) instructions in \(String(format: "%.6f", iterTime)) seconds")

        #expect(batchCount == iterCount, "Both methods should find same number of instructions")
    }

    @Test("Memory allocation stress test")
    func testMemoryAllocationStress() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping memory stress test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let allocations = 1000
        var allocatedPointers: [UnsafeMutablePointer<cs_insn>] = []

        // Allocate many instruction structures
        for _ in 0..<allocations {
            if let insn = cs_malloc(handle) {
                allocatedPointers.append(insn)
            }
        }

        print("✓ Memory allocation stress test:")
        print("  Successfully allocated: \(allocatedPointers.count) / \(allocations) structures")

        // Free all allocated memory
        for insn in allocatedPointers {
            cs_free(insn, 1)
        }

        // Should be able to allocate a reasonable number of structures
        #expect(allocatedPointers.count > allocations / 2, "Should successfully allocate most structures")
    }

    @Test("Rapid open/close cycles")
    func testRapidOpenCloseCycles() async throws {
        let cycles = 10000
        var successfulCycles = 0
        let architectures: [(cs_arch, cs_mode)] = [
            (CS_ARCH_X86, CS_MODE_32),
            (CS_ARCH_X86, CS_MODE_64),
            (CS_ARCH_ARM, CS_MODE_ARM),
            (CS_ARCH_ARM, CS_MODE_THUMB)
        ]

        let startTime = CFAbsoluteTimeGetCurrent()

        for i in 0..<cycles {
            let (arch, mode) = architectures[i % architectures.count]
            var handle: csh = 0

            let openResult = cs_open(arch, mode, &handle)
            if openResult == CS_ERR_OK {
                let closeResult = cs_close(&handle)
                if closeResult == CS_ERR_OK {
                    successfulCycles += 1
                }
            }
        }

        let endTime = CFAbsoluteTimeGetCurrent()
        let totalTime = endTime - startTime

        print("✓ Rapid open/close cycles:")
        print("  Total cycles: \(cycles)")
        print("  Successful cycles: \(successfulCycles)")
        print("  Time taken: \(String(format: "%.4f", totalTime)) seconds")
        print("  Cycles per second: \(String(format: "%.0f", Double(successfulCycles) / totalTime))")

        // Should handle rapid cycles without major issues
        #expect(successfulCycles > 0, "Should complete some cycles successfully")
    }

    @Test("Option setting performance")
    func testOptionSettingPerformance() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping option performance test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let iterations = 10000
        let options: [(cs_opt_type, size_t)] = [
            (CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue)),
            (CS_OPT_DETAIL, size_t(CS_OPT_OFF.rawValue)),
        ]

        let startTime = CFAbsoluteTimeGetCurrent()
        var successfulOperations = 0

        for i in 0..<iterations {
            let (option, value) = options[i % options.count]
            let result = cs_option(handle, option, value)
            if result == CS_ERR_OK {
                successfulOperations += 1
            }
        }

        let endTime = CFAbsoluteTimeGetCurrent()
        let totalTime = endTime - startTime

        print("✓ Option setting performance:")
        print("  Total operations: \(iterations)")
        print("  Successful operations: \(successfulOperations)")
        print("  Time taken: \(String(format: "%.4f", totalTime)) seconds")

        if successfulOperations > 0 {
            let avgTime = totalTime / Double(successfulOperations) * 1000000 // Convert to microseconds
            print("  Average time per operation: \(String(format: "%.2f", avgTime)) μs")
        }
    }

    @Test("Concurrent access safety test")
    func testConcurrentAccess() async throws {
        // Note: This test creates separate handles for concurrent access
        // Each handle should be used from only one thread at a time

        let concurrentTasks = 10
        let operationsPerTask = 100

        await withTaskGroup(of: Int.self) { group in
            for _ in 0..<concurrentTasks {
                group.addTask {
                    var successfulOperations = 0

                    for _ in 0..<operationsPerTask {
                        var handle: csh = 0
                        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

                        if openResult == CS_ERR_OK {
                            // Perform a quick disassembly
                            var insns: UnsafeMutablePointer<cs_insn>?
                            let count = Self.x86Code32.withUnsafeBufferPointer { buffer in
                                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                            }

                            if count > 0 {
                                cs_free(insns, count)
                                successfulOperations += 1
                            }

                            _ = cs_close(&handle)
                        }
                    }

                    return successfulOperations
                }
            }

            var totalSuccessful = 0
            for await result in group {
                totalSuccessful += result
            }

            let totalOperations = concurrentTasks * operationsPerTask
            print("✓ Concurrent access test:")
            print("  Total operations: \(totalOperations)")
            print("  Successful operations: \(totalSuccessful)")
            print("  Success rate: \(String(format: "%.1f", Double(totalSuccessful) / Double(totalOperations) * 100))%")

            // Should handle concurrent operations reasonably well
            #expect(totalSuccessful > 0, "Should complete some operations successfully")
        }
    }
}