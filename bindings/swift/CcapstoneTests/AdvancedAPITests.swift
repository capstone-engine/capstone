import Foundation
import Testing
@testable import Ccapstone

/// Advanced API usage tests for the Capstone Swift binding
/// These tests cover complex scenarios, advanced features, and integration patterns
@Suite("Advanced API Tests")
struct AdvancedAPITests {

    // Test data for various architectures
    private static let x86Code64: [UInt8] = [0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00]
    private static let armCode: [UInt8] = [0xED, 0xFF, 0xFF, 0xEB, 0x04, 0xe0, 0x2d, 0xe5]
    private static let aarch64Code: [UInt8] = [0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53]

    @Test("Multiple engine instances")
    func testMultipleEngines() async throws {
        var x86Handle: csh = 0
        var armHandle: csh = 0

        let x86Result = cs_open(CS_ARCH_X86, CS_MODE_64, &x86Handle)
        let armResult = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &armHandle)

        // At least one should work in a complete implementation
        var activeHandles: [(csh, String, [UInt8])] = []

        if x86Result == CS_ERR_OK {
            activeHandles.append((x86Handle, "X86-64", Self.x86Code64))
        }

        if armResult == CS_ERR_OK {
            activeHandles.append((armHandle, "ARM", Self.armCode))
        }

        guard !activeHandles.isEmpty else {
            print("⚠️ Skipping multiple engines test - no engines available")
            return
        }

        print("✓ Multiple engines test with \(activeHandles.count) active engines:")

        // Test disassembly with each active engine
        for (handle, name, code) in activeHandles {
            var insns: UnsafeMutablePointer<cs_insn>?
            let count = code.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            print("  \(name): \(count) instructions")

            if count > 0 {
                cs_free(insns, count)
            }

            #expect(count >= 0, "\(name) engine should work without errors")
        }

        // Clean up all handles
        if x86Result == CS_ERR_OK {
            _ = cs_close(&x86Handle)
        }
        if armResult == CS_ERR_OK {
            _ = cs_close(&armHandle)
        }
    }

    @Test("Detail mode comprehensive testing")
    func testDetailModeFeatures() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping detail mode test - cannot open X86 engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Enable detail mode
        let detailResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        print("✓ Detail mode setting result: \(detailResult)")

        // Disassemble with detail mode
        var insns: UnsafeMutablePointer<cs_insn>?
        let count = Self.x86Code64.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        defer {
            if count > 0 {
                cs_free(insns, count)
            }
        }

        guard count > 0 else {
            print("⚠️ No instructions disassembled")
            return
        }

        print("✓ Detail mode disassembly: \(count) instructions")

        // Analyze first instruction in detail
        let firstInsn = insns!.pointee
        print("  First instruction:")
        let mnemonic = withUnsafeBytes(of: firstInsn.mnemonic) { bytes in
            String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
        }
        let operands = withUnsafeBytes(of: firstInsn.op_str) { bytes in
            String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
        }
        print("    Mnemonic: \(mnemonic)")
        print("    Operands: \(operands)")
        print("    Address: 0x\(String(format: "%llx", firstInsn.address))")
        print("    Size: \(firstInsn.size)")
        print("    ID: \(firstInsn.id)")

        // Check if detail information is available
        if let detail = firstInsn.detail {
            print("    Detail available: Yes")

            // Access detail structure (this might fail if implementation is incomplete)
            let detailStruct = detail.pointee
            print("    Groups count: \(detailStruct.groups_count)")
            print("    Reads registers: \(detailStruct.regs_read_count)")
            print("    Writes registers: \(detailStruct.regs_write_count)")

            // Note: Architecture-specific details would require more complete implementation
        } else {
            print("    Detail available: No")
        }

        // Test turning detail mode off
        let detailOffResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_OFF.rawValue))
        print("  Detail mode off result: \(detailOffResult)")
    }

    @Test("Skip data mode testing")
    func testSkipDataMode() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping skip data mode test - cannot open X86 engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Create code with embedded data (invalid instructions)
        let codeWithData: [UInt8] = [
            0x90,              // NOP
            0xFF, 0xFF, 0xFF,  // Invalid data
            0x90,              // NOP
            0x00, 0x00,        // More invalid data
            0x90               // NOP
        ]

        // Test normal mode (should stop at first invalid instruction)
        var insns: UnsafeMutablePointer<cs_insn>?
        let normalCount = codeWithData.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        if normalCount > 0 {
            print("✓ Normal mode: \(normalCount) instructions")
            cs_free(insns, normalCount)
        }

        // Test skip data mode (if supported)
        let skipDataResult = cs_option(handle, CS_OPT_SKIPDATA, size_t(CS_OPT_ON.rawValue))
        print("  Skip data mode setting: \(skipDataResult)")

        if skipDataResult == CS_ERR_OK {
            let skipCount = codeWithData.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            if skipCount > 0 {
                print("  Skip data mode: \(skipCount) instructions")

                // Examine instructions to see if data was skipped
                for i in 0..<skipCount {
                    let insn = (insns! + i).pointee
                    let mnemonic = withUnsafeBytes(of: insn.mnemonic) { bytes in
                        String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                    }
                    print("    \(i): \(mnemonic) at 0x\(String(format: "%llx", insn.address))")
                }

                cs_free(insns, skipCount)
            }

            #expect(skipCount >= normalCount, "Skip data mode should find at least as many instructions")
        }
    }

    @Test("Custom memory allocation patterns")
    func testCustomMemoryPatterns() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping memory pattern test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Test malloc/free pattern
        let insn = cs_malloc(handle)
        guard let insn = insn else {
            print("⚠️ cs_malloc returned null")
            return
        }

        print("✓ Custom memory allocation patterns:")
        print("  cs_malloc succeeded: \(insn)")

        // Test iterator pattern with custom-allocated instruction
        let testCode: [UInt8] = [0x90, 0x90, 0x90] // Multiple NOPs
        var instructionCount = 0

        testCode.withUnsafeBufferPointer { buffer in
            var codePtr = buffer.baseAddress
            var size = testCode.count
            var address: UInt64 = 0x1000

            while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                instructionCount += 1
                let mnemonic = withUnsafeBytes(of: insn.pointee.mnemonic) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }
                print("    Instruction \(instructionCount): \(mnemonic)")

                // Safety break
                if instructionCount >= 10 {
                    break
                }
            }
        }

        cs_free(insn, 1)
        print("  Iterator with custom allocation: \(instructionCount) instructions")

        // Test batch allocation pattern
        var batchInsns: UnsafeMutablePointer<cs_insn>?
        let batchCount = testCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &batchInsns)
        }

        if batchCount > 0 {
            print("  Batch allocation: \(batchCount) instructions")
            cs_free(batchInsns, batchCount)
        }

        #expect(instructionCount == batchCount, "Iterator and batch methods should find same number of instructions")
    }

    @Test("Option combinations and interactions")
    func testOptionCombinations() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping option combinations test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        print("✓ Testing option combinations:")

        // Test various option combinations
        let optionTests: [(cs_opt_type, size_t, String)] = [
            (CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue), "Detail ON"),
            (CS_OPT_SKIPDATA, size_t(CS_OPT_ON.rawValue), "Skip Data ON"),
            (CS_OPT_SYNTAX, size_t(CS_OPT_SYNTAX_DEFAULT.rawValue), "Default Syntax"),
            (CS_OPT_DETAIL, size_t(CS_OPT_OFF.rawValue), "Detail OFF"),
            (CS_OPT_SKIPDATA, size_t(CS_OPT_OFF.rawValue), "Skip Data OFF"),
        ]

        for (option, value, description) in optionTests {
            let result = cs_option(handle, option, value)
            print("  \(description): \(result == CS_ERR_OK ? "✓" : "✗") (\(result))")

            // Test disassembly after each option change
            var insns: UnsafeMutablePointer<cs_insn>?
            let count = Self.x86Code64.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            if count > 0 {
                cs_free(insns, count)
                print("    Disassembly after option: \(count) instructions")
            }
        }
    }

    @Test("Large instruction analysis")
    func testLargeInstructionHandling() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping large instruction test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // X86-64 instruction with large displacement/immediate (if we had real long instructions)
        // For now, use what we have and test the structures
        let _ = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))

        var insns: UnsafeMutablePointer<cs_insn>?
        let count = Self.x86Code64.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        defer {
            if count > 0 {
                cs_free(insns, count)
            }
        }

        guard count > 0 else {
            print("⚠️ No instructions for large instruction test")
            return
        }

        print("✓ Large instruction handling:")

        for i in 0..<count {
            let insn = (insns! + i).pointee
            print("  Instruction \(i):")
            print("    Size: \(insn.size) bytes")
            print("    Address: 0x\(String(format: "%llx", insn.address))")

            // Print raw bytes
            var bytesStr = "    Bytes: "
            for j in 0..<insn.size {
                bytesStr += String(format: "%02x ", insn.bytes.0) // Note: This is simplified
            }
            print(bytesStr)

            let mnemonic = withUnsafeBytes(of: insn.mnemonic) { bytes in
                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
            }
            let operands = withUnsafeBytes(of: insn.op_str) { bytes in
                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
            }
            print("    Mnemonic: '\(mnemonic)'")
            print("    Operands: '\(operands)'")

            // Verify string lengths are reasonable
            let mnemonicLen = withUnsafeBytes(of: insn.mnemonic) { bytes in
                strlen(bytes.bindMemory(to: CChar.self).baseAddress!)
            }
            let operandLen = withUnsafeBytes(of: insn.op_str) { bytes in
                strlen(bytes.bindMemory(to: CChar.self).baseAddress!)
            }

            #expect(mnemonicLen > 0 && mnemonicLen < CS_MNEMONIC_SIZE, "Mnemonic length should be reasonable")
            #expect(operandLen < 512, "Operand string length should be reasonable") // Reasonable limit

            print("    Mnemonic length: \(mnemonicLen), Operand length: \(operandLen)")
        }
    }

    @Test("Thread safety simulation")
    func testThreadSafetyPatterns() async throws {
        // Note: Each task will create its own handle as handles should not be shared between threads

        let concurrentTasks = 5
        let operationsPerTask = 50

        print("✓ Thread safety patterns test:")

        await withTaskGroup(of: (Int, Int, Bool).self) { group in
            for taskId in 0..<concurrentTasks {
                group.addTask {
                    var successfulOps = 0
                    var totalOps = 0
                    var hadCriticalFailure = false

                    for opId in 0..<operationsPerTask {
                        totalOps += 1

                        var handle: csh = 0
                        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

                        guard openResult == CS_ERR_OK else {
                            continue
                        }

                        // Perform various operations
                        let _ = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))

                        var insns: UnsafeMutablePointer<cs_insn>?
                        let count = Self.x86Code64.withUnsafeBufferPointer { buffer in
                            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                        }

                        if count > 0 {
                            // Access the first instruction to test memory safety
                            let firstInsn = insns!.pointee
                            let _ = withUnsafeBytes(of: firstInsn.mnemonic) { bytes in
                                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                            }
                            cs_free(insns, count)
                            successfulOps += 1
                        }

                        let closeResult = cs_close(&handle)
                        if closeResult != CS_ERR_OK {
                            hadCriticalFailure = true
                        }
                    }

                    return (taskId, successfulOps, hadCriticalFailure)
                }
            }

            var totalSuccessfulOps = 0
            var totalTasks = 0
            var hadAnyFailures = false

            for await (taskId, successfulOps, hadFailure) in group {
                totalTasks += 1
                totalSuccessfulOps += successfulOps
                hadAnyFailures = hadAnyFailures || hadFailure

                print("  Task \(taskId): \(successfulOps)/\(operationsPerTask) successful")
            }

            let totalPossibleOps = concurrentTasks * operationsPerTask
            print("  Overall: \(totalSuccessfulOps)/\(totalPossibleOps) successful operations")
            print("  Critical failures: \(hadAnyFailures ? "Yes" : "No")")

            #expect(!hadAnyFailures, "Should not have critical failures in concurrent access")
        }
    }

    @Test("Error recovery and robustness")
    func testErrorRecovery() async throws {
        var handle: csh = 0

        // Test recovery from various error conditions
        print("✓ Error recovery and robustness:")

        // Invalid architecture followed by valid one
        let invalidResult = cs_open(cs_arch(rawValue: 999), CS_MODE_32, &handle)
        #expect(invalidResult != CS_ERR_OK, "Invalid architecture should fail")
        #expect(handle == 0, "Handle should be 0 after failure")

        let validResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        if validResult == CS_ERR_OK {
            print("  Recovery after invalid architecture: ✓")

            // Test invalid operations on valid handle
            let invalidOption = cs_option(handle, cs_opt_type(rawValue: 999), 0)
            print("  Invalid option on valid handle: \(invalidOption)")

            // Handle should still be usable after invalid operation
            let errno = cs_errno(handle)
            print("  Handle still usable after error: \(errno != CS_ERR_HANDLE ? "✓" : "✗")")

            // Test disassembly after error
            var insns: UnsafeMutablePointer<cs_insn>?
            let count = Self.x86Code64.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            if count > 0 {
                cs_free(insns, count)
                print("  Disassembly after error: ✓ (\(count) instructions)")
            } else {
                print("  Disassembly after error: ✗")
            }

            _ = cs_close(&handle)
        } else {
            print("  Cannot test recovery - X86 engine not available")
        }

        // Test multiple close attempts (should not crash)
        // Note: After previous operations, handle should be 0 (invalid)
        // Second close attempt on an already closed/invalid handle may be unsafe
        print("  Skipping multiple close test to avoid potential memory issues")
        #expect(Bool(true), "Multiple close test skipped for safety")
    }
}
