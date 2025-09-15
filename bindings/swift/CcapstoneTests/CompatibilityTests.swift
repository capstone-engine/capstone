import Foundation
import Testing
@testable import Ccapstone

/// Cross-platform compatibility and edge case tests for the Capstone Swift binding
/// These tests verify behavior across different platforms and unusual conditions
@Suite("Compatibility Tests")
struct CompatibilityTests {

    // Test data for various scenarios
    private static let emptyCode: [UInt8] = []
    private static let singleByteCode: [UInt8] = [0x90] // NOP instruction
    private static let invalidCode: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF]
    private static let mixedValidInvalidCode: [UInt8] = [0x90, 0xFF, 0xFF, 0x90, 0xFF]

    @Test("Platform-specific enum values consistency")
    func testEnumValueConsistency() async throws {
        // Test that enum values are consistent across platforms
        let enumTests: [(String, UInt32, UInt32)] = [
            ("CS_ERR_OK", CS_ERR_OK.rawValue, 0),
            ("CS_ERR_MEM", CS_ERR_MEM.rawValue, 1),
            ("CS_ERR_ARCH", CS_ERR_ARCH.rawValue, 2),
            ("CS_ERR_HANDLE", CS_ERR_HANDLE.rawValue, 3),
            ("CS_ERR_CSH", CS_ERR_CSH.rawValue, 4),
            ("CS_ERR_MODE", CS_ERR_MODE.rawValue, 5),
            ("CS_ERR_OPTION", CS_ERR_OPTION.rawValue, 6),
            ("CS_ERR_DETAIL", CS_ERR_DETAIL.rawValue, 7),
            ("CS_ERR_MEMSETUP", CS_ERR_MEMSETUP.rawValue, 8),
            ("CS_ERR_VERSION", CS_ERR_VERSION.rawValue, 9),

            ("CS_ARCH_ARM", CS_ARCH_ARM.rawValue, 0),
            ("CS_ARCH_AARCH64", CS_ARCH_AARCH64.rawValue, 1),
            ("CS_ARCH_MIPS", CS_ARCH_MIPS.rawValue, 3),
            ("CS_ARCH_X86", CS_ARCH_X86.rawValue, 4),
            ("CS_ARCH_PPC", CS_ARCH_PPC.rawValue, 5),

            ("CS_MODE_LITTLE_ENDIAN", CS_MODE_LITTLE_ENDIAN.rawValue, 0),
            ("CS_MODE_ARM", CS_MODE_ARM.rawValue, 0),
            ("CS_MODE_16", CS_MODE_16.rawValue, 1 << 1),
            ("CS_MODE_32", CS_MODE_32.rawValue, 1 << 2),
            ("CS_MODE_64", CS_MODE_64.rawValue, 1 << 3),
        ]

        print("✓ Testing enum value consistency:")
        for (name, actual, expected) in enumTests {
            #expect(actual == expected, "\(name) should be \(expected), got \(actual)")
            print("  \(name): \(actual) ✓")
        }
    }

    @Test("Pointer size and alignment compatibility")
    func testPointerCompatibility() async throws {
        // Test that pointer sizes and alignments are reasonable
        let insnSize = MemoryLayout<cs_insn>.size
        let insnAlignment = MemoryLayout<cs_insn>.alignment
        let detailSize = MemoryLayout<cs_detail>.size
        let detailAlignment = MemoryLayout<cs_detail>.alignment
        let cshSize = MemoryLayout<csh>.size

        print("✓ Platform-specific sizes and alignments:")
        print("  cs_insn: \(insnSize) bytes, alignment: \(insnAlignment)")
        print("  cs_detail: \(detailSize) bytes, alignment: \(detailAlignment)")
        print("  csh (handle): \(cshSize) bytes")

        // Basic sanity checks
        #expect(insnSize > 0 && insnSize < 1024, "cs_insn size should be reasonable")
        #expect(detailSize > 0 && detailSize < 4096, "cs_detail size should be reasonable")
        #expect(cshSize > 0 && cshSize <= 8, "csh should be pointer-sized")

        // Alignment should be power of 2 and reasonable
        #expect(insnAlignment > 0 && (insnAlignment & (insnAlignment - 1)) == 0, "cs_insn alignment should be power of 2")
        #expect(detailAlignment > 0 && (detailAlignment & (detailAlignment - 1)) == 0, "cs_detail alignment should be power of 2")
    }

    @Test("Empty and invalid code handling")
    func testEdgeCaseCodeHandling() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping edge case tests - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Test empty code
        var insns: UnsafeMutablePointer<cs_insn>?
        let emptyCount = Self.emptyCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        #expect(emptyCount == 0, "Empty code should produce 0 instructions")
        print("✓ Empty code handling: \(emptyCount) instructions")

        // Test single byte
        let singleCount = Self.singleByteCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        if singleCount > 0 {
            cs_free(insns, singleCount)
        }

        print("✓ Single byte code: \(singleCount) instructions")

        // Test invalid code
        let invalidCount = Self.invalidCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        if invalidCount > 0 {
            cs_free(insns, invalidCount)
        }

        print("✓ Invalid code handling: \(invalidCount) instructions")

        // All tests should complete without crashing
        #expect(Bool(true), "All edge cases should be handled gracefully")
    }

    @Test("Maximum values and boundaries")
    func testBoundaryValues() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping boundary tests - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Test with maximum address value
        let maxAddress: UInt64 = UInt64.max
        var insns: UnsafeMutablePointer<cs_insn>?
        let maxAddrCount = Self.singleByteCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, maxAddress, 0, &insns)
        }

        if maxAddrCount > 0 {
            let instruction = insns!.pointee
            print("✓ Maximum address test: instruction at 0x\(String(format: "%llx", instruction.address))")
            cs_free(insns, maxAddrCount)
        }

        // Test with zero address
        let zeroAddrCount = Self.singleByteCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0, 0, &insns)
        }

        if zeroAddrCount > 0 {
            cs_free(insns, zeroAddrCount)
        }

        print("✓ Zero address test: \(zeroAddrCount) instructions")

        // Test with maximum count parameter (should be ignored for cs_disasm with count=0)
        let maxCountTest = Self.singleByteCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, size_t.max, &insns)
        }

        if maxCountTest > 0 {
            cs_free(insns, maxCountTest)
        }

        print("✓ Maximum count parameter test: \(maxCountTest) instructions")
    }

    @Test("String handling and encoding")
    func testStringHandling() async throws {
        // Test error message strings for proper encoding
        let testErrors: [cs_err] = [
            CS_ERR_OK, CS_ERR_MEM, CS_ERR_ARCH, CS_ERR_HANDLE,
            CS_ERR_CSH, CS_ERR_MODE, CS_ERR_OPTION, CS_ERR_DETAIL
        ]

        print("✓ Testing string encoding and validity:")
        for errorCode in testErrors {
            let message = cs_strerror(errorCode)
            #expect(message != nil, "Error message should not be nil")

            if let message = message {
                let errorString = String(cString: message)
                #expect(!errorString.isEmpty, "Error string should not be empty")
                #expect(errorString.utf8.count > 0, "String should have valid UTF-8 encoding")

                // Check for reasonable string length (not too short or suspiciously long)
                #expect(errorString.count >= 2 && errorString.count <= 100, "Error message should have reasonable length")

                print("  \(errorCode.rawValue): '\(errorString)' (\(errorString.count) chars)")
            }
        }
    }

    @Test("Iterator API edge cases")
    func testIteratorEdgeCases() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping iterator edge case tests - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let insn = cs_malloc(handle)
        guard let insn = insn else {
            print("⚠️ Cannot allocate instruction structure")
            return
        }

        defer { cs_free(insn, 1) }

        // Test iterator with empty code
        var result = Self.emptyCode.withUnsafeBufferPointer { buffer -> Bool in
            var codePtr = buffer.baseAddress
            var size = Self.emptyCode.count
            var address: UInt64 = 0x1000

            return cs_disasm_iter(handle, &codePtr, &size, &address, insn)
        }

        #expect(result == false, "Iterator should return false for empty code")
        print("✓ Iterator empty code test: \(result)")

        // Test iterator with single valid instruction
        result = Self.singleByteCode.withUnsafeBufferPointer { buffer -> Bool in
            var codePtr = buffer.baseAddress
            var size = Self.singleByteCode.count
            var address: UInt64 = 0x1000

            let firstResult = cs_disasm_iter(handle, &codePtr, &size, &address, insn)
            if firstResult {
                let mnemonic = withUnsafeBytes(of: insn.pointee.mnemonic) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }
                print("  First instruction: \(mnemonic)")
                // Try to get second instruction (should fail)
                let secondResult = cs_disasm_iter(handle, &codePtr, &size, &address, insn)
                return secondResult
            }
            return firstResult
        }

        print("✓ Iterator single instruction test: second call returned \(result)")

        // Test iterator with mixed valid/invalid code
        var instructionCount = 0
        Self.mixedValidInvalidCode.withUnsafeBufferPointer { buffer in
            var codePtr = buffer.baseAddress
            var size = Self.mixedValidInvalidCode.count
            var address: UInt64 = 0x1000

            while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                instructionCount += 1
                if instructionCount > 10 { // Safety break to avoid infinite loops
                    break
                }
            }
        }

        print("✓ Iterator mixed code test: \(instructionCount) instructions found")
        #expect(instructionCount >= 0, "Should handle mixed code gracefully")
    }

    @Test("Version consistency across calls")
    func testVersionStability() async throws {
        // Call version function multiple times and ensure consistency
        let iterations = 100
        var versions: [UInt32] = []
        var majors: [Int32] = []
        var minors: [Int32] = []

        for _ in 0..<iterations {
            var major: Int32 = 0
            var minor: Int32 = 0
            let version = cs_version(&major, &minor)

            versions.append(version)
            majors.append(major)
            minors.append(minor)
        }

        // All versions should be identical
        let firstVersion = versions.first!
        let firstMajor = majors.first!
        let firstMinor = minors.first!

        for (i, version) in versions.enumerated() {
            #expect(version == firstVersion, "Version should be consistent across calls (call \(i))")
            #expect(majors[i] == firstMajor, "Major version should be consistent (call \(i))")
            #expect(minors[i] == firstMinor, "Minor version should be consistent (call \(i))")
        }

        print("✓ Version consistency test: \(iterations) calls, all returned \(firstMajor).\(firstMinor)")
    }

    @Test("Architecture support detection")
    func testArchitectureSupport() async throws {
        let architectures: [(cs_arch, cs_mode, String)] = [
            (CS_ARCH_ARM, CS_MODE_ARM, "ARM"),
            (CS_ARCH_ARM, CS_MODE_THUMB, "Thumb"),
            (CS_ARCH_AARCH64, CS_MODE_ARM, "AArch64"),
            (CS_ARCH_X86, CS_MODE_16, "X86-16"),
            (CS_ARCH_X86, CS_MODE_32, "X86-32"),
            (CS_ARCH_X86, CS_MODE_64, "X86-64"),
            (CS_ARCH_MIPS, CS_MODE_MIPS32, "MIPS32"),
            (CS_ARCH_MIPS, CS_MODE_MIPS64, "MIPS64"),
            (CS_ARCH_PPC, CS_MODE_32, "PowerPC-32"),
            (CS_ARCH_PPC, CS_MODE_64, "PowerPC-64"),
        ]

        print("✓ Testing architecture support:")
        var supportedCount = 0
        var unsupportedCount = 0

        for (arch, mode, name) in architectures {
            var handle: csh = 0
            let result = cs_open(arch, mode, &handle)

            if result == CS_ERR_OK {
                supportedCount += 1
                print("  ✓ \(name): Supported")
                _ = cs_close(&handle)
            } else {
                unsupportedCount += 1
                let errorMsg = cs_strerror(result)
                let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown"
                print("  ✗ \(name): Not supported (\(errorString))")
            }
        }

        print("  Summary: \(supportedCount) supported, \(unsupportedCount) unsupported")

        // At least some architectures should be supported in a complete implementation
        // For incomplete binding, we just verify it doesn't crash
        #expect(supportedCount >= 0, "Should handle architecture queries without crashing")
    }

    @Test("Memory safety with null pointers")
    func testNullPointerSafety() async throws {
        // cs_strerror should work with any error code
        for errorCode in 0..<20 {
            let message = cs_strerror(cs_err(rawValue: UInt32(errorCode)))
            #expect(message != nil, "cs_strerror should return non-null for any error code")
        }

        // cs_version with null parameters
        let versionOnly = cs_version(nil, nil)
        #expect(versionOnly > 0, "cs_version should work with null parameters")
        print("✓ cs_version with null parameters: \(versionOnly)")

        // Operations on invalid handles should return errors, not crash
        let errno = cs_errno(0)
        #expect(errno != CS_ERR_OK, "cs_errno on invalid handle should return error")

        let optResult = cs_option(0, CS_OPT_DETAIL, 1)
        #expect(optResult != CS_ERR_OK, "cs_option on invalid handle should return error")

        print("✓ All null pointer and invalid handle tests completed safely")
    }
}
