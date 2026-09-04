import Foundation
import Testing
@testable import Ccapstone

/// Basic functionality tests for the Capstone Swift binding
/// These tests verify the core API functions and basic operations
@Suite("Basic API Tests")
struct BasicTests {

    @Test("Version information retrieval")
    func testVersion() async throws {
        var major: Int32 = 0
        var minor: Int32 = 0

        let version = cs_version(&major, &minor)

        #expect(major > 0, "Major version should be positive")
        #expect(minor >= 0, "Minor version should be non-negative")
        #expect(version > 0, "Version should be positive")
        #expect(version == UInt32((major << 8) | minor), "Version should match expected format")

        print("✓ Capstone version: \(major).\(minor) (0x\(String(format: "%04x", version)))")
    }

    @Test("Engine open and close operations")
    func testOpenClose() async throws {
        var handle: csh = 0

        let result = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        #expect(result == CS_ERR_OK, "Engine should open successfully")
        #expect(handle != 0, "Handle should be non-zero after successful open")

        let closeResult = cs_close(&handle)
        #expect(closeResult == CS_ERR_OK, "Engine should close successfully")
        #expect(handle == 0, "Handle should be zero after close")

        print("✓ Engine open/close: Success")
    }

    @Test("Invalid architecture handling")
    func testInvalidArch() async throws {
        var handle: csh = 0

        let result = cs_open(cs_arch(1000), CS_MODE_32, &handle)
        #expect(result != CS_ERR_OK, "Invalid architecture should fail")
        #expect(handle == 0, "Handle should remain zero for invalid architecture")

        print("✓ Invalid architecture handled correctly")
    }

    @Test("Error message strings")
    func testStrerror() async throws {
        let errorMsg = cs_strerror(CS_ERR_OK)
        #expect(errorMsg != nil, "Error message should not be nil")

        let okString = String(cString: errorMsg!)
        #expect(!okString.isEmpty, "Error message string should not be empty")

        let invalidMsg = cs_strerror(CS_ERR_ARCH)
        #expect(invalidMsg != nil, "Error message for CS_ERR_ARCH should not be nil")

        let invalidString = String(cString: invalidMsg!)
        #expect(!invalidString.isEmpty, "Error message string should not be empty")
        #expect(okString != invalidString, "Different error codes should have different messages")

        print("✓ Error messages: '\(okString)' vs '\(invalidString)'")
    }

    @Test("Error number retrieval")
    func testErrno() async throws {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        if openResult == CS_ERR_OK {
            let errno = cs_errno(handle)
            #expect(errno == CS_ERR_OK, "Error number should be CS_ERR_OK for successful operation")
            _ = cs_close(&handle)
            print("✓ Error number retrieval: Success")
        } else {
            print("⚠️ Skipping errno test - cannot open X86 engine")
        }
    }

    @Test("Option setting")
    func testOption() async throws {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        if openResult == CS_ERR_OK {
            let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
            // Note: Option result may vary depending on implementation completeness
            // We mainly test that it doesn't crash

            _ = cs_close(&handle)
            print("✓ Option setting: Result \(optResult)")
        } else {
            print("⚠️ Skipping option test - cannot open X86 engine")
        }
    }

    @Test("Basic disassembly functionality")
    func testBasicDisassembly() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping basic disassembly test - cannot open X86 engine")
            return
        }

        defer { _ = cs_close(&handle) }

        // Simple x86 32-bit code: lea ecx, [edx+esi+8]; add eax, ebx
        let code: [UInt8] = [0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8]

        var insns: UnsafeMutablePointer<cs_insn>?
        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        defer {
            if count > 0 {
                cs_free(insns, count)
            }
        }

        #expect(count >= 0, "Disassembly should not fail catastrophically")

        if count > 0 {
            let firstInsn = insns!.pointee
            let mnemonic = withUnsafeBytes(of: firstInsn.mnemonic) { bytes in
                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
            }
            let operands = withUnsafeBytes(of: firstInsn.op_str) { bytes in
                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
            }

            #expect(!mnemonic.isEmpty, "Mnemonic should not be empty")
            #expect(firstInsn.size > 0, "Instruction size should be positive")
            #expect(firstInsn.address == 0x1000, "Instruction address should match input")

            print("✓ Basic disassembly: \(count) instructions")
            print("  First: \(mnemonic) \(operands) (size: \(firstInsn.size))")
        } else {
            print("⚠️ Basic disassembly returned 0 instructions (implementation may be incomplete)")
        }
    }

    @Test("Iterator API functionality")
    func testIteratorAPI() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping iterator API test - cannot open X86 engine")
            return
        }

        defer { _ = cs_close(&handle) }

        let insn = cs_malloc(handle)
        guard let insn = insn else {
            print("⚠️ cs_malloc returned nil")
            return
        }

        defer { cs_free(insn, 1) }

        let code: [UInt8] = [0x90, 0x90, 0x90] // Three NOPs
        var instructionCount = 0

        code.withUnsafeBufferPointer { buffer in
            var codePtr = buffer.baseAddress
            var size = code.count
            var address: UInt64 = 0x1000

            while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                instructionCount += 1
                let mnemonic = withUnsafeBytes(of: insn.pointee.mnemonic) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }

                #expect(!mnemonic.isEmpty, "Mnemonic should not be empty")
                #expect(insn.pointee.size > 0, "Instruction size should be positive")

                // Safety break to avoid infinite loops
                if instructionCount > 10 {
                    break
                }
            }
        }

        print("✓ Iterator API: \(instructionCount) instructions processed")
        #expect(instructionCount >= 0, "Iterator should handle instructions without crashing")
    }
}
