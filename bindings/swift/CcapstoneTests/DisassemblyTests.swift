import XCTest
@testable import Ccapstone

final class DisassemblyTests: XCTestCase {

    // Test data from existing tests
    private let x86Code32: [UInt8] = [0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00]
    private let x86Code64: [UInt8] = [0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00]
    private let armCode: [UInt8] = [0xED, 0xFF, 0xFF, 0xEB, 0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5]
    private let thumbCode: [UInt8] = [0x70, 0x47, 0xeb, 0x46, 0x83, 0xb0, 0xc9, 0x68]
    private let aarch64Code: [UInt8] = [0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, 0xe1, 0x0b, 0x40, 0xb9]
    private let mipsCode: [UInt8] = [0x0C, 0x10, 0x00, 0x97, 0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x0c, 0x8f, 0xa2, 0x00, 0x00]
    private let ppcCode: [UInt8] = [0x80, 0x20, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x10, 0x43, 0x23, 0x0e, 0xd0, 0x44, 0x00, 0x80]

    func testX86_32() {
        performDisassemblyTest(
            arch: CS_ARCH_X86,
            mode: CS_MODE_32,
            code: x86Code32,
            comment: "X86 32bit"
        )
    }

    func testX86_64() {
        performDisassemblyTest(
            arch: CS_ARCH_X86,
            mode: CS_MODE_64,
            code: x86Code64,
            comment: "X86 64bit"
        )
    }

    func testARM() {
        performDisassemblyTest(
            arch: CS_ARCH_ARM,
            mode: CS_MODE_ARM,
            code: armCode,
            comment: "ARM"
        )
    }

    func testThumb() {
        performDisassemblyTest(
            arch: CS_ARCH_ARM,
            mode: CS_MODE_THUMB,
            code: thumbCode,
            comment: "Thumb"
        )
    }

    func testAArch64() {
        performDisassemblyTest(
            arch: CS_ARCH_AARCH64,
            mode: CS_MODE_ARM,
            code: aarch64Code,
            comment: "AArch64"
        )
    }

    func testMIPS() {
        performDisassemblyTest(
            arch: CS_ARCH_MIPS,
            mode: cs_mode(CS_MODE_MIPS32.rawValue | CS_MODE_BIG_ENDIAN.rawValue),
            code: mipsCode,
            comment: "MIPS32 Big-endian"
        )
    }

    func testPPC() {
        performDisassemblyTest(
            arch: CS_ARCH_PPC,
            mode: CS_MODE_BIG_ENDIAN,
            code: ppcCode,
            comment: "PowerPC"
        )
    }

    func testDisasmWithDetail() {
        var handle: csh = 0
        var insns: UnsafeMutablePointer<cs_insn>?

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        let count = x86Code32.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertGreaterThan(count, 0)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            for i in 0..<count {
                let insn = insns![Int(i)]
                XCTAssertGreaterThan(insn.size, 0)
                XCTAssertNotEqual(insn.mnemonic.0, 0)  // Check first character is not null

                if insn.detail != nil {
                    let detail = insn.detail!.pointee
                    // Detail structure is valid (we don't check specific contents as they vary)
                    _ = detail
                }
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    func testIteratorAPI() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let insn = cs_malloc(handle)
        XCTAssertNotNil(insn)

        let code = x86Code32
        var size = code.count
        var address: UInt64 = 0x1000

        var count = 0
        let result = code.withUnsafeBufferPointer { buffer in
            var codePtr = buffer.baseAddress
            while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                let instruction = insn!.pointee
                XCTAssertGreaterThan(instruction.size, 0)
                XCTAssertNotEqual(instruction.mnemonic.0, 0)
                count += 1
            }
            return count
        }

        XCTAssertGreaterThan(result, 0)

        cs_free(insn, 1)
        _ = cs_close(&handle)
    }

    func testInvalidCode() {
        var handle: csh = 0
        var insns: UnsafeMutablePointer<cs_insn>?

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        // Test with invalid/empty code
        let invalidCode: [UInt8] = []
        let count = invalidCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertEqual(count, 0)

        _ = cs_close(&handle)
    }

    func testSkipData() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let skipDataResult = cs_option(handle, CS_OPT_SKIPDATA, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(skipDataResult, CS_ERR_OK)

        // Test with some invalid bytes mixed in
        let mixedCode: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF] + x86Code32
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = mixedCode.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertGreaterThan(count, 0)

        if count > 0 && insns != nil {
            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    // Helper function for basic disassembly tests
    private func performDisassemblyTest(arch: cs_arch, mode: cs_mode, code: [UInt8], comment: String) {
        var handle: csh = 0
        var insns: UnsafeMutablePointer<cs_insn>?

        let openResult = cs_open(arch, mode, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK, "Failed to open \(comment)")

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertGreaterThan(count, 0, "No instructions disassembled for \(comment)")
        XCTAssertNotNil(insns, "Instructions pointer is nil for \(comment)")

        if count > 0 && insns != nil {
            print("\n\(comment):")
            for i in 0..<count {
                let insn = insns![Int(i)]
                let address = String(format: "0x%x", insn.address)
                let mnemonic = String(cString: withUnsafeBytes(of: insn.mnemonic) { $0.bindMemory(to: CChar.self).baseAddress! })
                let opStr = String(cString: withUnsafeBytes(of: insn.op_str) { $0.bindMemory(to: CChar.self).baseAddress! })
                print("  \(address)\t\(mnemonic)\t\(opStr)")

                // Basic validation
                XCTAssertGreaterThan(insn.size, 0)
                XCTAssertNotEqual(insn.mnemonic.0, 0)  // Check first character is not null
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }
}