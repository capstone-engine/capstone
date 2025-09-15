import XCTest
@testable import Ccapstone

final class ArchitectureTests: XCTestCase {

    // Test code samples for different architectures
    private struct TestPlatform {
        let arch: cs_arch
        let mode: cs_mode
        let code: [UInt8]
        let comment: String
    }

    private let platforms: [TestPlatform] = [
        TestPlatform(
            arch: CS_ARCH_X86,
            mode: CS_MODE_16,
            code: [0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00],
            comment: "X86 16bit"
        ),
        TestPlatform(
            arch: CS_ARCH_X86,
            mode: CS_MODE_32,
            code: [0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00],
            comment: "X86 32bit"
        ),
        TestPlatform(
            arch: CS_ARCH_X86,
            mode: CS_MODE_64,
            code: [0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00],
            comment: "X86 64bit"
        ),
        TestPlatform(
            arch: CS_ARCH_ARM,
            mode: CS_MODE_ARM,
            code: [0xED, 0xFF, 0xFF, 0xEB, 0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5],
            comment: "ARM"
        ),
        TestPlatform(
            arch: CS_ARCH_ARM,
            mode: CS_MODE_THUMB,
            code: [0x70, 0x47, 0xeb, 0x46, 0x83, 0xb0, 0xc9, 0x68],
            comment: "Thumb"
        ),
        TestPlatform(
            arch: CS_ARCH_AARCH64,
            mode: CS_MODE_ARM,
            code: [0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, 0xe1, 0x0b, 0x40, 0xb9],
            comment: "AArch64"
        ),
        TestPlatform(
            arch: CS_ARCH_MIPS,
            mode: cs_mode(CS_MODE_MIPS32.rawValue | CS_MODE_BIG_ENDIAN.rawValue),
            code: [0x0C, 0x10, 0x00, 0x97, 0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x0c, 0x8f, 0xa2, 0x00, 0x00, 0x34, 0x21, 0x34, 0x56],
            comment: "MIPS32 Big-endian"
        ),
        TestPlatform(
            arch: CS_ARCH_MIPS,
            mode: cs_mode(CS_MODE_MIPS64.rawValue | CS_MODE_LITTLE_ENDIAN.rawValue),
            code: [0x56, 0x34, 0x21, 0x34, 0xc2, 0x17, 0x01, 0x00],
            comment: "MIPS64 Little-endian"
        ),
        TestPlatform(
            arch: CS_ARCH_PPC,
            mode: CS_MODE_BIG_ENDIAN,
            code: [0x80, 0x20, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x10, 0x43, 0x23, 0x0e, 0xd0, 0x44, 0x00, 0x80, 0x4c, 0x43, 0x22, 0x02],
            comment: "PowerPC"
        ),
        TestPlatform(
            arch: CS_ARCH_SPARC,
            mode: CS_MODE_BIG_ENDIAN,
            code: [0x80, 0xa0, 0x40, 0x02, 0x85, 0xc2, 0x60, 0x08, 0x85, 0xe8, 0x20, 0x01, 0x81, 0xe8, 0x00, 0x00, 0x90, 0x10, 0x20, 0x01],
            comment: "Sparc"
        ),
        TestPlatform(
            arch: CS_ARCH_SYSTEMZ,
            mode: CS_MODE_BIG_ENDIAN,
            code: [0xed, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x5a, 0x0f, 0x1f, 0xff, 0xc2, 0x09, 0x80, 0x00, 0x00, 0x00, 0x07, 0xf7],
            comment: "SystemZ"
        )
    ]

    func testAllArchitectures() {
        for platform in platforms {
            testArchitecture(platform)
        }
    }

    func testX86Syntax() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        // Test Intel syntax (default)
        let code: [UInt8] = [0x8d, 0x4c, 0x32, 0x08]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertGreaterThan(count, 0)
        if count > 0 && insns != nil {
            let insn = insns![0]
            let opStr = String(cString: withUnsafeBytes(of: insn.op_str) { $0.bindMemory(to: CChar.self).baseAddress! })
            print("Intel syntax: \(opStr)")
            cs_free(insns, count)
        }

        // Test AT&T syntax
        let attResult = cs_option(handle, CS_OPT_SYNTAX, size_t(CS_OPT_SYNTAX_ATT.rawValue))
        if attResult == CS_ERR_OK {
            let attCount = code.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            if attCount > 0 && insns != nil {
                let insn = insns![0]
                let opStr = String(cString: withUnsafeBytes(of: insn.op_str) { $0.bindMemory(to: CChar.self).baseAddress! })
                print("AT&T syntax: \(opStr)")
                cs_free(insns, attCount)
            }
        }

        _ = cs_close(&handle)
    }

    func testMIPSModes() {
        let mipsCodes: [(cs_mode, [UInt8], String)] = [
            (cs_mode(CS_MODE_MIPS32.rawValue | CS_MODE_BIG_ENDIAN.rawValue), [0x0C, 0x10, 0x00, 0x97], "MIPS32 BE"),
            (cs_mode(CS_MODE_MIPS32.rawValue | CS_MODE_LITTLE_ENDIAN.rawValue), [0x97, 0x00, 0x10, 0x0C], "MIPS32 LE"),
            (cs_mode(CS_MODE_MIPS64.rawValue | CS_MODE_BIG_ENDIAN.rawValue), [0x0C, 0x10, 0x00, 0x97], "MIPS64 BE"),
            (cs_mode(CS_MODE_MIPS64.rawValue | CS_MODE_LITTLE_ENDIAN.rawValue), [0x97, 0x00, 0x10, 0x0C], "MIPS64 LE")
        ]

        for (mode, code, comment) in mipsCodes {
            var handle: csh = 0

            let openResult = cs_open(CS_ARCH_MIPS, mode, &handle)
            XCTAssertEqual(openResult, CS_ERR_OK, "Failed to open \(comment)")

            var insns: UnsafeMutablePointer<cs_insn>?
            let count = code.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
            }

            XCTAssertGreaterThanOrEqual(count, 0, "Disassembly failed for \(comment)")

            if count > 0 && insns != nil {
                let insn = insns![0]
                let mnemonic = String(cString: withUnsafeBytes(of: insn.mnemonic) { $0.bindMemory(to: CChar.self).baseAddress! })
                print("\(comment): \(mnemonic)")
                cs_free(insns, count)
            }

            _ = cs_close(&handle)
        }
    }

    func testARMModes() {
        let armTests: [(cs_mode, [UInt8], String)] = [
            (CS_MODE_ARM, [0x04, 0xe0, 0x2d, 0xe5], "ARM mode"),
            (CS_MODE_THUMB, [0x70, 0x47], "Thumb mode"),
            (cs_mode(CS_MODE_THUMB.rawValue | CS_MODE_MCLASS.rawValue), [0x70, 0x47], "Thumb M-Class")
        ]

        for (mode, code, comment) in armTests {
            var handle: csh = 0

            let openResult = cs_open(CS_ARCH_ARM, mode, &handle)
            XCTAssertEqual(openResult, CS_ERR_OK, "Failed to open \(comment)")

            var insns: UnsafeMutablePointer<cs_insn>?
            let count = code.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
            }

            XCTAssertGreaterThanOrEqual(count, 0, "Disassembly failed for \(comment)")

            if count > 0 && insns != nil {
                let insn = insns![0]
                let mnemonic = String(cString: withUnsafeBytes(of: insn.mnemonic) { $0.bindMemory(to: CChar.self).baseAddress! })
                print("\(comment): \(mnemonic)")
                cs_free(insns, count)
            }

            _ = cs_close(&handle)
        }
    }

    private func testArchitecture(_ platform: TestPlatform) {
        var handle: csh = 0
        var insns: UnsafeMutablePointer<cs_insn>?

        let openResult = cs_open(platform.arch, platform.mode, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK, "Failed to open \(platform.comment)")

        let count = platform.code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        XCTAssertGreaterThan(count, 0, "No instructions disassembled for \(platform.comment)")

        if count > 0 && insns != nil {
            print("\n\(platform.comment):")
            for i in 0..<count {
                let insn = insns![Int(i)]
                let address = String(format: "0x%x", insn.address)
                let mnemonic = String(cString: withUnsafeBytes(of: insn.mnemonic) { $0.bindMemory(to: CChar.self).baseAddress! })
                let opStr = String(cString: withUnsafeBytes(of: insn.op_str) { $0.bindMemory(to: CChar.self).baseAddress! })
                print("  \(address)\t\(mnemonic)\t\(opStr)")

                // Validate instruction properties
                XCTAssertGreaterThan(insn.size, 0)
                XCTAssertNotEqual(insn.mnemonic.0, 0)
                XCTAssertEqual(insn.address, 0x1000 + UInt64(calculateOffset(for: i, from: insns!)))
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    // Helper to calculate instruction offset for address validation
    private func calculateOffset(for index: Int, from instructions: UnsafeMutablePointer<cs_insn>) -> Int {
        var offset = 0
        for i in 0..<index {
            offset += Int(instructions[i].size)
        }
        return offset
    }
}