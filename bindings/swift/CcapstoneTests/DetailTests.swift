import XCTest
@testable import Ccapstone

final class DetailTests: XCTestCase {
    func testX86Detail() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        // mov rax, qword ptr [rip + 0x13b8]
        let code: [UInt8] = [0x48, 0x8B, 0x05, 0xB8, 0x13, 0x00, 0x00]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
        }

        XCTAssertEqual(count, 1)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            let insn = insns![0]
            XCTAssertNotNil(insn.detail)

            if insn.detail != nil {
                let detail = insn.detail!.pointee
                let x86Detail = detail.x86

                // Check basic detail properties
                XCTAssertGreaterThanOrEqual(detail.regs_read_count, 0)
                XCTAssertGreaterThanOrEqual(detail.regs_write_count, 0)
                XCTAssertGreaterThanOrEqual(detail.groups_count, 0)

                // Check X86-specific details
                XCTAssertGreaterThan(x86Detail.op_count, 0)
                XCTAssertLessThanOrEqual(x86Detail.op_count, 8)

                print("X86 Detail:")
                print("  Instruction ID: \(insn.id)")
                print("  Groups count: \(detail.groups_count)")
                print("  Regs read count: \(detail.regs_read_count)")
                print("  Regs write count: \(detail.regs_write_count)")
                print("  Operands count: \(x86Detail.op_count)")

                // Print operand information
                let operands = withUnsafeBytes(of: x86Detail.operands) { bytes in
                    return bytes.bindMemory(to: cs_x86_op.self)
                }

                for i in 0 ..< min(Int(x86Detail.op_count), 8) {
                    let operand = operands[i]
                    print("    Operand \(i): type=\(operand.type.rawValue), size=\(operand.size)")
                }
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    func testARMDetail() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        // str lr, [sp, #-4]!
        let code: [UInt8] = [0x04, 0xE0, 0x2D, 0xE5]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
        }

        XCTAssertEqual(count, 1)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            let insn = insns![0]
            XCTAssertNotNil(insn.detail)

            if insn.detail != nil {
                let detail = insn.detail!.pointee
                let armDetail = detail.arm

                // Check basic detail properties
                XCTAssertGreaterThanOrEqual(detail.regs_read_count, 0)
                XCTAssertGreaterThanOrEqual(detail.regs_write_count, 0)
                XCTAssertGreaterThanOrEqual(detail.groups_count, 0)

                // Check ARM-specific details
                XCTAssertGreaterThan(armDetail.op_count, 0)
                XCTAssertLessThanOrEqual(armDetail.op_count, 36)

                print("ARM Detail:")
                print("  Instruction ID: \(insn.id)")
                print("  Groups count: \(detail.groups_count)")
                print("  Regs read count: \(detail.regs_read_count)")
                print("  Regs write count: \(detail.regs_write_count)")
                print("  Operands count: \(armDetail.op_count)")
                print("  CC: \(armDetail.cc.rawValue)")
                print("  Update flags: \(armDetail.update_flags)")
                // print("  Writeback: \(armDetail.writeback)") // Not available in this struct
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    func testAArch64Detail() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        // add x1, x1, x2
        let code: [UInt8] = [0x21, 0x00, 0x02, 0x8B]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
        }

        XCTAssertEqual(count, 1)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            let insn = insns![0]
            XCTAssertNotNil(insn.detail)

            if insn.detail != nil {
                let detail = insn.detail!.pointee
                let aarch64Detail = detail.aarch64

                // Check basic detail properties
                XCTAssertGreaterThanOrEqual(detail.regs_read_count, 0)
                XCTAssertGreaterThanOrEqual(detail.regs_write_count, 0)
                XCTAssertGreaterThanOrEqual(detail.groups_count, 0)

                // Check AArch64-specific details
                XCTAssertGreaterThan(aarch64Detail.op_count, 0)
                XCTAssertLessThanOrEqual(aarch64Detail.op_count, 8)

                print("AArch64 Detail:")
                print("  Instruction ID: \(insn.id)")
                print("  Groups count: \(detail.groups_count)")
                print("  Regs read count: \(detail.regs_read_count)")
                print("  Regs write count: \(detail.regs_write_count)")
                print("  Operands count: \(aarch64Detail.op_count)")
                print("  CC: \(aarch64Detail.cc.rawValue)")
                print("  Update flags: \(aarch64Detail.update_flags)")
                // print("  Writeback: \(aarch64Detail.writeback)") // Not available in this struct
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    func testMIPSDetail() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32.rawValue | CS_MODE_BIG_ENDIAN.rawValue), &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        // jal 0x97000c
        let code: [UInt8] = [0x0C, 0x10, 0x00, 0x97]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
        }

        XCTAssertEqual(count, 1)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            let insn = insns![0]
            XCTAssertNotNil(insn.detail)

            if insn.detail != nil {
                let detail = insn.detail!.pointee
                let mipsDetail = detail.mips

                // Check basic detail properties
                XCTAssertGreaterThanOrEqual(detail.regs_read_count, 0)
                XCTAssertGreaterThanOrEqual(detail.regs_write_count, 0)
                XCTAssertGreaterThanOrEqual(detail.groups_count, 0)

                // Check MIPS-specific details
                XCTAssertGreaterThan(mipsDetail.op_count, 0)
                XCTAssertLessThanOrEqual(mipsDetail.op_count, 4)

                print("MIPS Detail:")
                print("  Instruction ID: \(insn.id)")
                print("  Groups count: \(detail.groups_count)")
                print("  Regs read count: \(detail.regs_read_count)")
                print("  Regs write count: \(detail.regs_write_count)")
                print("  Operands count: \(mipsDetail.op_count)")
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }

    func testInstructionGroups() {
        var handle: csh = 0

        let openResult = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)
        XCTAssertEqual(openResult, CS_ERR_OK)

        let optResult = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        XCTAssertEqual(optResult, CS_ERR_OK)

        // ret instruction
        let code: [UInt8] = [0xC3]
        var insns: UnsafeMutablePointer<cs_insn>?

        let count = code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 1, &insns)
        }

        XCTAssertEqual(count, 1)
        XCTAssertNotNil(insns)

        if count > 0 && insns != nil {
            let insn = insns![0]
            XCTAssertNotNil(insn.detail)

            if insn.detail != nil {
                let detail = insn.detail!.pointee

                print("Instruction groups:")
                print("  Groups count: \(detail.groups_count)")

                // Check if this instruction belongs to some groups
                let groups = withUnsafeBytes(of: detail.groups) { bytes in
                    return bytes.bindMemory(to: UInt8.self)
                }

                for i in 0 ..< min(Int(detail.groups_count), 16) {
                    let group = groups[i]
                    print("    Group \(i): \(group)")
                }
            }

            cs_free(insns, count)
        }

        _ = cs_close(&handle)
    }
}
