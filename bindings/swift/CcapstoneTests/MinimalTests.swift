import Foundation
import XCTest
@testable import Ccapstone

/// Minimal tests that only use core Capstone functions
/// These tests avoid architecture-specific functionality that requires complete linking
final class MinimalTests: XCTestCase {

    func testVersionAPI() {
        var major: Int32 = 0
        var minor: Int32 = 0

        let version = cs_version(&major, &minor)

        XCTAssertGreaterThan(major, 0, "Major version should be positive")
        XCTAssertGreaterThanOrEqual(minor, 0, "Minor version should be non-negative")
        XCTAssertGreaterThan(version, 0, "Combined version should be positive")
        XCTAssertEqual(version, UInt32((major << 8) | minor), "Version should match expected format")

        print("✓ Capstone version: \(major).\(minor) (0x\(String(format: "%04x", version)))")
    }

    func testErrorStrings() {
        let testErrors: [(cs_err, String)] = [
            (CS_ERR_OK, "OK"),
            (CS_ERR_MEM, "Memory"),
            (CS_ERR_ARCH, "Architecture"),
            (CS_ERR_HANDLE, "Handle"),
            (CS_ERR_CSH, "CSH"),
            (CS_ERR_MODE, "Mode"),
            (CS_ERR_OPTION, "Option")
        ]

        print("\n✓ Testing error strings:")
        for (errorCode, description) in testErrors {
            let message = cs_strerror(errorCode)
            XCTAssertNotNil(message, "Error message should not be nil for \(description)")

            if let message = message {
                let errorString = String(cString: message)
                XCTAssertFalse(errorString.isEmpty, "Error message should not be empty for \(description)")
                print("  \(errorCode.rawValue) (\(description)): \(errorString)")
            }
        }
    }

    func testBasicEnumValues() {
        // Test that enum values are accessible and have expected values
        XCTAssertEqual(CS_ERR_OK.rawValue, 0, "CS_ERR_OK should be 0")
        XCTAssertNotEqual(CS_ERR_ARCH.rawValue, 0, "CS_ERR_ARCH should not be 0")

        // Test architecture enum values
        XCTAssertEqual(CS_ARCH_ARM.rawValue, 0, "CS_ARCH_ARM should be 0")
        XCTAssertEqual(CS_ARCH_AARCH64.rawValue, 1, "CS_ARCH_AARCH64 should be 1")
        XCTAssertEqual(CS_ARCH_MIPS.rawValue, 3, "CS_ARCH_MIPS should be 3")
        XCTAssertEqual(CS_ARCH_X86.rawValue, 4, "CS_ARCH_X86 should be 4")

        // Test mode enum values
        XCTAssertEqual(CS_MODE_LITTLE_ENDIAN.rawValue, 0, "CS_MODE_LITTLE_ENDIAN should be 0")
        XCTAssertEqual(CS_MODE_ARM.rawValue, 0, "CS_MODE_ARM should be 0")
        XCTAssertEqual(CS_MODE_16.rawValue, 1 << 1, "CS_MODE_16 should be 2")
        XCTAssertEqual(CS_MODE_32.rawValue, 1 << 2, "CS_MODE_32 should be 4")
        XCTAssertEqual(CS_MODE_64.rawValue, 1 << 3, "CS_MODE_64 should be 8")

        // Test option enum values
        XCTAssertEqual(CS_OPT_INVALID.rawValue, 0, "CS_OPT_INVALID should be 0")
        XCTAssertNotEqual(CS_OPT_DETAIL.rawValue, 0, "CS_OPT_DETAIL should not be 0")

        // Test option values
        XCTAssertEqual(CS_OPT_OFF.rawValue, 0, "CS_OPT_OFF should be 0")
        XCTAssertEqual(CS_OPT_ON.rawValue, 1 << 0, "CS_OPT_ON should be 1")

        print("✓ All enum values are correctly defined")
    }

    func testAPIFunctionAvailability() {
        // Test that all basic C functions are available (can be referenced)
        // This doesn't call them, just verifies they exist and can be linked

        let functions: [String: Any] = [
            "cs_version": cs_version,
            "cs_open": cs_open,
            "cs_close": cs_close,
            "cs_disasm": cs_disasm,
            "cs_malloc": cs_malloc,
            "cs_disasm_iter": cs_disasm_iter,
            "cs_free": cs_free,
            "cs_option": cs_option,
            "cs_errno": cs_errno,
            "cs_strerror": cs_strerror,
        ]

        print("✓ Available C API functions:")
        for (name, _) in functions.sorted(by: { $0.key < $1.key }) {
            print("  - \(name)")
        }

        XCTAssertEqual(functions.count, 10, "All 10 basic functions should be available")
    }

    func testInvalidParameters() {
        // Test behavior with obviously invalid parameters
        // These should not crash but return error codes

        // Test cs_strerror with invalid error code
        let invalidErrorMsg = cs_strerror(cs_err(rawValue: 999))
        XCTAssertNotNil(invalidErrorMsg, "cs_strerror should handle invalid error codes")

        // Test cs_errno with invalid handle
        let errno = cs_errno(0)  // 0 is invalid handle
        XCTAssertNotEqual(errno, CS_ERR_OK, "cs_errno should return error for invalid handle")

        print("✓ Invalid parameter handling works correctly")
    }

    func testConstantValues() {
        // Test important constant values
        XCTAssertEqual(CS_MNEMONIC_SIZE, 32, "CS_MNEMONIC_SIZE should be 32")

        print("✓ Constant values are correct")
        print("  CS_MNEMONIC_SIZE: \(CS_MNEMONIC_SIZE)")
    }

    func testStructureSizes() {
        // Test that key structures have reasonable sizes
        let insnSize = MemoryLayout<cs_insn>.size
        let detailSize = MemoryLayout<cs_detail>.size

        XCTAssertGreaterThan(insnSize, 0, "cs_insn structure should have positive size")
        XCTAssertGreaterThan(detailSize, 0, "cs_detail structure should have positive size")

        print("✓ Structure sizes:")
        print("  cs_insn: \(insnSize) bytes")
        print("  cs_detail: \(detailSize) bytes")

        // cs_insn should be reasonably sized (has mnemonic, op_str, etc.)
        XCTAssertGreaterThan(insnSize, 64, "cs_insn should be at least 64 bytes")

        // cs_detail should be large (has architecture-specific unions)
        XCTAssertGreaterThan(detailSize, 100, "cs_detail should be at least 100 bytes")
    }

    func testVersionConsistency() {
        // Test version consistency across different calls
        var major1: Int32 = 0, minor1: Int32 = 0
        var major2: Int32 = 0, minor2: Int32 = 0

        let version1 = cs_version(&major1, &minor1)
        let version2 = cs_version(&major2, &minor2)

        XCTAssertEqual(version1, version2, "Version should be consistent")
        XCTAssertEqual(major1, major2, "Major version should be consistent")
        XCTAssertEqual(minor1, minor2, "Minor version should be consistent")

        // Test CS_MAKE_VERSION macro equivalent
        let calculatedVersion = UInt32((major1 << 8) | minor1)
        XCTAssertEqual(version1, calculatedVersion, "Version calculation should match macro")

        print("✓ Version consistency verified")
    }
}
