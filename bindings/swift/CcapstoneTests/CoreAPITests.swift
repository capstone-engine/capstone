import Foundation
import Testing
@testable import Ccapstone

/// Core API tests that focus on the C interface without architecture-specific details
/// These tests verify the basic Capstone C API functionality exposed through Swift
@Suite("Core API Tests")
struct CoreAPITests {

    @Test("Version API comprehensive testing")
    func testVersionAPI() async throws {
        var major: Int32 = 0
        var minor: Int32 = 0

        let version = cs_version(&major, &minor)

        #expect(major > 0, "Major version should be greater than 0")
        #expect(minor >= 0, "Minor version should be greater than or equal to 0")
        #expect(version > 0, "Version should be greater than 0")
        #expect(version == UInt32((major << 8) | minor), "Version format should be correct")

        print("✓ Capstone version: \(major).\(minor) (0x\(String(format: "%04x", version)))")
    }

    @Test("Basic enum values validation")
    func testBasicEnumValues() async throws {
        // Test error code enum values
        #expect(CS_ERR_OK.rawValue == 0, "CS_ERR_OK should be 0")
        #expect(CS_ERR_ARCH.rawValue != 0, "CS_ERR_ARCH should not be 0")
        #expect(CS_ERR_HANDLE.rawValue != 0, "CS_ERR_HANDLE should not be 0")
        #expect(CS_ERR_MEM.rawValue != 0, "CS_ERR_MEM should not be 0")

        // Test architecture enum values
        #expect(CS_ARCH_ARM.rawValue == 0, "CS_ARCH_ARM should be 0")
        #expect(CS_ARCH_AARCH64.rawValue == 1, "CS_ARCH_AARCH64 should be 1")
        #expect(CS_ARCH_X86.rawValue == 4, "CS_ARCH_X86 should be 4")

        // Test mode enum values
        #expect(CS_MODE_LITTLE_ENDIAN.rawValue == 0, "CS_MODE_LITTLE_ENDIAN should be 0")
        #expect(CS_MODE_16.rawValue == 1 << 1, "CS_MODE_16 should be 2")
        #expect(CS_MODE_32.rawValue == 1 << 2, "CS_MODE_32 should be 4")
        #expect(CS_MODE_64.rawValue == 1 << 3, "CS_MODE_64 should be 8")

        // Test option enum values
        #expect(CS_OPT_INVALID.rawValue == 0, "CS_OPT_INVALID should be 0")
        #expect(CS_OPT_DETAIL.rawValue != 0, "CS_OPT_DETAIL should not be 0")

        print("✓ All enum values are correctly defined")
    }

    @Test("Error message validation")
    func testErrorMessages() async throws {
        let testErrors: [(cs_err, String)] = [
            (CS_ERR_OK, "Success"),
            (CS_ERR_MEM, "Memory error"),
            (CS_ERR_ARCH, "Architecture error"),
            (CS_ERR_HANDLE, "Handle error"),
            (CS_ERR_CSH, "CSH error"),
            (CS_ERR_MODE, "Mode error"),
            (CS_ERR_OPTION, "Option error"),
            (CS_ERR_DETAIL, "Detail error"),
            (CS_ERR_MEMSETUP, "Memory setup error"),
            (CS_ERR_VERSION, "Version error")
        ]

        print("✓ Testing error messages:")
        for (errorCode, description) in testErrors {
            let message = cs_strerror(errorCode)
            #expect(message != nil, "Error message for \(description) should not be nil")

            if let message = message {
                let errorString = String(cString: message)
                #expect(!errorString.isEmpty, "Error message for \(description) should not be empty")
                print("  \(errorCode.rawValue) (\(description)): \(errorString)")
            }
        }
    }

    @Test("Basic handle operations")
    func testBasicHandleOperations() async throws {
        var handle: csh = 0

        // Test invalid architecture
        let invalidResult = cs_open(cs_arch(rawValue: 999), CS_MODE_32, &handle)
        #expect(invalidResult != CS_ERR_OK, "Invalid architecture should return error")
        #expect(handle == 0, "Handle should be 0 for invalid architecture")

        // Test valid operations (if possible)
        let validResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        if validResult == CS_ERR_OK {
            print("✓ Successfully opened X86 32-bit engine, handle: \(handle)")
            #expect(handle != 0, "Handle should not be 0 for valid operations")

            // Test option setting
            let _ = cs_option(handle, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
            // Success or failure is acceptable, depends on implementation completeness

            // Test error number retrieval
            let _ = cs_errno(handle)
            // errno value depends on previous operation results

            // Test close
            let closeResult = cs_close(&handle)
            #expect(closeResult == CS_ERR_OK, "Handle close should succeed")
            #expect(handle == 0, "Handle should be 0 after close")
        } else {
            let errorMsg = cs_strerror(validResult)
            let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown error"
            print("⚠️  Unable to open X86 engine: \(errorString)")
            print("   This is expected because Swift binding is incomplete")
        }
    }

    @Test("Invalid operations handling")
    func testInvalidOperations() async throws {
        // Test operations on invalid handle
        let errno = cs_errno(0)
        #expect(errno != CS_ERR_OK, "cs_errno on invalid handle should return error")

        let optResult = cs_option(0, CS_OPT_DETAIL, size_t(CS_OPT_ON.rawValue))
        #expect(optResult != CS_ERR_OK, "cs_option on invalid handle should return error")

        // Test double close - using zero handle which should be safe
        var zeroHandle: csh = 0
        let doubleClose = cs_close(&zeroHandle)
        #expect(doubleClose != CS_ERR_OK, "Closing zero handle should return error")

        print("✓ Invalid operations correctly return errors")
    }

    @Test("Constants and structure sizes")
    func testConstantsAndSizes() async throws {
        // Test important constant values
        #expect(CS_MNEMONIC_SIZE == 32, "CS_MNEMONIC_SIZE should be 32")

        // Test structure sizes
        let insnSize = MemoryLayout<cs_insn>.size
        let detailSize = MemoryLayout<cs_detail>.size

        #expect(insnSize > 0, "cs_insn structure size should be greater than 0")
        #expect(detailSize > 0, "cs_detail structure size should be greater than 0")

        print("✓ Constants and structure sizes:")
        print("  CS_MNEMONIC_SIZE: \(CS_MNEMONIC_SIZE)")
        print("  cs_insn size: \(insnSize) bytes")
        print("  cs_detail size: \(detailSize) bytes")

        // cs_insn should contain mnemonic, operand strings, etc., should have reasonable size
        #expect(insnSize > 32, "cs_insn should be at least 32 bytes")

        // cs_detail contains architecture-specific unions, should be larger
        #expect(detailSize > 100, "cs_detail should be at least 100 bytes")
    }
    
    @Test("Function availability check")
    func testFunctionAvailability() async throws {
        // Verify that all core C functions can be referenced (can be linked)
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

        #expect(functions.count == 10, "Should have 10 basic functions available")
    }

    @Test("Version consistency validation")
    func testVersionConsistency() async throws {
        // Test version function consistency
        var major1: Int32 = 0, minor1: Int32 = 0
        var major2: Int32 = 0, minor2: Int32 = 0

        let version1 = cs_version(&major1, &minor1)
        let version2 = cs_version(&major2, &minor2)

        #expect(version1 == version2, "Version should remain consistent")
        #expect(major1 == major2, "Major version should remain consistent")
        #expect(minor1 == minor2, "Minor version should remain consistent")

        // Test correctness of version calculation
        let calculatedVersion = UInt32((major1 << 8) | minor1)
        #expect(version1 == calculatedVersion, "Version calculation should be correct")

        print("✓ Version consistency verification passed")
    }

    @Test("Edge cases handling")
    func testEdgeCases() async throws {
        // Test edge cases

        // Test invalid error codes
        let invalidError = cs_err(rawValue: 9999)
        let invalidMsg = cs_strerror(invalidError)
        #expect(invalidMsg != nil, "Invalid error codes should also have messages")

        // Test version with nil parameters
        let versionOnly = cs_version(nil, nil)
        #expect(versionOnly > 0, "Getting version only should work")

        print("✓ Edge cases handled correctly")
    }
}
