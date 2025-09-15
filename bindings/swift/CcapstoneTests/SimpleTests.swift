import XCTest
@testable import Ccapstone

final class SimpleTests: XCTestCase {

    func testVersionOnly() {
        var major: Int32 = 0
        var minor: Int32 = 0

        let version = cs_version(&major, &minor)

        XCTAssertGreaterThan(major, 0)
        XCTAssertGreaterThanOrEqual(minor, 0)
        XCTAssertGreaterThan(version, 0)
        XCTAssertEqual(version, UInt32((major << 8) | minor))

        print("Capstone version: \(major).\(minor) (0x\(String(format: "%04x", version)))")
    }

    func testBasicAPIAvailability() {
        // Test that all basic functions are available
        // This doesn't actually call them, just verifies they can be referenced
        let _ = cs_open
        let _ = cs_close
        let _ = cs_disasm
        let _ = cs_malloc
        let _ = cs_disasm_iter
        let _ = cs_free
        let _ = cs_option
        let _ = cs_errno
        let _ = cs_strerror
        let _ = cs_version

        // Test enum availability
        let _ = CS_ARCH_X86
        let _ = CS_MODE_32
        let _ = CS_ERR_OK
        let _ = CS_OPT_DETAIL
        let _ = CS_OPT_ON

        XCTAssertTrue(true, "All basic API functions are available")
    }

    func testErrorMessages() {
        let errorCodes: [cs_err] = [
            CS_ERR_OK,
            CS_ERR_MEM,
            CS_ERR_ARCH,
            CS_ERR_HANDLE,
            CS_ERR_CSH,
            CS_ERR_MODE,
            CS_ERR_OPTION
        ]

        print("Testing error messages:")
        for errorCode in errorCodes {
            let message = cs_strerror(errorCode)
            XCTAssertNotNil(message, "Error message should not be nil for \(errorCode)")

            if let message = message {
                let errorString = String(cString: message)
                XCTAssertFalse(errorString.isEmpty, "Error message should not be empty for \(errorCode)")
                print("  \(errorCode.rawValue): \(errorString)")
            }
        }
    }

    func testSimpleOpenClose() {
        var handle: csh = 0

        print("Testing cs_open...")
        let result = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        if result == CS_ERR_OK {
            print("✓ cs_open succeeded, handle: \(handle)")
            XCTAssertNotEqual(handle, 0, "Handle should not be zero")

            print("Testing cs_close...")
            let closeResult = cs_close(&handle)
            if closeResult == CS_ERR_OK {
                print("✓ cs_close succeeded")
                XCTAssertEqual(handle, 0, "Handle should be zero after close")
            } else {
                let errorMsg = cs_strerror(closeResult)
                let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown error"
                print("✗ cs_close failed: \(errorString)")
                XCTFail("cs_close failed with error: \(errorString)")
            }
        } else {
            let errorMsg = cs_strerror(result)
            let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown error"
            print("✗ cs_open failed: \(errorString)")
            XCTFail("cs_open failed with error: \(errorString)")
        }
    }
}