import Foundation
import Testing
@testable import Ccapstone

@Suite struct SimpleTests {

    @Test func versionOnly() {
        var major: Int32 = 0
        var minor: Int32 = 0

        let version = cs_version(&major, &minor)

        #expect(major > 0)
        #expect(minor >= 0)
        #expect(version > 0)
        #expect(version == UInt32((major << 8) | minor))

        print("Capstone version: \(major).\(minor) (0x\(String(format: "%04x", version)))")
    }

    @Test func basicAPIAvailability() {
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

        #expect(true, "All basic API functions are available")
    }

    @Test func errorMessages() {
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
            #expect(message != nil, "Error message should not be nil for \(errorCode)")

            if let message = message {
                let errorString = String(cString: message)
                #expect(!errorString.isEmpty, "Error message should not be empty for \(errorCode)")
                print("  \(errorCode.rawValue): \(errorString)")
            }
        }
    }

    @Test func simpleOpenClose() {
        var handle: csh = 0

        print("Testing cs_open...")
        let result = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
        if result == CS_ERR_OK {
            print("✓ cs_open succeeded, handle: \(handle)")
            #expect(handle != 0, "Handle should not be zero")

            print("Testing cs_close...")
            let closeResult = cs_close(&handle)
            if closeResult == CS_ERR_OK {
                print("✓ cs_close succeeded")
                #expect(handle == 0, "Handle should be zero after close")
            } else {
                let errorMsg = cs_strerror(closeResult)
                let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown error"
                print("✗ cs_close failed: \(errorString)")
                Issue.record("cs_close failed with error: \(errorString)")
            }
        } else {
            let errorMsg = cs_strerror(result)
            let errorString = errorMsg != nil ? String(cString: errorMsg!) : "Unknown error"
            print("✗ cs_open failed: \(errorString)")
            Issue.record("cs_open failed with error: \(errorString)")
        }
    }
}
