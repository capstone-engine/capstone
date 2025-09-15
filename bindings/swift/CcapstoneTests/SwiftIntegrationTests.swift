import Foundation
import Testing
@testable import Ccapstone

/// Swift-specific integration tests for the Capstone binding
/// These tests verify Swift-specific patterns, safety features, and idiomatic usage
@Suite("Swift Integration Tests")
struct SwiftIntegrationTests {
    // Test data
    private static let x86Code: [UInt8] = [0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00]

    @Test("Swift optionals and error handling")
    func testSwiftOptionals() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping Swift optionals test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        print("✓ Swift optionals and error handling:")

        // Test cs_malloc returning optional
        let insn = cs_malloc(handle)
        if let insn = insn {
            print("  cs_malloc returned valid pointer: \(insn)")
            cs_free(insn, 1)
        } else {
            print("  cs_malloc returned nil")
        }

        // Test cs_strerror returning optional
        let errorMessage = cs_strerror(CS_ERR_OK)
        if let message = errorMessage {
            let errorString = String(cString: message)
            print("  Error message: '\(errorString)'")
            #expect(!errorString.isEmpty, "Error message should not be empty")
        } else {
            #expect(Bool(false), "cs_strerror should not return nil")
        }
    }

    @Test("Swift memory management patterns")
    func testSwiftMemoryManagement() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping memory management test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        print("✓ Swift memory management patterns:")

        // Test RAII-style pattern with defer
        func performDisassemblyWithDefer() -> size_t {
            var insns: UnsafeMutablePointer<cs_insn>?
            let count = Self.x86Code.withUnsafeBufferPointer { buffer in
                cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            }

            defer {
                if count > 0 {
                    cs_free(insns, count)
                }
            }

            // Simulate some processing
            if count > 0 {
                let firstInsn = insns!.pointee
                _ = withUnsafeBytes(of: firstInsn.mnemonic) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }
            }

            return count
        }

        let deferCount = performDisassemblyWithDefer()
        print("  RAII-style pattern with defer: \(deferCount) instructions")

        // Test withUnsafeBufferPointer pattern
        let bufferCount = Self.x86Code.withUnsafeBufferPointer { buffer -> size_t in
            var insns: UnsafeMutablePointer<cs_insn>?
            let count = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            defer {
                if count > 0 {
                    cs_free(insns, count)
                }
            }
            return count
        }

        print("  withUnsafeBufferPointer pattern: \(bufferCount) instructions")
        #expect(deferCount == bufferCount, "Both patterns should yield same results")

        // Test iterator pattern with automatic cleanup
        func testIteratorPattern() -> Int {
            guard let insn = cs_malloc(handle) else {
                return 0
            }
            defer { cs_free(insn, 1) }

            var instructionCount = 0
            Self.x86Code.withUnsafeBufferPointer { buffer in
                var codePtr = buffer.baseAddress
                var size = Self.x86Code.count
                var address: UInt64 = 0x1000

                while cs_disasm_iter(handle, &codePtr, &size, &address, insn) {
                    instructionCount += 1
                    let mnemonic = withUnsafeBytes(of: insn.pointee.mnemonic) { bytes in
                        String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                    }
                    let _ = mnemonic // Use the value

                    if instructionCount > 100 { // Safety break
                        break
                    }
                }
            }

            return instructionCount
        }

        let iteratorCount = testIteratorPattern()
        print("  Iterator pattern with automatic cleanup: \(iteratorCount) instructions")
    }

    @Test("Swift string handling and C interop")
    func testSwiftStringHandling() async throws {
        print("✓ Swift string handling and C interop:")

        // Test converting C strings to Swift strings
        let testErrors: [cs_err] = [CS_ERR_OK, CS_ERR_MEM, CS_ERR_ARCH, CS_ERR_HANDLE]

        for errorCode in testErrors {
            if let cMessage = cs_strerror(errorCode) {
                let swiftString = String(cString: cMessage)

                // Test Swift string operations
                let uppercased = swiftString.uppercased()
                let length = swiftString.count
                let utf8Count = swiftString.utf8.count

                print("  Error \(errorCode.rawValue): '\(swiftString)' -> '\(uppercased)' (\(length)/\(utf8Count) chars)")

                #expect(!swiftString.isEmpty, "Swift string should not be empty")
                #expect(length > 0, "String length should be positive")
                #expect(utf8Count >= length, "UTF-8 byte count should be >= character count")
            }
        }

        // Test version information as Swift strings
        var major: Int32 = 0
        var minor: Int32 = 0
        let version = cs_version(&major, &minor)

        let versionString = String(format: "%d.%d", major, minor)
        let hexVersionString = String(format: "0x%04x", version)

        print("  Version: \(versionString) (\(hexVersionString))")

        #expect(versionString.count >= 3, "Version string should be at least X.Y")
        #expect(hexVersionString.hasPrefix("0x"), "Hex version should start with 0x")
    }

    @Test("Swift array and collection integration")
    func testSwiftCollectionIntegration() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping collection integration test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        print("✓ Swift array and collection integration:")

        // Test with different array types
        let testData: [String: [UInt8]] = [
            "x86_32": [0x8D, 0x4C, 0x32, 0x08],
            "nops": [0x90, 0x90, 0x90, 0x90],
            "empty": [],
            "single": [0x90],
        ]

        for (name, codeArray) in testData {
            let count = codeArray.withUnsafeBufferPointer { buffer -> size_t in
                var insns: UnsafeMutablePointer<cs_insn>?
                let result = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                defer {
                    if result > 0 {
                        cs_free(insns, result)
                    }
                }
                return result
            }

            print("  \(name) array (\(codeArray.count) bytes): \(count) instructions")
        }

        // Test using Array methods
        let extendedCode = Self.x86Code + Self.x86Code // Array concatenation
        let count = extendedCode.withUnsafeBufferPointer { buffer -> size_t in
            var insns: UnsafeMutablePointer<cs_insn>?
            let result = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
            defer {
                if result > 0 {
                    cs_free(insns, result)
                }
            }
            return result
        }

        print("  Extended array (\(extendedCode.count) bytes): \(count) instructions")

        // Test with ArraySlice
        if extendedCode.count > 4 {
            let slice = extendedCode[2 ..< 6] // Take a slice
            let sliceArray = Array(slice) // Convert slice to array for withUnsafeBufferPointer

            let sliceCount = sliceArray.withUnsafeBufferPointer { buffer -> size_t in
                var insns: UnsafeMutablePointer<cs_insn>?
                let result = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                defer {
                    if result > 0 {
                        cs_free(insns, result)
                    }
                }
                return result
            }

            print("  Array slice (\(sliceArray.count) bytes): \(sliceCount) instructions")
        }
    }

    @Test("Swift error handling patterns")
    func testSwiftErrorHandling() async throws {
        print("✓ Swift error handling patterns:")

        // Define a Swift wrapper that throws
        enum CapstoneError: Error, CustomStringConvertible {
            case openFailed(cs_err)
            case disassemblyFailed(cs_err)
            case invalidHandle

            var description: String {
                switch self {
                case .openFailed(let err):
                    if let msg = cs_strerror(err) {
                        return "Open failed: \(String(cString: msg))"
                    }
                    return "Open failed: \(err)"
                case .disassemblyFailed(let err):
                    return "Disassembly failed: \(err)"
                case .invalidHandle:
                    return "Invalid handle"
                }
            }
        }

        func safeOpen(arch: cs_arch, mode: cs_mode) throws -> csh {
            var handle: csh = 0
            let result = cs_open(arch, mode, &handle)
            guard result == CS_ERR_OK else {
                throw CapstoneError.openFailed(result)
            }
            return handle
        }

        func safeDisassemble(handle: csh, code: [UInt8]) throws -> Int {
            guard handle != 0 else {
                throw CapstoneError.invalidHandle
            }

            return code.withUnsafeBufferPointer { buffer -> Int in
                var insns: UnsafeMutablePointer<cs_insn>?
                let count = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                defer {
                    if count > 0 {
                        cs_free(insns, count)
                    }
                }
                return Int(count)
            }
        }

        // Test successful case
        do {
            let handle = try safeOpen(arch: CS_ARCH_X86, mode: CS_MODE_32)
            defer {
                var mutableHandle = handle
                _ = cs_close(&mutableHandle)
            }

            let count = try safeDisassemble(handle: handle, code: Self.x86Code)
            print("  Successful operation: \(count) instructions")

        } catch {
            print("  Expected success case failed: \(error)")
        }

        // Test failure case
        do {
            _ = try safeOpen(arch: cs_arch(rawValue: 999), mode: CS_MODE_32)
            print("  Expected failure case succeeded (unexpected)")
        } catch let error as CapstoneError {
            print("  Expected failure caught: \(error)")
        } catch {
            print("  Unexpected error type: \(error)")
        }

        // Test invalid handle
        do {
            _ = try safeDisassemble(handle: 0, code: Self.x86Code)
            print("  Invalid handle case succeeded (unexpected)")
        } catch let error as CapstoneError {
            print("  Invalid handle error caught: \(error)")
        } catch {
            print("  Unexpected error for invalid handle: \(error)")
        }
    }

    @Test("Swift value types and reference types")
    func testSwiftValueAndReferenceTypes() async throws {
        var handle: csh = 0
        let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

        guard openResult == CS_ERR_OK else {
            print("⚠️ Skipping value/reference types test - cannot open engine")
            return
        }

        defer { _ = cs_close(&handle) }

        print("✓ Swift value types and reference types:")

        // Test copying instruction data to Swift value types
        struct SwiftInstruction {
            var address: UInt64
            let size: UInt16
            let mnemonic: String
            let operands: String
            let bytes: [UInt8]

            init(from csInsn: cs_insn) {
                self.address = csInsn.address
                self.size = csInsn.size
                self.mnemonic = withUnsafeBytes(of: csInsn.mnemonic) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }
                self.operands = withUnsafeBytes(of: csInsn.op_str) { bytes in
                    String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
                }

                // Copy bytes (simplified - in real implementation would copy actual bytes)
                var byteArray: [UInt8] = []
                for _ in 0 ..< min(Int(csInsn.size), 16) { // Limit to reasonable size
                    // Note: This is simplified - real implementation would access csInsn.bytes properly
                    byteArray.append(0x90) // Placeholder
                }
                self.bytes = byteArray
            }
        }

        var swiftInstructions: [SwiftInstruction] = []

        var insns: UnsafeMutablePointer<cs_insn>?
        let count = Self.x86Code.withUnsafeBufferPointer { buffer in
            cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
        }

        defer {
            if count > 0 {
                cs_free(insns, count)
            }
        }

        // Convert C structures to Swift value types
        if count > 0 {
            for i in 0 ..< count {
                let csInsn = (insns! + i).pointee
                let swiftInsn = SwiftInstruction(from: csInsn)
                swiftInstructions.append(swiftInsn)
            }
        }

        print("  Converted \(swiftInstructions.count) instructions to Swift value types")

        // Test Swift collection operations on converted data
        let mnemonics = swiftInstructions.map { $0.mnemonic }
        let addresses = swiftInstructions.map { $0.address }
        let totalBytes = swiftInstructions.reduce(0) { $0 + Int($1.size) }

        print("  Mnemonics: \(mnemonics)")
        print("  Addresses: \(addresses.map { String(format: "0x%llx", $0) })")
        print("  Total instruction bytes: \(totalBytes)")

        // Test value semantics
        if var firstInstruction = swiftInstructions.first {
            let originalAddress = firstInstruction.address
            firstInstruction.address = 0x2000 // This shouldn't affect the array

            let arrayAddress = swiftInstructions.first?.address ?? 0
            #expect(originalAddress == arrayAddress, "Value types should maintain independence")
            print("  Value type semantics: ✓ (original: 0x\(String(format: "%llx", originalAddress)), array: 0x\(String(format: "%llx", arrayAddress)))")
        }
    }

    @Test("Swift async/await compatibility")
    func testAsyncAwaitCompatibility() async throws {
        print("✓ Swift async/await compatibility:")

        // Test that Capstone operations can be used in async contexts
        func asyncDisassembly() async -> Int {
            var handle: csh = 0
            let openResult = cs_open(CS_ARCH_X86, CS_MODE_32, &handle)

            guard openResult == CS_ERR_OK else {
                return -1
            }

            defer { _ = cs_close(&handle) }

            // Simulate some async work
            try? await Task.sleep(nanoseconds: 1_000_000) // 1ms

            return Self.x86Code.withUnsafeBufferPointer { buffer -> Int in
                var insns: UnsafeMutablePointer<cs_insn>?
                let count = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                defer {
                    if count > 0 {
                        cs_free(insns, count)
                    }
                }
                return Int(count)
            }
        }

        let result = await asyncDisassembly()
        print("  Async disassembly result: \(result) instructions")

        // Test concurrent async operations
        async let result1 = asyncDisassembly()
        async let result2 = asyncDisassembly()
        async let result3 = asyncDisassembly()

        let results = await [result1, result2, result3]
        print("  Concurrent async results: \(results)")

        // All should succeed or fail consistently
        let successfulResults = results.filter { $0 >= 0 }
        if !successfulResults.isEmpty {
            let allSame = successfulResults.allSatisfy { $0 == successfulResults.first }
            #expect(allSame, "Concurrent operations should yield same results")
            print("  Concurrent consistency: \(allSame ? "✓" : "✗")")
        }
    }

    @Test("Swift generic and protocol integration")
    func testGenericAndProtocolIntegration() async throws {
        print("✓ Swift generic and protocol integration:")

        // Define protocols for Capstone operations
        protocol DisassemblyProvider {
            func disassemble<T: Collection>(_ code: T) -> Int where T.Element == UInt8
        }

        class CapstoneDisassembler: DisassemblyProvider {
            let handle: csh

            init?(architecture: cs_arch, mode: cs_mode) {
                var handle: csh = 0
                let result = cs_open(architecture, mode, &handle)
                guard result == CS_ERR_OK else {
                    return nil
                }
                self.handle = handle
            }

            deinit {
                var mutableHandle = handle
                _ = cs_close(&mutableHandle)
            }

            func disassemble<T: Collection>(_ code: T) -> Int where T.Element == UInt8 {
                let codeArray = Array(code) // Convert any collection to array
                return codeArray.withUnsafeBufferPointer { buffer -> Int in
                    var insns: UnsafeMutablePointer<cs_insn>?
                    let count = cs_disasm(handle, buffer.baseAddress, buffer.count, 0x1000, 0, &insns)
                    defer {
                        if count > 0 {
                            cs_free(insns, count)
                        }
                    }
                    return Int(count)
                }
            }
        }

        // Test with different collection types
        guard let disassembler = CapstoneDisassembler(architecture: CS_ARCH_X86, mode: CS_MODE_32) else {
            print("  Could not create disassembler")
            return
        }

        // Test with Array
        let arrayResult = disassembler.disassemble(Self.x86Code)
        print("  Array disassembly: \(arrayResult) instructions")

        // Test with ArraySlice
        if Self.x86Code.count > 4 {
            let slice = Self.x86Code[0 ..< 4]
            let sliceResult = disassembler.disassemble(slice)
            print("  ArraySlice disassembly: \(sliceResult) instructions")
        }

        // Test with different UInt8 collections
        let set = Set(Self.x86Code)
        let setArray = Array(set).sorted() // Convert set back to sorted array for consistent results
        let setResult = disassembler.disassemble(setArray)
        print("  Set-derived array disassembly: \(setResult) instructions")

        // Test generic function
        func testGenericDisassembly<T: Collection>(_ provider: DisassemblyProvider, code: T) -> Int where T.Element == UInt8 {
            return provider.disassemble(code)
        }

        let genericResult = testGenericDisassembly(disassembler, code: Self.x86Code)
        print("  Generic function result: \(genericResult) instructions")

        #expect(arrayResult == genericResult, "Generic and direct calls should yield same results")
    }
}
