import Testing
import capstone

private extension capstone.cs_insn {
	var mnemonicString: String {
		withUnsafeBytes(of: mnemonic) {
			String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
		}
	}

	var opString: String {
		withUnsafeBytes(of: op_str) {
			String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
		}
	}
}

@Test func integration() {
	var handle: capstone.csh = 0
	#expect(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK)
	defer {
		_ = cs_close(&handle)
	}

	// mov eax, ebx
	let code: [UInt8] = [0x89, 0xD8]
	var insn: UnsafeMutablePointer<capstone.cs_insn>?
	let count = code.withUnsafeBufferPointer {
		cs_disasm(handle, $0.baseAddress, $0.count, 0x4000_0000, 0, &insn)
	}
	defer {
		if let insn {
			cs_free(insn, count)
		}
	}

	#expect(count == 1)
	#expect(insn?.pointee.id == X86_INS_MOV.rawValue)
	#expect(insn?.pointee.mnemonicString == "mov")
	#expect(insn?.pointee.opString == "eax, ebx")
	#expect(insn?.pointee.address == 0x4000_0000)
	#expect(insn?.pointee.size == 2)
}
