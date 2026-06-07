//
//  CapstoneKit.swift
//  capstone
//
//  Created by Christophe Bronner on 2026-06-04.
//

@_exported public import capstone

public struct Capstone: ~Copyable {
	public let handle: csh

	@inlinable @_transparent
	public init(handle: csh) {
		self.handle = handle
	}

	@inlinable @_transparent
	public init(
		arch: CapstoneArch,
		mode: CapstoneMode
	) throws(CapstoneError) {
		var handle: csh = .init(0)
		let err = cs_open(arch, mode, &handle)
		guard err == .CS_ERR_OK else { throw err }
		self.handle = handle
	}

	deinit {
		var handle = handle
		cs_close(&handle)
	}
}

public extension Capstone {
	/// See ``cs_option`` with ``CS_OPT_DETAIL``.
	func withDetailedInstructions(_ value: Bool) {
		let value = value ? CapstoneOptionValue.CS_OPT_ON : []
		set(option: .detail, to: value)
	}

	/// See ``cs_option``.
	@inlinable @_transparent
	func set(option: CapstoneOptionKind, to value: some FixedWidthInteger) {
		cs_option(handle, option, UInt(value))
	}

	/// See ``cs_option``.
	@inlinable @_transparent
	func set(option: CapstoneOptionKind, to value: some RawRepresentable<some FixedWidthInteger>) {
		set(option: option, to: value.rawValue)
	}

	/// See ``cs_support``.
	@inlinable
	static func support(_ query: CInt) -> Bool {
		cs_support(query)
	}
	
	/// Throws the last error of an API function fail. See ``cs_errno``.
	@inlinable
	func errno() throws(CapstoneError) {
		throw cs_errno(handle)
	}

	/// See ``cs_disasm``.
	@available(macOS 10.14.4, *)
	@inlinable
	func disassemble(
		code: Span<UInt8>,
		address: UInt64,
		count: Int = 0
	) throws(CapstoneError) -> CapstoneInstructionBuffer {
		var output: UnsafeMutablePointer<CapstoneInstruction>!
		let result = code.withUnsafeBufferPointer {
			cs_disasm(handle, $0.baseAddress, $0.count, address, count, &output)
		}
		if result == 0 {
			throw cs_errno(handle)
		}
		let buffer = UnsafeMutableBufferPointer(start: output, count: count)
		return CapstoneInstructionBuffer(buffer)
	}

	/// See ``cs_disasm_iter``.
	@available(macOS 10.14.4, *)
	@inlinable
	func disassemble(
		_ code: inout Span<UInt8>,
		at address: inout UInt64,
	) throws(CapstoneError) -> CapstoneInstructionBox {
		var result = CapstoneInstructionBox(using: self)
		var size = code.count

		let success = code.withUnsafeBufferPointer {
			var base = $0.baseAddress
			return cs_disasm_iter(handle, &base, &size, &address, &result.pointee)
		}
		code = code.extracting(droppingFirst: code.count - size)
		if !success {
			throw cs_errno(handle)
		}
		return result
	}

	/// See ``cs_regs_access``.
	@available(macOS 10.14.4, *)
	@inlinable
	func access(
		regsOf insn: borrowing CapstoneInstruction,
		read: inout MutableSpan<UInt16>,
		write: inout MutableSpan<UInt16>,
	) throws(CapstoneError) {
		let cs_regs_count = MemoryLayout<cs_regs>.size / MemoryLayout<UInt16>.size
		precondition(read.count >= cs_regs_count && write.count >= cs_regs_count)
		var rcount = 0
		var wcount = 0
		let err = withUnsafePointer(to: insn) { insn in
			read.withUnsafeMutableBufferPointer { readp in
				write.withUnsafeMutableBufferPointer { writep in
					cs_regs_access(handle, insn, readp.baseAddress, &rcount, writep.baseAddress, &wcount)
				}
			}
		}
		read = read.extracting(first: rcount)
		write = write.extracting(first: rcount)
		try err.check()
	}

	/// See ``cs_insn_group``.
	@inlinable
	func instruction(_ instr: borrowing CapstoneInstruction, in group: InstructionGroup) -> Bool {
		withUnsafePointer(to: instr) { instr in
			cs_insn_group(handle, instr, group.rawValue)
		}
	}

	/// See ``cs_insn_name``.
	@inlinable
	func instruction(name id: some RawRepresentable<UInt32>) -> String {
		guard let name = cs_insn_name(handle, id.rawValue) else { return "" }
		return String(cString: name)
	}
}

public extension CapstoneError {
	/// Throws an error if the result wasn't a success.
	@inlinable @_transparent
	func check() throws(CapstoneError) {
		guard self != .CS_ERR_OK else { return }
		throw self
	}
}

extension CapstoneError: @retroactive CustomStringConvertible {
	public var description: String {
		String(cString: cs_strerror(self))
	}
}

public extension CapstoneInstruction {
	/// See ``cs_insn``.
	@inlinable @_transparent
	var detail: Detail {
		@inlinable @_transparent
		_read {
			if let unsafeMutableDetailPointer {
				yield unsafeMutableDetailPointer.pointee
			} else {
				yield .init()
			}
		}
	}
}

public struct CapstoneInstructionBox: ~Copyable {
	@usableFromInline let ptr: UnsafeMutablePointer<CapstoneInstruction>!

	@inlinable @_transparent
	public init(using capstone: borrowing Capstone) {
		ptr = cs_malloc(capstone.handle)
	}

	deinit {
		cs_free(ptr, 1)
	}

	@inlinable @_transparent
	public var pointee: CapstoneInstruction {
		_read { yield ptr.pointee }
		_modify { yield &ptr.pointee }
	}
}

public struct CapstoneInstructionBuffer: ~Copyable {
	@usableFromInline let buffer: UnsafeMutableBufferPointer<CapstoneInstruction>!

	@inlinable @_transparent
	public init(_ buffer: UnsafeMutableBufferPointer<CapstoneInstruction>) {
		self.buffer = buffer
	}

	deinit {
		cs_free(buffer.baseAddress, buffer.count)
	}

	@inlinable @_transparent
	public var count: Int { buffer.count }

	@inlinable @_transparent
	public func withUnsafeBufferPointer<R>(
		do action: (UnsafeBufferPointer<CapstoneInstruction>) -> R
	) -> R {
		action(UnsafeBufferPointer(buffer))
	}

	@inlinable @_transparent
	public func withUnsafeMutableBufferPointer<R>(
		do action: (UnsafeMutableBufferPointer<CapstoneInstruction>) -> R
	) -> R {
		action(buffer)
	}

	@inlinable
	public subscript(index: Int) -> CapstoneInstruction {
		@_transparent
		_read { yield buffer[index] }
		@_transparent
		_modify { yield &buffer[index] }
	}
}
