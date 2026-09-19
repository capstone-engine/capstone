// Public domain
// SPDX-License-Identifier: CC0
// CapstoneKit

@_exported public import capstone

public struct Capstone: ~Copyable {
	public let handle: csh

	@inlinable
	public init(handle: csh) {
		self.handle = handle
	}

	/// See ``cs_open``.
	@inlinable
	public init(
		arch: CapstoneArch,
		mode: CapstoneMode
	) throws(CapstoneError) {
		var handle = csh(0)
		try cs_open(arch, mode, &handle).check()
		self.handle = handle
	}

	@inlinable
	deinit {
		var handle = handle
		cs_close(&handle)
	}
}

public extension Capstone {
	/// See ``cs_close``. Called automatically once this instance is no longer used.
	@inlinable
	consuming func close() {
		var handle = handle
		cs_close(&handle)
	}

	/// See ``cs_option`` with ``CS_OPT_DETAIL``.
	@inlinable @_transparent
	func withDetailedInstructions(_ value: Bool) {
		let value: CapstoneOption.Value = value ? .on : .off
		set(option: .detail, to: value)
	}

	/// See ``cs_option``.
	@inlinable
	func set(option: CapstoneOption.Kind, to value: some FixedWidthInteger) {
		cs_option(handle, option, UInt(value))
	}

	/// See ``cs_option``.
	@inlinable @_transparent
	func set(option: CapstoneOption) {
		set(option: option.type, to: option.val)
	}

	/// See ``cs_option``.
	@inlinable @_transparent
	func set(option: CapstoneOption.Kind, to value: some RawRepresentable<some FixedWidthInteger>) {
		set(option: option, to: value.rawValue)
	}

	/// See ``cs_support``.
	@inlinable
	static func support(_ query: CInt) -> Bool {
		cs_support(query)
	}
	
	/// Throws the last error of an API function fail. See ``capstone/cs_errno``.
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
		return CapstoneInstructionBuffer(managing: buffer)
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
	func instruction(_ instr: borrowing CapstoneInstruction, in group: some FixedWidthInteger) -> Bool {
		withUnsafePointer(to: instr) { instr in
			cs_insn_group(handle, instr, UInt32(group))
		}
	}

	/// See ``cs_insn_group``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, in group: some RawRepresentable<some FixedWidthInteger>) -> Bool {
		instruction(instr, in: group.rawValue)
	}

	/// See ``cs_insn_group``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, in group: InstructionGroup) -> Bool {
		instruction(instr, in: group.rawValue)
	}

	/// See ``cs_reg_read``.
	@inlinable
	func instruction(_ instr: borrowing CapstoneInstruction, read reg: some FixedWidthInteger) -> Bool {
		withUnsafePointer(to: instr) {
			cs_reg_read(handle, $0, UInt32(reg))
		}
	}

	/// See ``cs_reg_read``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, read reg: some RawRepresentable<some FixedWidthInteger>) -> Bool {
		instruction(instr, read: reg.rawValue)
	}

	/// See ``cs_reg_write``.
	@inlinable
	func instruction(_ instr: borrowing CapstoneInstruction, write reg: some FixedWidthInteger) -> Bool {
		withUnsafePointer(to: instr) {
			cs_reg_write(handle, $0, UInt32(reg))
		}
	}

	/// See ``cs_reg_write``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, write reg: some RawRepresentable<some FixedWidthInteger>) -> Bool {
		instruction(instr, write: reg.rawValue)
	}

	/// See ``cs_op_count``.
	@inlinable
	func instruction(_ instr: borrowing CapstoneInstruction, opCountOf op_type: some FixedWidthInteger) -> Int32 {
		withUnsafePointer(to: instr) {
			cs_op_count(handle, $0, UInt32(op_type))
		}
	}

	/// See ``cs_op_count``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, opCountOf op_type: some RawRepresentable<some FixedWidthInteger>) -> Int32 {
		instruction(instr, opCountOf: op_type.rawValue)
	}

	/// See ``cs_op_index``.
	@inlinable
	func instruction(_ instr: borrowing CapstoneInstruction, opIndexOf op_type: some FixedWidthInteger, at position: some FixedWidthInteger) -> Int32 {
		withUnsafePointer(to: instr) {
			cs_op_index(handle, $0, UInt32(op_type), UInt32(position))
		}
	}

	/// See ``cs_op_index``.
	@inlinable @_transparent
	func instruction(_ instr: borrowing CapstoneInstruction, opIndexOf op_type: some RawRepresentable<some FixedWidthInteger>, at position: some FixedWidthInteger) -> Int32 {
		instruction(instr, opIndexOf: op_type.rawValue, at: position)
	}

	/// See ``cs_insn_name``.
	@inlinable
	func nameOf(instruction id: some FixedWidthInteger) -> String {
		guard let name = cs_insn_name(handle, UInt32(id)) else { return "" }
		return String(cString: name)
	}

	/// See ``cs_insn_name``.
	@inlinable @_transparent
	func nameOf(instruction id: some RawRepresentable<some FixedWidthInteger>) -> String {
		nameOf(instruction: id.rawValue)
	}

	/// See ``cs_group_name``.
	@inlinable
	func nameOf(group id: some FixedWidthInteger) -> String {
		guard let name = cs_group_name(handle, UInt32(id)) else { return "" }
		return String(cString: name)
	}

	/// See ``cs_group_name``.
	@inlinable @_transparent
	func nameOf(group id: some RawRepresentable<some FixedWidthInteger>) -> String {
		nameOf(group: id.rawValue)
	}

	/// See ``cs_insn_name``.
	@inlinable
	func nameOf(register id: some FixedWidthInteger) -> String {
		guard let name = cs_reg_name(handle, UInt32(id)) else { return "" }
		return String(cString: name)
	}

	/// See ``cs_insn_name``.
	@inlinable @_transparent
	func nameOf(register id: some RawRepresentable<some FixedWidthInteger>) -> String {
		nameOf(register: id.rawValue)
	}
}

public extension CapstoneError {
	/// Throws an error if the result wasn't a success.
	@inlinable
	func check() throws(CapstoneError) {
		guard self != .ok else { return }
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
	@inlinable
	var detail: Detail {
		@inlinable
		_read {
			if let unsafeMutableDetailPointer {
				yield unsafeMutableDetailPointer.pointee
			} else {
				yield .init()
			}
		}
	}
}

/// Represents an instruction managed by Capstone.
public struct CapstoneInstructionBox: ~Copyable {
	@usableFromInline let ptr: UnsafeMutablePointer<CapstoneInstruction>!

	/// Manage an instruction allocated with ``cs_malloc``.
	/// The instruction will be freed once this instance goes out of scope.
	/// - Parameter ptr: The instruction pointer to manage.
	@inlinable
	public init(managing ptr: UnsafeMutablePointer<CapstoneInstruction>) {
		self.ptr = ptr
	}
	
	/// Allocates a new instruction using Capstone's memory allocator.
	/// - Parameter capstone: The Capstone instance to use for allocating the instruction.
	@inlinable
	public init(using capstone: borrowing Capstone) {
		ptr = cs_malloc(capstone.handle)
	}

	deinit {
		cs_free(ptr, 1)
	}

	@inlinable
	public var pointee: CapstoneInstruction {
		_read { yield ptr.pointee }
		_modify { yield &ptr.pointee }
	}
}

/// Represents a list of instructions managed by Capstone.
public struct CapstoneInstructionBuffer: ~Copyable {
	@usableFromInline let buffer: UnsafeMutableBufferPointer<CapstoneInstruction>!

	/// Manage an instruction list allocated by ``cs_disasm``.
	/// The list and all its instructions will be freed once this instance goes out of scope.
	/// - Parameter buffer: The instruction buffer to manage.
	@inlinable
	public init(managing buffer: UnsafeMutableBufferPointer<CapstoneInstruction>) {
		self.buffer = buffer
	}

	deinit {
		cs_free(buffer.baseAddress, buffer.count)
	}

	@inlinable
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
