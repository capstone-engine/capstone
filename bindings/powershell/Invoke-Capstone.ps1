function Invoke-Capstone {
<#
.SYNOPSIS
	Powershell wrapper for Capstone v3 (using inline C#). The only Capstone feature
	which has not been implemented is the extended architecture-dependent information.
	
	In effect the function directly parses the Capstone dll so it can support any
	features implemented by Capstone so long as function calls are prototyped in C#.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE

	# x86 Assembly
	C:\PS> $Bytes = [Byte[]] @(0x90,0x90)
	C:\PS> Invoke-Capstone -Architecture X86 -Mode 32 -Bytes $Bytes
	
	nop
	nop

.EXAMPLE

	# ARM Assembly
	C:\PS> $Bytes = [Byte[]] @( 0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3 )
	C:\PS> Invoke-Capstone -Architecture ARM -Mode ARM -Bytes $Bytes
	
	sdiv r0, r0, r1
	udiv r1, r1, r2
	vbit q5, q15, q6
	vcgt.f32 q10, q9, q12

.EXAMPLE

	# Detailed mode & ATT syntax
	C:\PS> $Bytes = [Byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
	C:\PS> Invoke-Capstone -Architecture X86 -Mode 32 -Bytes $Bytes -Syntax ATT -Detailed
	
	Size     : 5
	Address  : 0x100000
	Mnemonic : movl
	Operands : $0xa, %eax
	Bytes    : {184, 10, 0, 0...}
	RegRead  :
	RegWrite :
	
	Size     : 2
	Address  : 0x100005
	Mnemonic : divl
	Operands : %ebx
	Bytes    : {247, 243, 0, 0...}
	RegRead  : {eax, edx}
	RegWrite : {eax, edx, eflags}

.EXAMPLE

	# Invoke-Capstone emits objects
	C:\PS> $Bytes = [Byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
	C:\PS> $Object = Invoke-Capstone -Architecture X86 -Mode 32 -Bytes $Bytes -Detailed
	C:\PS> $Object |Select-Object Size,Mnemonic,Operands

	Size Mnemonic Operands
	---- -------- --------
	   5 mov      eax, 0xa
	   2 div      ebx

#>

	param(
        [Parameter(Mandatory = $True)]
        [ValidateSet(
			'ARM',
			'ARM64',
			'MIPS',
			'X86',
			'PPC',
			'SPARC',
			'SYSZ',
			'XCORE',
			'MAX',
			'ALL')
		]
        [String]$Architecture,
		
        [Parameter(Mandatory = $True)]
        [ValidateSet(
			'Little_Endian',
			'ARM',
			'16',
			'32',
			'64',
			'THUMB',
			'MCLASS',
			'V8',
			'MICRO',
			'MIPS3',
			'MIPS32R6',
			'MIPSGP64',
			'V9',
			'Big_Endian',
			'MIPS32',
			'MIPS64')
		]
        [String]$Mode,
		
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[Byte[]]$Bytes,

		[Parameter(Mandatory = $False)]
		[String]$Syntax = "Intel",

		[Parameter(Mandatory = $False)]
		[Int]$Address = 0x100000,

		[Parameter(Mandatory = $False)]
		[switch]$Detailed = $null
    )

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct cs_insn
	{
		public uint id;
		public ulong address;
		public ushort size;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public byte[] bytes;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
		public string mnemonic;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
		public string operands;
		public IntPtr detail;
	}

	/// Partial, only architecture-independent internal data
	[StructLayout(LayoutKind.Sequential)]
	public struct cs_detail
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
		public byte[] regs_read;
		public byte regs_read_count;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
		public byte[] regs_write;
		public byte regs_write_count;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public byte[] groups;
		public byte groups_count;
	}

	[Flags]
	public enum cs_err : int
	{
		CS_ERR_OK = 0,    /// No error: everything was fine
		CS_ERR_MEM,       /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
		CS_ERR_ARCH,      /// Unsupported architecture: cs_open()
		CS_ERR_HANDLE,    /// Invalid handle: cs_op_count(), cs_op_index()
		CS_ERR_CSH,	      /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
		CS_ERR_MODE,      /// Invalid/unsupported mode: cs_open()
		CS_ERR_OPTION,    /// Invalid/unsupported option: cs_option()
		CS_ERR_DETAIL,    /// Information is unavailable because detail option is OFF
		CS_ERR_MEMSETUP,  /// Dynamic memory management uninitialized (see CS_OPT_MEM)
		CS_ERR_VERSION,   /// Unsupported version (bindings)
		CS_ERR_DIET,      /// Access irrelevant data in "diet" engine
		CS_ERR_SKIPDATA,  /// Access irrelevant data for "data" instruction in SKIPDATA mode
		CS_ERR_X86_ATT,   /// X86 AT&T syntax is unsupported (opt-out at compile time)
		CS_ERR_X86_INTEL, /// X86 Intel syntax is unsupported (opt-out at compile time)
	}
	
	public static class Capstone
	{
		[DllImport("capstone.dll")]
		public static extern cs_err cs_open(
			int arch,
			int mode,
			ref IntPtr handle);

		[DllImport("capstone.dll")]
		public static extern UInt32 cs_disasm(
			IntPtr handle,
			byte[] code,
			int code_size,
			ulong address,
			int count,
			ref IntPtr insn);

		[DllImport("capstone.dll")]
		public static extern bool cs_free(
			IntPtr insn,
			int count);

		[DllImport("capstone.dll")]
		public static extern cs_err cs_close(
			IntPtr handle);

		[DllImport("capstone.dll")]
		public static extern cs_err cs_option(
			IntPtr handle,
			int type,
			int value);

		[DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl)]
		public static extern IntPtr cs_reg_name(
			IntPtr handle,
			uint reg_id);
	}
"@

	# Architecture -> int
	New-Variable -Option Constant -Name cs_arch -Value @{
		"ARM"   = 0
		"ARM64" = 1
		"MIPS"  = 2
		"X86"   = 3
		"PPC"   = 4
		"SPARC" = 5
		"SYSZ"  = 6
		"XCORE" = 7
		"MAX"   = 8
		"ALL"   = 0xFFFF
	}

	# Mode -> int
	New-Variable -Option Constant -Name cs_mode -Value @{
		"Little_Endian" = 0
		"ARM"           = 0
		"16"            = 2
		"32"            = 4
		"64"            = 8
		"THUMB"         = 16
		"MCLASS"        = 32
		"V8"            = 64
		"MICRO"         = 16
		"MIPS3"         = 32
		"MIPS32R6"      = 64
		"MIPSGP64"      = 128
		"V9"            = 16
		"Big_Endian"    = -2147483648
		"MIPS32"        = 4
		"MIPS64"        = 8
	}
	
	# Disasm Handle
	$DisAsmHandle = [IntPtr]::Zero
	
	# Initialize Capstone with cs_open()
	try {
		$CallResult = [Capstone]::cs_open($cs_arch[$Architecture],$cs_mode[$Mode],[ref]$DisAsmHandle)
	} catch {
		if ($Error[0].FullyQualifiedErrorId -eq "DllNotFoundException") {
			echo "`n[!] Missing Capstone DLL"
		} else {
			echo "`n[!] Exception: $($Error[0].FullyQualifiedErrorId)"
		}
		echo "[>] Quitting..`n"
		Return
	}
	if ($CallResult -ne "CS_ERR_OK") {
		if ($CallResult -eq "CS_ERR_MODE"){
			echo "`n[!] Invalid Architecture/Mode combination"
			echo "[>] Quitting..`n"
		} else {
			echo "`n[!] cs_open error: $CallResult"
			echo "[>] Quitting..`n"
		}
		Return
	}

	# Set disassembly syntax
	#---
	# cs_opt_type  -> CS_OPT_SYNTAX = 1
	#---
	# cs_opt_value -> CS_OPT_SYNTAX_INTEL = 1
	#              -> CS_OPT_SYNTAX_ATT   = 2
	if ($Syntax -eq "Intel") {
		$CS_OPT_SYNTAX = 1
	} else {
		$CS_OPT_SYNTAX = 2
	}
	$CallResult = [Capstone]::cs_option($DisAsmHandle, 1, $CS_OPT_SYNTAX)
	if ($CallResult -ne "CS_ERR_OK") {
		echo "`n[!] cs_option error: $CallResult"
		echo "[>] Quitting..`n"
		$CallResult = [Capstone]::cs_close($DisAsmHandle)
		Return
	}

	# Set disassembly detail
	#---
	# cs_opt_type  -> CS_OPT_DETAIL = 2
	#---
	# cs_opt_value -> CS_OPT_ON  = 3
	#              -> CS_OPT_OFF = 0
	if ($Detailed) {
		$CS_OPT = 3
	} else {
		$CS_OPT = 0
	}
	$CallResult = [Capstone]::cs_option($DisAsmHandle, 2, $CS_OPT)
	if ($CallResult -ne "CS_ERR_OK") {
		echo "`n[!] cs_option error: $CallResult"
		echo "[>] Quitting..`n"
		$CallResult = [Capstone]::cs_close($DisAsmHandle)
		Return
	}

	# Out Buffer Handle
	$InsnHandle = [IntPtr]::Zero

	# Disassemble bytes
	$Count = [Capstone]::cs_disasm($DisAsmHandle, $Bytes, $Bytes.Count, $Address, 0, [ref]$InsnHandle)
	
	if ($Count -gt 0) {
		# Result Array
		$Disasm = @()

		# Result struct
		$cs_insn = New-Object cs_insn
		$cs_insn_size = [System.Runtime.InteropServices.Marshal]::SizeOf($cs_insn)
		$cs_insn = $cs_insn.GetType()

		# Result detail struct
		$cs_detail = New-Object cs_detail
		$cs_detail = $cs_detail.GetType()
	
		# Result buffer offset
		$BuffOffset = $InsnHandle.ToInt64()
	
		for ($i=0; $i -lt $Count; $i++) {
			# Cast Offset to cs_insn
			$InsnPointer = New-Object System.Intptr -ArgumentList $BuffOffset
			$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($InsnPointer,[type]$cs_insn)
	
			if ($CS_OPT -eq 0) {
				# Some dirty tricks for spacing, sorry mmkay!
				if ($i -eq 0) {
					$Disasm += echo "`n"
				}
				$Disasm += echo "$($Cast.mnemonic) $($Cast.operands)"
				if ($i -eq $($count-1)){
					$Disasm += echo "`n"
				}
			} else {
				$DetailCast = [system.runtime.interopservices.marshal]::PtrToStructure($Cast.detail,[type]$cs_detail)
				if($DetailCast.regs_read_count -gt 0) {
					$RegRead = @()
					for ($r=0; $r -lt $DetailCast.regs_read_count; $r++) {
						$NamePointer = [Capstone]::cs_reg_name($DisAsmHandle, $DetailCast.regs_read[$r])
						$RegRead += [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePointer)
					}
				}
				if ($DetailCast.regs_write_count -gt 0) {
					$RegWrite = @()
					for ($r=0; $r -lt $DetailCast.regs_write_count; $r++) {
						$NamePointer = [Capstone]::cs_reg_name($DisAsmHandle, $DetailCast.regs_write[$r])
						$RegWrite += [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePointer)
					}
				}
				$HashTable = @{
					Address = echo "0x$("{0:X}" -f $Cast.address)"
					Mnemonic = $Cast.mnemonic
					Operands = $Cast.operands
					Bytes = $Cast.bytes
					Size = $Cast.size
					RegRead = $RegRead
					RegWrite = $RegWrite
				}
				$Object = New-Object PSObject -Property $HashTable
				$Disasm += $Object |Select-Object Size,Address,Mnemonic,Operands,Bytes,RegRead,RegWrite
			}
			$BuffOffset = $BuffOffset + $cs_insn_size
		}
	} else {
		echo "[!] Disassembly Failed"
		echo "[>] Quitting.."
		$CallResult = [Capstone]::cs_close($DisAsmHandle)
		Return
	}
	
	# Print result
	$Disasm
	
	# Free Buffer Handle
	$CallResult = [Capstone]::cs_free($InsnHandle, $Count)
}