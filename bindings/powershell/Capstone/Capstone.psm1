<#
.SYNOPSIS
    Get Capstone version as Version object
#>
function Get-CapstoneVersion {
    $Version = [System.BitConverter]::GetBytes(
        [Capstone]::cs_version($null, $null)
    )

    New-Object -TypeName version -ArgumentList @(
        $Version[1]
        $Version[0]
        0
        0
    )
}

<#
.SYNOPSIS
    Create C# bindings for capstone.dll

.PARAMETER DllPath
    Path to capstone.dll
#>
function Initialize-Capstone {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                try {
                    Test-Path -Path $_ -PathType Leaf -ErrorAction Stop
                } catch {
                    throw "Capstone DLL is missing: $DllPath"
                }
            })]
        [ValidateNotNullOrEmpty()]
        [string]$DllPath
    )

    # Escape path for use in inline C#
    $DllPath = $DllPath.Replace('\', '\\')

    # Inline C# to parse the unmanaged capstone DLL
    # http://stackoverflow.com/questions/16552801/how-do-i-conditionally-add-a-class-with-add-type-typedefinition-if-it-isnt-add
    if (-not ([System.Management.Automation.PSTypeName]'Capstone').Type) {
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

        public enum cs_err : int
        {
            CS_ERR_OK = 0,    /// No error: everything was fine
            CS_ERR_MEM,       /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
            CS_ERR_ARCH,      /// Unsupported architecture: cs_open()
            CS_ERR_HANDLE,    /// Invalid handle: cs_op_count(), cs_op_index()
            CS_ERR_CSH,       /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
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
        public enum cs_arch : int
        {
            CS_ARCH_ARM = 0,      /// ARM architecture (including Thumb, Thumb-2)
            CS_ARCH_ARM64,        /// ARM-64, also called AArch64
            CS_ARCH_MIPS,         /// Mips architecture
            CS_ARCH_X86,          /// X86 architecture (including x86 & x86-64)
            CS_ARCH_PPC,          /// PowerPC architecture
            CS_ARCH_SPARC,        /// Sparc architecture
            CS_ARCH_SYSZ,         /// SystemZ architecture
            CS_ARCH_XCORE,        /// XCore architecture
            CS_ARCH_MAX,
            CS_ARCH_ALL = 0xFFFF, /// All architectures - for cs_support()
        }
        public enum cs_mode : int
        {
            CS_MODE_LITTLE_ENDIAN = 0,    /// little-endian mode (default mode)
            CS_MODE_ARM = 0,              /// 32-bit ARM
            CS_MODE_16 = 1 << 1,          /// 16-bit mode (X86)
            CS_MODE_32 = 1 << 2,          /// 32-bit mode (X86)
            CS_MODE_64 = 1 << 3,          /// 64-bit mode (X86, PPC)
            CS_MODE_THUMB = 1 << 4,       /// ARM's Thumb mode, including Thumb-2
            CS_MODE_MCLASS = 1 << 5,      /// ARM's Cortex-M series
            CS_MODE_V8 = 1 << 6,          /// ARMv8 A32 encodings for ARM
            CS_MODE_MICRO = 1 << 4,       /// MicroMips mode (MIPS)
            CS_MODE_MIPS3 = 1 << 5,       /// Mips III ISA
            CS_MODE_MIPS32R6 = 1 << 6,    /// Mips32r6 ISA
            CS_MODE_MIPSGP64 = 1 << 7,    /// General Purpose Registers are 64-bit wide (MIPS)
            CS_MODE_V9 = 1 << 4,          /// SparcV9 mode (Sparc)
            CS_MODE_BIG_ENDIAN = 1 << 31, /// big-endian mode
            CS_MODE_MIPS32 = CS_MODE_32,  /// Mips32 ISA (Mips)
            CS_MODE_MIPS64 = CS_MODE_64,  /// Mips64 ISA (Mips)
        }

        public static class Capstone
        {
            [DllImport("$DllPath")]
            public static extern cs_err cs_open(
                cs_arch arch,
                cs_mode mode,
                ref IntPtr handle);

            [DllImport("$DllPath")]
            public static extern UInt32 cs_disasm(
                IntPtr handle,
                byte[] code,
                int code_size,
                ulong address,
                int count,
                ref IntPtr insn);

            [DllImport("$DllPath")]
            public static extern bool cs_free(
                IntPtr insn,
                int count);

            [DllImport("$DllPath")]
            public static extern cs_err cs_close(
                ref IntPtr handle);

            [DllImport("$DllPath")]
            public static extern cs_err cs_option(
                IntPtr handle,
                int type,
                int value);

            [DllImport("$DllPath", CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr cs_reg_name(
                IntPtr handle,
                uint reg_id);

            [DllImport("$DllPath")]
            public static extern int cs_version(
                uint major,
                uint minor);
        }
"@
    } else {
        Write-Verbose 'C# bindings are already compiled'
    }
}

function Get-CapstoneDisassembly {
<#
.SYNOPSIS
    Powershell wrapper for Capstone (using inline C#).

.DESCRIPTION
    Author: Ruben Boonen (@FuzzySec), @beatcracker
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER Architecture
    Architecture type.

.PARAMETER Mode
    Mode type.

.PARAMETER Bytes
    Byte array to be disassembled.

.PARAMETER Syntax
    Syntax for output assembly.

.PARAMETER Address
    Assign address for the first instruction to be disassembled.

.PARAMETER Detailed
    Return detailed output.

.PARAMETER Version
    Print ASCII version banner.

.EXAMPLE

    C:\PS> $Bytes = [byte[]] @( 0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3 )
    C:\PS> Get-CapstoneDisassembly -Architecture CS_ARCH_ARM -Mode CS_MODE_ARM -Bytes $Bytes

    Address     : 0x100000
    Instruction : sdiv r0, r0, r1

    Address     : 0x100004
    Instruction : udiv r1, r1, r2

    Address     : 0x100008
    Instruction : vbit q5, q15, q6

    Address     : 0x10000C
    Instruction : vcgt.f32 q10, q9, q12

.EXAMPLE

    # Detailed mode & ATT syntax
    C:\PS> $Bytes = [byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
    C:\PS> Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_32 -Bytes $Bytes -Syntax ATT -Detailed

    Address  : 0x100000
    Mnemonic : movl
    Operands : $0xa, %eax
    Bytes    : {184, 10, 0, 0...}
    Size     : 5
    RegRead  :
    RegWrite :

    Address  : 0x100005
    Mnemonic : divl
    Operands : %ebx
    Bytes    : {247, 243}
    Size     : 2
    RegRead  : {eax, edx}
    RegWrite : {eax, edx, eflags}

.EXAMPLE

    # Get-CapstoneDisassembly emits objects
    C:\PS> $Bytes = [byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
    C:\PS> $Object = Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_32 -Bytes $Bytes -Detailed
    C:\PS> $Object | Select-Object -Property Size, Mnemonic, Operands

    Size Mnemonic Operands
    ---- -------- --------
    5 mov      eax, 0xa
    2 div      ebx
#>
    [CmdletBinding(DefaultParameterSetName = 'Capstone')]
    Param (
        [Parameter(ParameterSetName = 'Capstone', Mandatory = $true)]
        [ValidateSet(
            'CS_ARCH_ARM',
            'CS_ARCH_ARM64',
            'CS_ARCH_MIPS',
            'CS_ARCH_X86',
            'CS_ARCH_PPC',
            'CS_ARCH_SPARC',
            'CS_ARCH_SYSZ',
            'CS_ARCH_XCORE',
            'CS_ARCH_MAX',
            'CS_ARCH_ALL'
        )]
        [string]$Architecture,

        [Parameter(ParameterSetName = 'Capstone', Mandatory = $true)]
        [ValidateSet(
            'CS_MODE_LITTLE_ENDIAN',
            'CS_MODE_ARM',
            'CS_MODE_16',
            'CS_MODE_32',
            'CS_MODE_64',
            'CS_MODE_THUMB',
            'CS_MODE_MCLASS',
            'CS_MODE_V8',
            'CS_MODE_MICRO',
            'CS_MODE_MIPS3',
            'CS_MODE_MIPS32R6',
            'CS_MODE_MIPSGP64',
            'CS_MODE_V9',
            'CS_MODE_BIG_ENDIAN',
            'CS_MODE_MIPS32',
            'CS_MODE_MIPS64'
        )]
        [string]$Mode,

        [Parameter(ParameterSetName = 'Capstone', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(ParameterSetName = 'Capstone')]
        [ValidateSet(
            'Intel',
            'ATT'
        )]
        [string]$Syntax = 'Intel',

        [Parameter(ParameterSetName = 'Capstone')]
        [uint64]$Address = 0x100000,

        [Parameter(ParameterSetName = 'Capstone')]
        [switch]$Detailed,

        [Parameter(ParameterSetName = 'Version')]
        [switch]$Version
    )

    if ($Version) {
        $Banner = @'

                 (((;
              (; "((((\
           ;((((((; "((((;
          ((((""\(((( "((((
        ((((" ((\ "(((( "(((\
      ;(((/ ((((((( "(((( \(((
     ((((" (((* "(((( \(((;"(((\
    ((((";((("/(( \(((;"(((\"(((\
   (((( (((( ((((" "(((\ ((() (((\
  ;((("(((( (((*     **"" ((()"(((;
  (((" ((( (((( ((((((((((((((:*(((
 (((( (((*)((( ********"""" ;;(((((;
 (((* ((( (((((((((((((((((((((*"" (
 ((("(((( """***********"""" ;;(((((
  "" (((((((((((((((((((((((((((*""
         """****(((((****"""

     -=[Capstone Engine v{0}]=-

'@ -f (Get-CapstoneVersion).ToString(2)
        # Mmm ASCII version banner!
        return $Banner
    }

    # Disasm Handle
    $DisAsmHandle = [System.IntPtr]::Zero

    # Initialize Capstone with cs_open()
    $CallResult = [Capstone]::cs_open($Architecture, $Mode, [ref]$DisAsmHandle)
    if ($CallResult -ne 'CS_ERR_OK') {
        if ($CallResult -eq 'CS_ERR_MODE') {
            throw "Invalid Architecture/Mode combination: $Architecture/$Mode"
        } else {
            throw "cs_open error: $CallResult"
        }
    }

    # Set disassembly syntax
    #---
    # cs_opt_type  -> CS_OPT_SYNTAX = 1
    #---
    # cs_opt_value -> CS_OPT_SYNTAX_INTEL = 1
    #              -> CS_OPT_SYNTAX_ATT   = 2
    if ($Syntax -eq 'Intel') {
        $CS_OPT_SYNTAX = 1
    } else {
        $CS_OPT_SYNTAX = 2
    }

    $CallResult = [Capstone]::cs_option($DisAsmHandle, 1, $CS_OPT_SYNTAX)
    if ($CallResult -ne 'CS_ERR_OK') {
        $CallResult = [Capstone]::cs_close([ref]$DisAsmHandle)
        throw "cs_option error: $CallResult"
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
    if ($CallResult -ne 'CS_ERR_OK') {
        $CallResult = [Capstone]::cs_close([ref]$DisAsmHandle)
        throw "cs_option error: $CallResult"
    }

    # Out Buffer Handle
    $InsnHandle = [System.IntPtr]::Zero

    # Disassemble bytes
    $Count = [Capstone]::cs_disasm($DisAsmHandle, $Bytes, $Bytes.Count, $Address, 0, [ref]$InsnHandle)

    if ($Count -gt 0) {
        # Result struct
        $cs_insn = if ($PSVersionTable.PSVersion.Major -gt 2) {
            [cs_insn]@{}
        } else {
            New-Object -TypeName cs_insn
        }

        $cs_insn_size = [System.Runtime.InteropServices.Marshal]::SizeOf($cs_insn)
        $cs_insn = $cs_insn.GetType()

        # Result detail struct
        $cs_detail = if ($PSVersionTable.PSVersion.Major -gt 2) {
            [cs_detail]@{}
        } else {
            New-Object -TypeName cs_detail
        }
        $cs_detail = $cs_detail.GetType()

        # Result buffer offset
        $BuffOffset = $InsnHandle.ToInt64()

        for ($i = 0 ; $i -lt $Count ; $i++) {
            # Cast Offset to cs_insn
            $Cast = [System.Runtime.InteropServices.Marshal]::PtrToStructure([System.Intptr]$BuffOffset, [type]$cs_insn)

            if ($CS_OPT -eq 0) {
                $Disassembly = @{
                    Address     = $Cast.address
                    Instruction = '{0} {1}' -f $Cast.mnemonic, $Cast.operands
                }

                if ($PSVersionTable.PSVersion.Major -gt 2) {
                    # Add TypeName for PS formatting and output result
                    $Disassembly.PSTypeName ='CapstoneDisassembly.Simple'
                    [pscustomobject]$Disassembly
                } else {
                    $Disassembly = New-Object -TypeName PSObject -Property $Disassembly
                    # Add TypeName for PS formatting and output result
                    $Disassembly.PSObject.TypeNames.Insert(0, 'CapstoneDisassembly.Simple')
                    $Disassembly
                }
            } else {
                $DetailCast = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Cast.detail, [type]$cs_detail)
                if ($DetailCast.regs_read_count -gt 0) {
                    $RegRead = for ($r = 0 ; $r -lt $DetailCast.regs_read_count ; $r++) {
                        $NamePointer = [Capstone]::cs_reg_name($DisAsmHandle, $DetailCast.regs_read[$r])
                        [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePointer)
                    }
                }

                if ($DetailCast.regs_write_count -gt 0) {
                    $RegWrite = for ($r = 0 ; $r -lt $DetailCast.regs_write_count ; $r++) {
                        $NamePointer = [Capstone]::cs_reg_name($DisAsmHandle, $DetailCast.regs_write[$r])
                        [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePointer)
                    }
                }

                $Disassembly = @{
                    Address    = $Cast.address
                    Mnemonic   = $Cast.mnemonic
                    Operands   = $Cast.operands
                    Bytes      = $Cast.bytes[0..($Cast.size - 1)]
                    Size       = $Cast.size
                    RegRead    = $RegRead
                    RegWrite   = $RegWrite
                }

                if ($PSVersionTable.PSVersion.Major -gt 2) {
                    # Add TypeName for PS formatting and output result
                    $Disassembly.PSTypeName = 'CapstoneDisassembly.Detailed'
                    [pscustomobject]$Disassembly
                } else {
                    $Disassembly = New-Object -TypeName PSObject -Property $Disassembly
                    # Add TypeName for PS formatting and output result
                    $Disassembly.PSObject.TypeNames.Insert(0, 'CapstoneDisassembly.Detailed')
                    $Disassembly
                }
            }
            $BuffOffset = $BuffOffset + $cs_insn_size
        }
    } else {
        $CallResult = [Capstone]::cs_close([ref]$DisAsmHandle)
        throw 'Disassembly Failed'
    }

    # Free Buffer Handle
    $CallResult = [Capstone]::cs_free($InsnHandle, $Count)
}

#region Init

Initialize-Capstone -DllPath (
    Join-Path -Path $PSScriptRoot -ChildPath 'Lib\Capstone\capstone.dll'
) -ErrorAction Stop

#endregion