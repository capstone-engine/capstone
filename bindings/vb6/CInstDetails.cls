VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CInstDetails"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Option Explicit
'Capstone Disassembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache
'Copyright: FireEye 2017

'Public Type cs_detail
'    regs_read(0 To 11) As      Byte ' list of implicit registers read by this insn UNSIGNED
'    regs_read_count As         Byte ' number of implicit registers read by this insn UNSIGNED
'    regs_write(0 To 19) As     Byte ' list of implicit registers modified by this insn UNSIGNED
'    regs_write_count As        Byte ' number of implicit registers modified by this insn UNSIGNED
'    groups(0 To 7) As          Byte ' list of group this instruction belong to UNSIGNED
'    groups_count As            Byte ' number of groups this insn belongs to UNSIGNED
'
'    // Architecture-specific instruction info
'    union {
'        cs_x86 x86; // X86 architecture, including 16-bit, 32-bit & 64-bit mode
'        cs_arm64 arm64; // ARM64 architecture (aka AArch64)
'        cs_arm arm;     // ARM architecture (including Thumb/Thumb2)
'        cs_mips mips;   // MIPS architecture
'        cs_ppc ppc; // PowerPC architecture
'        cs_sparc sparc; // Sparc architecture
'        cs_sysz sysz;   // SystemZ architecture
'        cs_xcore xcore; // XCore architecture
'    };
'} cs_detail;
    
Public regRead As New Collection
Public regWritten As New Collection
Public groups As New Collection
Public parent As CDisassembler

'this will be set to a class of the specific instruction info type by architecture..
Public info As Object

Private m_raw() As Byte

Function toString() As String
    
    On Error Resume Next
    
    Dim ret() As String
    Dim v, tmp
     
    push ret, "Instruction details: "
    push ret, String(40, "-")
    
    If DEBUG_DUMP Then
        push ret, "Raw: "
        push ret, HexDump(m_raw)
    End If
    
    push ret, "Registers Read: " & regRead.count & IIf(regRead.count > 0, "  Values: " & col2Str(regRead), Empty)
    push ret, "Registers Written: " & regWritten.count & IIf(regWritten.count > 0, "  Values: " & col2Str(regWritten), Empty)
    push ret, "Groups: " & groups.count & IIf(groups.count > 0, "  Values: " & col2Str(groups), Empty)
    
    'it is expected that each CXXInst class implements a toString() method..if not we catch the error anyway..
    If Not info Is Nothing Then
        push ret, info.toString()
    End If
    
    toString = Join(ret, vbCrLf)
    
End Function

Friend Sub LoadDetails(lpDetails As Long, parent As CDisassembler)
        
    Dim cd As cs_detail
    Dim i As Long
    Dim x86 As CX86Inst
    
    Set Me.parent = parent
    
    'vbdef only contains up to the groups_count field..
    CopyMemory ByVal VarPtr(cd), ByVal lpDetails, LenB(cd)
    
    If DEBUG_DUMP Then
        ReDim m_raw(LenB(cd))
        CopyMemory ByVal VarPtr(m_raw(0)), ByVal lpDetails, LenB(cd)
    End If
    
    For i = 1 To cd.regs_read_count
        regRead.Add cd.regs_read(i - 1)
    Next
    
    For i = 1 To cd.regs_write_count
        regWritten.Add cd.regs_write(i - 1)
    Next
    
    For i = 1 To cd.groups_count
        groups.Add cd.groups(i - 1)
    Next
    
    Const align = 5
    
    'each arch needs its own CxxInstr class implemented here...
    If parent.arch = CS_ARCH_X86 Then
        Set x86 = New CX86Inst
        x86.LoadDetails lpDetails + LenB(cd) + align, parent
        Set info = x86
    End If
    
    
    
End Sub
