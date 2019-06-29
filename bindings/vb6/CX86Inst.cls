VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CX86Inst"
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


'// Instruction structure  sizeof() = 432 bytes
'typedef struct cs_x86 {
'    // Instruction prefix, which can be up to 4 bytes.
'    // A prefix byte gets value 0 when irrelevant.
'    // prefix[0] indicates REP/REPNE/LOCK prefix (See X86_PREFIX_REP/REPNE/LOCK above)
'    // prefix[1] indicates segment override (irrelevant for x86_64):
'    // See X86_PREFIX_CS/SS/DS/ES/FS/GS above.
'    // prefix[2] indicates operand-size override (X86_PREFIX_OPSIZE)
'    // prefix[3] indicates address-size override (X86_PREFIX_ADDRSIZE)
'    uint8_t prefix[4];
'
'    // Instruction opcode, wich can be from 1 to 4 bytes in size.
'    // This contains VEX opcode as well.
'    // An trailing opcode byte gets value 0 when irrelevant.
'    uint8_t opcode[4];
'
'    // REX prefix: only a non-zero value is relavant for x86_64
'    uint8_t rex;
'
'    // Address size, which can be overrided with above prefix[5].
'    uint8_t addr_size;
'
'    // ModR/M byte
'    uint8_t modrm;
'
'    // SIB value, or 0 when irrelevant.
'    uint8_t sib;
'
'    // Displacement value, or 0 when irrelevant.
'    int32_t disp;
'
'    /* SIB state */
'    // SIB index register, or X86_REG_INVALID when irrelevant.
'    x86_reg sib_index;
'    // SIB scale. only applicable if sib_index is relavant.
'    int8_t sib_scale;
'    // SIB base register, or X86_REG_INVALID when irrelevant.
'    x86_reg sib_base;
'
'    // SSE Code Condition
'    x86_sse_cc sse_cc;
'
'    // AVX Code Condition
'    x86_avx_cc avx_cc;
'
'    // AVX Suppress all Exception
'    bool avx_sae;
'
'    // AVX static rounding mode
'    x86_avx_rm avx_rm;
'
'    // Number of operands of this instruction,
'    // or 0 when instruction has no operand.
'    uint8_t op_count;
'
'    cs_x86_op operands[8];  // operands for this instruction.
'} cs_x86;

Private m_prefix() As Byte
Private m_opcode() As Byte
Public rex As Byte
Public addr_size As Byte
Public modrm As Byte
Public sib As Byte
Public disp As Long
Public sib_index As x86_reg
Public sib_scale As Byte
Public sib_base As x86_reg
Public sse_cc As x86_sse_cc
Public avx_cc As x86_avx_cc
Public avx_sae As Boolean
Public avx_rm As x86_avx_rm
Public operands As New Collection

Public parent As CDisassembler
Private hEngine As Long
Private m_raw() As Byte

Property Get prefix() As Byte()
    prefix = m_prefix
End Property

Property Get opcode() As Byte()
    opcode = m_opcode
End Property

Function toString() As String
    
    Dim r() As String
    Dim o As CX86Operand
    
    push r, "X86 Instruction Details:"
    push r, String(40, "-")
    
    If DEBUG_DUMP Then
        push r, "Raw: "
        push r, HexDump(m_raw)
    End If
    
    push r, "Prefix: " & b2Str(m_prefix)
    push r, "OpCode: " & b2Str(m_opcode)
    push r, "Rex: " & rex
    push r, "addr_size: " & addr_size
    push r, "modrm: " & Hex(modrm)
    push r, "disp: " & Hex(disp)
    
    If parent.mode <> CS_MODE_16 Then
        push r, "sib: " & Hex(sib)
        push r, "sib_index: " & regName(hEngine, sib_index)
        push r, "sib_scale: " & Hex(sib_scale)
        push r, "sib_base: " & regName(hEngine, sib_base)
    End If
    
    If sse_cc <> 0 Then push r, "sse_cc: " & x86_sse_cc2str(sse_cc)
    If avx_cc <> 0 Then push r, "avx_cc: " & x86_avx_cc2str(avx_cc)
    If avx_sae <> 0 Then push r, "avx_sae: " & avx_sae
    If avx_rm <> 0 Then push r, "avx_rm: " & x86_avx_rm2str(avx_rm)
    
    push r, "Operands: " & operands.count
    
    For Each o In operands
        push r, String(40, "-")
        push r, o.toString
    Next
    
    toString = Join(r, vbCrLf)
    
End Function

Friend Sub LoadDetails(lpStruct As Long, parent As CDisassembler)
    
    Dim cs As cs_x86
    Dim o As CX86Operand
    Dim ptr As Long
    Dim i As Long
    
    Const sizeOfx86Operand = 48
    
    Set Me.parent = parent
    hEngine = parent.hCapstone

    CopyMemory ByVal VarPtr(cs), ByVal lpStruct, LenB(cs)
    
    If DEBUG_DUMP Then
        ReDim m_raw(LenB(cs))
        CopyMemory ByVal VarPtr(m_raw(0)), ByVal lpStruct, LenB(cs)
    End If
    
    Me.rex = cs.rex
    Me.addr_size = cs.addr_size
    Me.modrm = cs.modrm
    Me.sib = cs.sib
    Me.disp = cs.disp
    Me.sib_index = cs.sib_index
    Me.sib_scale = cs.sib_scale
    Me.sib_base = cs.sib_base
    Me.sse_cc = cs.sse_cc
    Me.avx_cc = cs.avx_cc
    Me.avx_sae = cs.avx_sae
    Me.avx_rm = cs.avx_rm
    m_prefix = cs.prefix
    m_opcode = cs.opcode
    
    ptr = lpStruct + LenB(cs) 'we dont include the operands in our vb struct..
    For i = 1 To cs.op_count
        Set o = New CX86Operand
        o.LoadDetails ptr, hEngine
        operands.Add o
        ptr = ptr + sizeOfx86Operand
    Next
    
    
    
End Sub

