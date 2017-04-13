VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CX86Operand"
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


'// Instruction operand sizeof() reports 48 bytes
'typedef struct cs_x86_op {
'        x86_op_type type;   // operand type
'
'        union {
'            x86_reg reg;    // register value for REG operand
'            int64_t imm;    // immediate value for IMM operand
'            double fp;      // floating point value for FP operand
'            x86_op_mem mem; // base/index/scale/disp value for MEM operand (24bytes max)
'        };
'
'        // size of this operand (in bytes).
'        uint8_t size;
'
'        // AVX broadcast type, or 0 if irrelevant
'        x86_avx_bcast avx_bcast;
'
'        // AVX zero opmask {z}
'        bool avx_zero_opmask;
'} cs_x86_op;

'Instruction's operand referring to memory
'This is associated with X86_OP_MEM operand type above
'Public Type x86_op_mem
'    segment As Long  ' segment register (or X86_REG_INVALID if irrelevant) UNSIGNED
'    base As Long     ' base register (or X86_REG_INVALID if irrelevant) UNSIGNED
'    index As Long    ' index register (or X86_REG_INVALID if irrelevant) UNSIGNED
'    scale As Long    ' scale for index register
'    disp As Currency ' displacement value
'End Type

'this shows the alignment padding used by compiler..
'    cs_x86_op op;
'    op.type = (x86_op_type)1;
'    op.reg = (x86_reg)2;
'    op.avx_bcast = (x86_avx_bcast)3;
'    op.avx_zero_opmask = 4;
'    op.size = 0xaa;
'    printf("&cs_x86_op = %x", &op);
'    _asm int 3
'
'
'0x0012FF34  01 00 00 00 cc cc cc cc 02 00 00 00 cc cc cc cc  ....лллл....лллл
'0x0012FF44  cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  лллллллллллллллл
'0x0012FF54  aa cc cc cc 03 00 00 00 01 cc cc cc cc cc cc cc  ╙ллл.....ллллллл

Public optype As x86_op_type
Public size As Byte
Public avx_bcast As x86_avx_bcast
Public avx_zero_opmask As Boolean

'only one of the following will be set based on type
Public reg As x86_reg
Public fp As Currency
Public imm As Currency
Public mem As CX86OpMem

Private hEngine As Long
Private m_raw() As Byte

Function toString() As String
    
    Dim ret() As String
    
    push ret, "X86 Operand:"
    push ret, String(45, "-")
    
    If DEBUG_DUMP Then
        push ret, "Raw: "
        push ret, HexDump(m_raw)
    End If
    
    push ret, "Type: " & opStr()
    push ret, "Size: " & size
    If avx_bcast <> 0 Then push ret, "BCast: " & bcastStr()
    If avx_zero_opmask Then push ret, "AvxOpMask: " & avx_zero_opmask
    
    If optype = X86_OP_FP Then
         push ret, "FP: " & cur2str(fp)
    ElseIf optype = X86_OP_IMM Then
         push ret, "IMM: " & cur2str(imm)
    ElseIf optype = x86_op_mem Then
        If mem.base <> 0 Then push ret, "Base: " & regName(hEngine, mem.base)
        If mem.index <> 0 Then push ret, "Index: " & regName(hEngine, mem.index)
        If mem.scale_ <> 1 Then push ret, "Scale: " & Hex(mem.scale_)
        If mem.segment <> 0 Then push ret, "Seg: " & regName(hEngine, mem.segment)
        If mem.disp <> 0 Then push ret, "Disp: " & cur2str(mem.disp)
    ElseIf optype = X86_OP_REG Then
         push ret, "Reg: " & regName(hEngine, reg)
    End If
    
    toString = Join(ret, vbCrLf)
    
End Function

Function opStr() As String

    If optype = X86_OP_FP Then opStr = "X86_OP_FP"
    If optype = x86_op_mem Then opStr = "x86_op_mem"
    If optype = X86_OP_IMM Then opStr = "X86_OP_IMM"
    If optype = X86_OP_REG Then opStr = "X86_OP_REG"
    If optype = X86_OP_INVALID Then opStr = "X86_OP_INVALID"
    
    If Len(opStr) = 0 Then
        opStr = "Error: " & Hex(optype)
    ElseIf DEBUG_DUMP Then
        opStr = opStr & " (" & Hex(optype) & ")"
    End If
        
End Function

Function bcastStr() As String
    Dim r As String
    
    If avx_bcast = X86_AVX_BCAST_INVALID Then r = "X86_AVX_BCAST_INVALID"
    If avx_bcast = X86_AVX_BCAST_2 Then r = "X86_AVX_BCAST_2"
    If avx_bcast = X86_AVX_BCAST_4 Then r = "X86_AVX_BCAST_4"
    If avx_bcast = X86_AVX_BCAST_8 Then r = "X86_AVX_BCAST_8"
    If avx_bcast = X86_AVX_BCAST_16 Then r = "X86_AVX_BCAST_16"
    
    If Len(r) = 0 Then
        r = "Unknown: " & Hex(avx_bcast)
    ElseIf DEBUG_DUMP Then
        r = r & " (" & Hex(avx_bcast) & ")"
    End If
    
    bcastStr = r
End Function


Friend Sub LoadDetails(lpStruct As Long, hCapstone As Long)
    
    Dim opMem As x86_op_mem
    Dim ptr As Long
    
    Const align4 = 4
    Const align3 = 3
    
    hEngine = hCapstone
    
    If DEBUG_DUMP Then
        ReDim m_raw(48)
        CopyMemory ByVal VarPtr(m_raw(0)), ByVal lpStruct, 48
    End If
    
    optype = readLng(lpStruct)
    ptr = lpStruct + 4 + align4
    
    If optype = X86_OP_FP Then
        fp = readCur(ptr)
    ElseIf optype = X86_OP_IMM Then
        imm = readCur(ptr)
    ElseIf optype = x86_op_mem Then
        CopyMemory ByVal VarPtr(opMem), ByVal ptr, LenB(opMem)
        Set mem = New CX86OpMem
        mem.base = opMem.base
        mem.disp = opMem.disp
        mem.index = opMem.index
        mem.scale_ = opMem.scale
        mem.segment = opMem.segment
    ElseIf optype = X86_OP_REG Then
        reg = readLng(ptr)
    End If
    
    ptr = ptr + LenB(opMem)
    
    size = readByte(ptr)
    ptr = ptr + 1 + align3
    
    avx_bcast = readLng(ptr)
    ptr = ptr + 4
    
    avx_zero_opmask = (readByte(ptr) = 1)
    
End Sub

Private Sub Class_Terminate()
    'looks like everything is freeing up ok
    'Debug.Print "Cx86Operand.Terminate"
End Sub
