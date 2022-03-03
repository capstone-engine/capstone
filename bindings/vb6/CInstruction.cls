VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CInstruction"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Option Explicit

'Capstone Disassembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache 2.0
'Copyright: FireEye 2017


'Public Type cs_insn
'                              ' Instruction ID (basically a numeric ID for the instruction mnemonic)
'                              ' Find the instruction id in the '[ARCH]_insn' enum in the header file
'                              ' of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
'                              ' 'x86_insn' in x86.h for X86, etc...
'                              ' available even when CS_OPT_DETAIL = CS_OPT_OFF
'                              ' NOTE: in Skipdata mode, "data" instruction has 0 for this id field. UNSIGNED
'    id As Long                '
'    align As Long             'not sure why it needs this..but it does..
'    address As Currency       ' Address (EIP) of this instruction available even when CS_OPT_DETAIL = CS_OPT_OFF UNSIGNED
'    size As Integer           ' Size of this instruction available even when CS_OPT_DETAIL = CS_OPT_OFF UNSIGNED
'    bytes(0 To 23) As Byte    ' Machine bytes of this instruction, with number of bytes indicated by @size above available even when CS_OPT_DETAIL = CS_OPT_OFF
'    mnemonic(0 To 31) As Byte ' Ascii text of instruction mnemonic available even when CS_OPT_DETAIL = CS_OPT_OFF
'    op_str(0 To 159) As Byte  ' Ascii text of instruction operands available even when CS_OPT_DETAIL = CS_OPT_OFF
'
'                              ' Pointer to cs_detail.
'                              ' NOTE: detail pointer is only valid when both requirements below are met:
'                              ' (1) CS_OP_DETAIL = CS_OPT_ON
'                              ' (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
'                              ' NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
'                              '  is not NULL, its content is still irrelevant.
'    lpDetail As Long          '  points to a cs_detail structure NOTE: only available when CS_OPT_DETAIL = CS_OPT_ON
'
'End Type

Public ID As Long
Public address As Currency
Public size As Long
Private m_bytes() As Byte
Public instruction As String
Public operand As String
Public lpDetails As Long
Public parent As CDisassembler

Public details As CInstDetails 'may be null

Property Get bytes() As Byte()
    bytes = Me.bytes()
End Property

Property Get byteDump(Optional padding = 15) As String
    Dim b As String, i As Long
    For i = 0 To UBound(m_bytes)
        b = b & hhex(m_bytes(i)) & " "
    Next
    byteDump = rpad(b, padding)
End Property

Property Get text() As String
   
    text = cur2str(address) & "    " & byteDump & "    " & instruction & " " & operand
    
End Property

Function toString() As String
    
    Dim r() As String
    
    push r, "CInstruction: "
    push r, String(40, "-")
    push r, "Id: " & Hex(ID)
    push r, "address: " & cur2str(address)
    push r, "size: " & Hex(size)
    push r, "bytes: " & byteDump()
    push r, "instruction: " & instruction
    push r, "operand: " & operand
    push r, "lpDetails: " & Hex(lpDetails)
    
    If Not details Is Nothing Then
        push r, details.toString()
    End If
    
    toString = Join(r, vbCrLf)
    
End Function

Friend Sub LoadInstruction(instAry As Long, index As Long, parent As CDisassembler)

    Dim inst As cs_insn
    Dim i As Long
    
    getInstruction instAry, index, VarPtr(inst), LenB(inst)
    
    ID = inst.ID
    address = inst.address
    size = inst.size
    lpDetails = inst.lpDetail
    Set Me.parent = parent
    
    m_bytes() = inst.bytes
    ReDim Preserve m_bytes(size - 1)
    
    For i = 0 To UBound(inst.mnemonic)
        If inst.mnemonic(i) = 0 Then Exit For
        instruction = instruction & Chr(inst.mnemonic(i))
    Next
    
    For i = 0 To UBound(inst.op_str)
        If inst.op_str(i) = 0 Then Exit For
        operand = operand & Chr(inst.op_str(i))
    Next

    If lpDetails = 0 Then Exit Sub
    Set details = New CInstDetails
    details.LoadDetails lpDetails, parent
    
End Sub


    

