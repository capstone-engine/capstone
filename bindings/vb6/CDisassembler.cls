VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CDisassembler"
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


'NOTE: the VB code was built and tested against Capstone v3.0 rc4
'      if the capstone C structures change, the VB code will have to
'      be adjusted to match!
'
'      instructions details are currently only implemented for x86

Public arch As cs_arch
Public mode As cs_mode
Public hCapstone As Long
Public hLib As Long

Public version As String
Public vMajor As Long
Public vMinor As Long

Public errMsg As String
Public lastErr As cs_err

Private Function CheckPath(pth As String) As Long
    
    Dim hCap As Long, capPth As String, shimPth As String
    
    shimPth = pth & "\vbCapstone.dll"
    capPth = pth & "\capstone.dll"
    
    If Not FileExists(shimPth) Then Exit Function
       
    hCap = LoadLibrary(capPth)
    If hCap = 0 Then hCap = LoadLibrary("capstone.dll")
    If hCap = 0 Then errMsg = "Could not find capstone.dll"
    
    CheckPath = LoadLibrary(shimPth)
    'If CheckPath = 0 Then MsgBox Err.LastDllError
    
End Function

Public Function init(arch As cs_arch, mode As cs_mode, Optional enableDetails As Boolean = False) As Boolean
    
    errMsg = Empty
    hLib = GetModuleHandle("vbCapstone.dll")
    
    If hLib = 0 Then hLib = CheckPath(App.path & "\bin\")
    If hLib = 0 Then hLib = CheckPath(App.path & "\")
    If hLib = 0 Then hLib = CheckPath(App.path & "\..\")
    If hLib = 0 Then hLib = LoadLibrary("vbCapstone.dll")
    
    If hLib = 0 Then
        errMsg = errMsg & " Could not load vbCapstone.dll"
        Exit Function
    End If
    
    Me.arch = arch
    Me.mode = mode
    
    cs_version vMajor, vMinor
    version = vMajor & "." & vMinor
    
    If cs_support(arch) = 0 Then
        errMsg = "specified architecture not supported"
        Exit Function
    End If
    
    Dim handle As Long 'in vb class a public var is actually a property get/set can not use as byref to api..
    lastErr = cs_open(arch, mode, handle)
    If lastErr <> CS_ERR_OK Then
        errMsg = err2str(lastErr)
        Exit Function
    End If

    hCapstone = handle
    If enableDetails Then          'vb bindings currently only support details for x86
        If arch = CS_ARCH_X86 Then
            cs_option handle, CS_OPT_DETAIL, CS_OPT_ON
        End If
    End If
    
    init = True
    
End Function

'base is a variant and currently accepts the following input types:
'  x64 number held as currency type (ex.  makeCur(&haabbccdd, &h11223344) )
'  int/long value (ex. &h1000 or 12345)
'  numeric string or 0x/&h prefixed hex string (ex. "12345", "0x1200", "&haabbccdd")
Function disasm(ByVal base, code() As Byte, Optional count As Long = 0) As Collection

    Dim c As Long
    Dim instAry As Long
    Dim ret As New Collection
    Dim ci As CInstruction
    Dim i As Long
    Dim address As Currency

    On Error Resume Next
    
    Set disasm = ret
    
    If TypeName(base) = "Currency" Then
        address = base
    Else
        If TypeName(base) = "String" Then base = Replace(Trim(base), "0x", "&h")
        address = lng2Cur(CLng(base))
        If Err.Number <> 0 Then
            errMsg = "Could not convert base address to long"
            Exit Function
        End If
    End If
    
    c = cs_disasm(Me.hCapstone, code(0), UBound(code) + 1, address, count, instAry)
    If c = 0 Then Exit Function
            
    For i = 0 To c - 1
        Set ci = New CInstruction
        ci.LoadInstruction instAry, i, Me
        ret.Add ci
    Next
    
    cs_free instAry, c
    
End Function
 

Private Sub Class_Terminate()
    Dim msg As String
    If DEBUG_DUMP Then
        msg = "CDissembler.Terminate " & Hex(hCapstone)
        If hCapstone <> 0 Then lastErr = cs_close(hCapstone)
        Debug.Print msg & " : " & lastErr
    End If
End Sub

