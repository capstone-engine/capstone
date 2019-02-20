Attribute VB_Name = "mMisc"
Option Explicit

'These are old library functions

Private Type Bit64Currency
  value As Currency
End Type

Private Type Bit64Integer
  LowValue As Long
  HighValue As Long
End Type

Global Const LANG_US = &H409

Public Declare Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As Long
Public Declare Function FreeLibrary Lib "kernel32" (ByVal hLibModule As Long) As Long
Public Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal length As Long)
Public Declare Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Public Declare Function GetModuleHandle Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long
Public Declare Function SetDllDirectory Lib "kernel32" Alias "SetDllDirectoryA" (ByVal lpPathName As String) As Long

Function makeCur(high As Long, low As Long) As Currency
  Dim c As Bit64Currency
  Dim dl As Bit64Integer
  dl.LowValue = low
  dl.HighValue = high
  LSet c = dl
  makeCur = c.value
End Function

Function lng2Cur(v As Long) As Currency
  Dim c As Bit64Currency
  Dim dl As Bit64Integer
  dl.LowValue = v
  dl.HighValue = 0
  LSet c = dl
  lng2Cur = c.value
End Function

Function cur2str(v As Currency) As String
    Dim c As Bit64Currency
    Dim dl As Bit64Integer
    c.value = v
    LSet dl = c
    If dl.HighValue = 0 Then
        cur2str = Right("00000000" & Hex(dl.LowValue), 8)
    Else
        cur2str = Right("00000000" & Hex(dl.HighValue), 8) & "`" & Right("00000000" & Hex(dl.LowValue), 8)
    End If
End Function

Function x64StrToCur(ByVal str As String) As Currency
        
    str = Replace(Trim(str), "0x", "")
    str = Replace(str, " ", "")
    str = Replace(str, "`", "")
     
    Dim low As String, high As String
    Dim c As Bit64Currency
    Dim dl As Bit64Integer
    
    low = VBA.Right(str, 8)
    dl.LowValue = CLng("&h" & low)
    
    If Len(str) > 8 Then
        high = Mid(str, 1, Len(str) - 8)
        dl.HighValue = CLng("&h" & high)
    End If
     
    LSet c = dl
    x64StrToCur = c.value
      
End Function

Function cur2lng(v As Currency) As Long
  Dim c As Bit64Currency
  Dim dl As Bit64Integer
  c.value = v
  LSet dl = c
  cur2lng = dl.LowValue
End Function

Function readLng(offset As Long) As Long
    Dim tmp As Long
    CopyMemory ByVal VarPtr(tmp), ByVal offset, 4
    readLng = tmp
End Function

Function readByte(offset As Long) As Byte
    Dim tmp As Byte
    CopyMemory ByVal VarPtr(tmp), ByVal offset, 1
    readByte = tmp
End Function

Function readCur(offset As Long) As Currency
    Dim tmp As Currency
    CopyMemory ByVal VarPtr(tmp), ByVal offset, 8
    readCur = tmp
End Function

Function col2Str(c As Collection, Optional emptyVal = "") As String
    Dim v, tmp As String
    
    If c.count = 0 Then
        col2Str = emptyVal
    Else
        For Each v In c
            col2Str = col2Str & hhex(v) & ", "
        Next
        col2Str = Mid(col2Str, 1, Len(col2Str) - 2)
    End If
    
End Function

Function regCol2Str(hEngine As Long, c As Collection) As String
    Dim v, tmp As String
    
    If c.count = 0 Then Exit Function
    
    For Each v In c
        regCol2Str = regCol2Str & regName(hEngine, CLng(v)) & ", "
    Next
    regCol2Str = Mid(regCol2Str, 1, Len(regCol2Str) - 2)
    
End Function



Function b2Str(b() As Byte) As String
    Dim i As Long
    
    If AryIsEmpty(b) Then
         b2Str = "Empty"
    Else
        For i = 0 To UBound(b)
             b2Str = b2Str & hhex(b(i)) & " "
        Next
        b2Str = Trim(b2Str)
    End If

End Function



Function AryIsEmpty(ary) As Boolean
  Dim i As Long
  
  On Error GoTo oops
    i = UBound(ary)  '<- throws error if not initalized
    AryIsEmpty = False
  Exit Function
oops: AryIsEmpty = True
End Function

Public Function toBytes(ByVal hexstr, Optional strRet As Boolean = False)

'supports:
'11 22 33 44   spaced hex chars
'11223344      run together hex strings
'11,22,33,44   csv hex
'\x11,0x22     misc C source rips
'
'ignores common C source prefixes, operators, delimiters, and whitespace
'
'not supported
'1,2,3,4        all hex chars are must have two chars even if delimited
'
'a version which supports more formats is here:
'  https://github.com/dzzie/libs/blob/master/dzrt/globals.cls

    Dim ret As String, x As String, str As String
    Dim r() As Byte, b As Byte, b1 As Byte
    Dim foundDecimal As Boolean, tmp, i, a, a2
    Dim pos As Long, marker As String
    
    On Error GoTo nope
    
    str = Replace(hexstr, vbCr, Empty)
    str = Replace(str, vbLf, Empty)
    str = Replace(str, vbTab, Empty)
    str = Replace(str, Chr(0), Empty)
    str = Replace(str, "{", Empty)
    str = Replace(str, "}", Empty)
    str = Replace(str, ";", Empty)
    str = Replace(str, "+", Empty)
    str = Replace(str, """""", Empty)
    str = Replace(str, "'", Empty)
    str = Replace(str, " ", Empty)
    str = Replace(str, "0x", Empty)
    str = Replace(str, "\x", Empty)
    str = Replace(str, ",", Empty)
    
    For i = 1 To Len(str) Step 2
        x = Mid(str, i, 2)
        If Not isHexChar(x, b) Then Exit Function
        bpush r(), b
    Next
    
    If strRet Then
        toBytes = StrConv(r, vbUnicode, LANG_US)
    Else
        toBytes = r
    End If
    
nope:
End Function

Private Sub bpush(bAry() As Byte, b As Byte) 'this modifies parent ary object
    On Error GoTo init
    Dim x As Long
    
    x = UBound(bAry) '<-throws Error If Not initalized
    ReDim Preserve bAry(UBound(bAry) + 1)
    bAry(UBound(bAry)) = b
    
    Exit Sub

init:
    ReDim bAry(0)
    bAry(0) = b
    
End Sub

Sub push(ary, value) 'this modifies parent ary object
    On Error GoTo init
    Dim x
       
    x = UBound(ary)
    ReDim Preserve ary(x + 1)
    
    If IsObject(value) Then
        Set ary(x + 1) = value
    Else
        ary(x + 1) = value
    End If
    
    Exit Sub
init:
    ReDim ary(0)
    If IsObject(value) Then
        Set ary(0) = value
    Else
        ary(0) = value
    End If
End Sub


Public Function isHexChar(hexValue As String, Optional b As Byte) As Boolean
    On Error Resume Next
    Dim v As Long
    
    If Len(hexValue) = 0 Then GoTo nope
    If Len(hexValue) > 2 Then GoTo nope 'expecting hex char code like FF or 90
    
    v = CLng("&h" & hexValue)
    If Err.Number <> 0 Then GoTo nope 'invalid hex code
    
    b = CByte(v)
    If Err.Number <> 0 Then GoTo nope  'shouldnt happen.. > 255 cant be with len() <=2 ?

    isHexChar = True
    
    Exit Function
nope:
    Err.Clear
    isHexChar = False
End Function

Function hhex(b) As String
    hhex = Right("00" & Hex(b), 2)
End Function

Function rpad(x, i, Optional c = " ")
    rpad = Left(x & String(i, c), i)
End Function

Function HexDump(bAryOrStrData, Optional hexOnly = 0, Optional ByVal startAt As Long = 1, Optional ByVal length As Long = -1) As String
    Dim s() As String, chars As String, tmp As String
    On Error Resume Next
    Dim ary() As Byte
    Dim offset As Long
    Const LANG_US = &H409
    Dim i As Long, tt, h, x

    offset = 0
    
    If TypeName(bAryOrStrData) = "Byte()" Then
        ary() = bAryOrStrData
    Else
        ary = StrConv(CStr(bAryOrStrData), vbFromUnicode, LANG_US)
    End If
    
    If startAt < 1 Then startAt = 1
    If length < 1 Then length = -1
    
    While startAt Mod 16 <> 0
        startAt = startAt - 1
    Wend
    
    startAt = startAt + 1
    
    chars = "   "
    For i = startAt To UBound(ary) + 1
        tt = Hex(ary(i - 1))
        If Len(tt) = 1 Then tt = "0" & tt
        tmp = tmp & tt & " "
        x = ary(i - 1)
        'chars = chars & IIf((x > 32 And x < 127) Or x > 191, Chr(x), ".") 'x > 191 causes \x0 problems on non us systems... asc(chr(x)) = 0
        chars = chars & IIf((x > 32 And x < 127), Chr(x), ".")
        If i > 1 And i Mod 16 = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            If hexOnly = 0 Then
                push s, h & "   " & tmp & chars
            Else
                push s, tmp
            End If
            offset = offset + 16
            tmp = Empty
            chars = "   "
        End If
        If length <> -1 Then
            length = length - 1
            If length = 0 Then Exit For
        End If
    Next
    
    'if read length was not mod 16=0 then
    'we have part of line to account for
    If tmp <> Empty Then
        If hexOnly = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            h = h & "   " & tmp
            While Len(h) <= 56: h = h & " ": Wend
            push s, h & chars
        Else
            push s, tmp
        End If
    End If
    
    HexDump = Join(s, vbCrLf)
    
    If hexOnly <> 0 Then
        HexDump = Replace(HexDump, " ", "")
        HexDump = Replace(HexDump, vbCrLf, "")
    End If
    
End Function



Function FileExists(path As String) As Boolean
  On Error GoTo hell
    
  If Len(path) = 0 Then Exit Function
  If Right(path, 1) = "\" Then Exit Function
  If Dir(path, vbHidden Or vbNormal Or vbReadOnly Or vbSystem) <> "" Then FileExists = True
  
  Exit Function
hell: FileExists = False
End Function

Sub WriteFile(path, it)
    Dim f
    f = FreeFile
    Open path For Output As #f
    Print #f, it
    Close f
End Sub

Function GetParentFolder(path) As String
    Dim tmp() As String, ub As Long
    On Error Resume Next
    tmp = Split(path, "\")
    ub = tmp(UBound(tmp))
    If Err.Number = 0 Then
        GetParentFolder = Replace(Join(tmp, "\"), "\" & ub, "")
    Else
        GetParentFolder = path
    End If
End Function

