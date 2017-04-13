VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form1 
   Caption         =   "VB6 Bindings for Capstone Disassembly Engine - Contributed by FireEye FLARE  Team"
   ClientHeight    =   7290
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10275
   LinkTopic       =   "Form1"
   ScaleHeight     =   7290
   ScaleWidth      =   10275
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton Command2 
      Caption         =   "Save"
      Height          =   375
      Left            =   8760
      TabIndex        =   8
      Top             =   120
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   " Arm 64"
      Height          =   375
      Index           =   4
      Left            =   6840
      TabIndex        =   7
      Top             =   120
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Arm"
      Height          =   375
      Index           =   3
      Left            =   5160
      TabIndex        =   6
      Top             =   120
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   "x86 64bit"
      Height          =   375
      Index           =   2
      Left            =   3480
      TabIndex        =   5
      Top             =   120
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   "x86 16bit"
      Height          =   375
      Index           =   0
      Left            =   120
      TabIndex        =   4
      Top             =   120
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   "x86 32bit"
      Height          =   375
      Index           =   1
      Left            =   1800
      TabIndex        =   3
      Top             =   120
      Width           =   1455
   End
   Begin MSComctlLib.ListView lv 
      Height          =   2415
      Left            =   120
      TabIndex        =   2
      Top             =   1440
      Width           =   10095
      _ExtentX        =   17806
      _ExtentY        =   4260
      View            =   3
      LabelEdit       =   1
      LabelWrap       =   -1  'True
      HideSelection   =   0   'False
      FullRowSelect   =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   -2147483643
      BorderStyle     =   1
      Appearance      =   1
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.ListBox List1 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   840
      Left            =   120
      TabIndex        =   1
      Top             =   600
      Width           =   10095
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   3375
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   0
      Text            =   "Form1.frx":0000
      Top             =   3840
      Width           =   10095
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

'Capstone Disassembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache
'Copyright: FireEye 2017

Dim cap As CDisassembler
Dim lastSample As Long

Private Sub Command1_Click(index As Integer)
    
    Dim code() As Byte, arch As cs_arch, mode As cs_mode
    lastSample = index
    
    Const x86_code32 As String = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    Const X86_CODE16 As String = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    Const X86_CODE64 As String = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
    Const ARM_CODE As String = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"
    Const ARM64_CODE As String = "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"

    Select Case index
        Case 0:
                arch = CS_ARCH_X86
                mode = CS_MODE_16
                code = toBytes(X86_CODE16)
        Case 1:
                arch = CS_ARCH_X86
                mode = CS_MODE_32
                code = toBytes(x86_code32)
        Case 2:
                arch = CS_ARCH_X86
                mode = CS_MODE_64
                code = toBytes(X86_CODE64)
                
        Case 3:
                arch = CS_ARCH_ARM
                mode = CS_MODE_ARM
                code = toBytes(ARM_CODE)
                
        Case 4:
                arch = CS_ARCH_ARM64
                mode = CS_MODE_ARM
                code = toBytes(ARM64_CODE)
    End Select
    
    
    test code, arch, mode
    
End Sub

Private Sub test(code() As Byte, arch As cs_arch, mode As cs_mode)
    
    
    Dim ret As Collection
    Dim ci As CInstruction
    Dim li As ListItem
    
    clearForm
    If Not cap Is Nothing Then Set cap = Nothing
    
    Set cap = New CDisassembler
    
    If Not cap.init(arch, mode, True) Then
        List1.AddItem "Failed to init engine: " & cap.errMsg
        Exit Sub
    End If
      
    List1.AddItem "Capstone loaded @ 0x" & Hex(cap.hLib)
    List1.AddItem "hEngine: 0x" & Hex(cap.hCapstone)
    List1.AddItem "Version: " & cap.version
    
    If cap.vMajor < 3 Then
        List1.AddItem "Sample requires Capstone v3+"
        Exit Sub
    End If
    
    Set ret = cap.disasm(&H1000, code)

    For Each ci In ret
        Set li = lv.ListItems.Add(, , ci.text)
        Set li.Tag = ci
    Next
    
End Sub

Private Sub Command2_Click()

    Dim fName() As String
    Dim fPath As String
    Dim t() As String
    Dim li As ListItem
    Dim ci As CInstruction
    
    On Error Resume Next
    
    If lastSample = -1 Then
        MsgBox "Run a test first..."
        Exit Sub
    End If
    
    fName = Split("16b,32b,64b,Arm,Arm64", ",")
    
    fPath = App.path & "\vb" & fName(lastSample) & "Test.txt"
    If FileExists(fPath) Then Kill fPath
    
    For Each li In lv.ListItems
        push t, li.text
        Set ci = li.Tag
        push t, ci.toString()
        push t, String(60, "-")
    Next
    
    WriteFile fPath, Join(t, vbCrLf)
    
    MsgBox FileLen(fPath) & " bytes saved to: " & vbCrLf & vbCrLf & fPath
    
End Sub

Private Sub lv_ItemClick(ByVal Item As MSComctlLib.ListItem)
    Dim ci As CInstruction
    Set ci = Item.Tag
    Text1 = ci.toString()
End Sub

Function clearForm()
    List1.Clear
    lv.ListItems.Clear
    Text1 = Empty
End Function

Private Sub Form_Load()
    lv.ColumnHeaders(1).Width = lv.Width
    clearForm
    lastSample = -1
End Sub
