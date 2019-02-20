VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CX86OpMem"
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


Public segment As Long     ' segment register (or X86_REG_INVALID if irrelevant) UNSIGNED
Public base As Long        ' base register (or X86_REG_INVALID if irrelevant) UNSIGNED
Public index As Long       ' index register (or X86_REG_INVALID if irrelevant) UNSIGNED
Public scale_ As Long      ' scale for index register
Public disp As Currency    ' displacement value

