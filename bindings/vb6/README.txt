
Capstone Disassembly Engine bindings for VB6
Contributed by FireEye FLARE Team
Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
License: Apache  
Copyright: FireEye 2017

This is a sample for using the capstone disassembly engine with VB6.

All of the capstone API are implemented, so this lib supports basic 
disassembly of all of the processor architectures that capstone implements.

In the vb code, full instruction details are currently only supported for
the x86 processor family.

This sample was built against Capstone 3.0 rc4. Note that if the capstone
structures change in the future this code will have to be adjusted to match.

The vbCapstone.dll is written in C. Project files are provided for VS2008.
It is a small shim to give VB6 access to a stdcall API to access capstone.
You could also modify capstone itself so its exports were stdcall.

The C project has an additional include directory set to ./../../include/
for <capstone.h>. This is for the /capstone/bindings/vb6/ directory structure






