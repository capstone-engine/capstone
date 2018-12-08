This documentation explains how to install & use the PowerShell binding for Capstone.


Install
------

Compile the relevant version (x86/x64) of `capstone.dll` and place it in
`./Capstone/Lib/Capstone/`.

Alternatively, pre-compiled DLL’s can be obtained from the Capstone homepage
at http://capstone-engine.org/download


Usage
-----

To use the PowerShell binding, the entire Capstone folder should be added to
one of the PowerShell module directories:

    # Global PSModulePath path
    %Windir%\System32\WindowsPowerShell\v1.0\Modules

    # User PSModulePath path
    %UserProfile%\Documents\WindowsPowerShell\Modules

Once this is done the module can be initialized by typing “Import-Module Capstone”
in a new PowerShell terminal. Further information on the usage of the binding
can be obtained with the following command:

    Get-Help Get-CapstoneDisassembly -Full