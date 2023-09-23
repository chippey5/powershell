# Set-ProgramRule

A simple powershell script to recursively block or unblock executables in the firewall from a provided folder.

## Prerequisites
* Administrative privileges.
* PowerShell 5 or newer. 

## Installation

You can see how to install PowerShell modules on the official documentation [here](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-5.1).

To easily install it, run the following commands in an elevated terminal to have it added to your system's PowerShell module directory.

```
#Create target module directory
New-Item -ItemType Directory "C:\Program Files\WindowsPowerShell\Modules\Set-ProgramRule" -Force

#Download files
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/chippey5/powershell/master/Set-ProgramRule/Set-ProgramRule.psm1" -OutFile "C:\Program Files\WindowsPowerShell\Modules\Set-ProgramRule\Set-ProgramRule.psm1" 
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/chippey5/powershell/master/Set-ProgramRule/Set-ProgramRule.psd1" -OutFile "C:\Program Files\WindowsPowerShell\Modules\Set-ProgramRule\Set-ProgramRule.psd1" 
```

## Examples

##### Block executables under `C:\Program Files (x86)\SomeProgram`

```
Set-ProgramRule -Block "C:\Program Files (x86)\SomeProgram"
```

##### Unblock executables under `C:\Program Files (x86)\SomeProgram`
```
Set-ProgramRule -Unblock "C:\Program Files (x86)\SomeProgram"
```

##### Purging orphaned rules created by Set-ProgramRule
```
Set-ProgramRule -Purge
```

##### Finding the rules blocked by the script

* Open `WF.msc` / *Windows Defender Firewall with advanced security*
* Open either inbound or outbound rules
* From the right hand side, select *Filter by Group*, select *Filter by PS-SetProgramRule*
