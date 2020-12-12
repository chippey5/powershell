# Set-ProgramRule

A simple powershell script to recursively block or unblock executables in the firewall from a provided folder.

## Prerequisites
* The script needs to be run from an elevated command.
* PowerShell 5 or newer is required. 

## Installation

You can see how to install PowerShell modules on the official documentation [here](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-5.1).

To easily install it, run the following command to have it added to your user's PowerShell module directory.

```
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/chippey5/powershell/master/Set-ProgramRule/Set-ProgramRule.psm1" -OutFile (New-Item -Path "$($env:USERPROFILE)\Documents\WindowsPowerShell\Modules\Set-ProgramRule\Set-ProgramRule.psm1" -Force)
```

## Examples

##### Block executables under `C:\Program Files (x86)\SomeProgram`

```
Set-ProgramRule -block "C:\Program Files (x86)\SomeProgram"
```

##### Unblock executables under `C:\Program Files (x86)\SomeProgram`
```
Set-ProgramRule -unblock "C:\Program Files (x86)\SomeProgram"
```

##### Finding the rules blocked by the script

* Open `WF.msc` / *Windows Defender Firewall with advanced security*
* Open either inbound or outbound rules
* From the right hand side, select *Filter by Group*, select *Filter by PS-SetProgramRule*
