function Set-ProgramRule {
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "unblock")]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "block")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if (-Not ($_ | Test-Path) ) {
                    throw "File or folder does not exist"
                }
                return $true 
            })]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = "block")]
        [switch]$Block,

        [Parameter(Mandatory = $true, ParameterSetName = "unblock")]
        [switch]$Unblock,

        [Parameter(Mandatory = $true, ParameterSetName = "purge")]
        [switch]$Purge
    )
    #Requires -RunAsAdministrator
    <#
    .Synopsis
        Block or unblock single or multiple executables recursively in a provided folder.

    .PARAMETER -Block
        Sets the action to block in firewall.

    .PARAMETER -Unblock
        Sets the action to unblock in firewall.

    .PARAMETER -Path
        The Path to file or executables in folder to block/unblock. Passing a string without passing -Path will still default to -Path.

    .PARAMETER -Purge
        Purges Orphaned/defunct rules - removes firewall rules whose Paths are not valid anymore that were created by Set-ProgramRule.

    .Example
        Set-ProgramRule -Block "C:\Program Files (x86)\SomeProgram"
        Adds blocking firewall rules for all executables that are recursively found under "C:\Program Files (x86)\SomeProgram".

    .Example
        Set-ProgramRule -Block "C:\Program Files (x86)\SomeProgram\program.exe"
        Blocks inbound and outbound internet connections for "C:\Program Files (x86)\SomeProgram\program.exe".

    .Example
        Set-ProgramRule -Unblock "C:\Program Files (x86)\SomeProgram"
        Removes all firewall rules found for all executables that are recursively found under "C:\Program Files (x86)\SomeProgram".

    .Example
        Set-ProgramRule -Unblock "C:\Program Files (x86)\SomeProgram\program.exe"
        Removes all firewall rules found regarding "C:\Program Files (x86)\SomeProgram\program.exe".

    .Example
        Set-ProgramRule -Purge
        Removes all Orphaned firewall rules whose Paths don't exist anymore that were created by Set-ProgramRule.
    #>

    function Get-Executables {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory = $true)]
            [System.IO.FileInfo]$Path
        )
        #If given Path is a folder
        if ((Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).PSIsContainer -eq $true) {
            [array]$executables = Get-ChildItem -LiteralPath $Path -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue
        }
        #If given Path is a file
        else {
            if ($Path.Extension -eq ".exe") {
                [array]$executables = $Path
            }
        }
        return $executables, $error
    }

    function blockPrograms {
        [cmdletbinding()]
        param ([array]$executables)
        if ($executables.Count -ge 1) {
            Write-Host "" #Formatting
            foreach ($exe in $executables) {
                $rulesPrecheck = Get-NetFirewallApplicationFilter -Program $exe.FullName -ErrorAction Ignore | Get-NetFirewallRule -ErrorAction Ignore #Check existing rules for the current .exe Path
                
                #Inbound rule
                if (-not ($rulesPrecheck | Where-Object { $_.Direction -eq "Inbound" })) {
                    try {
                        New-NetFirewallRule -DisplayName $exe.Name -Direction Inbound -Enabled "True" -Group "PS-SetProgramRule" -Action Block -Profile "Any" -Program $exe.FullName -ErrorAction SilentlyContinue -ErrorVariable NewFirewallRuleVar | Out-Null
                        Write-Host "Blocked inbound: $($exe.Name)"
                    }
                    catch {
                        Write-Host "Failed to create inbound rule for $($exe.Name)."
                    }
                }
                else {
                    $existingRuleName = ($rulesPrecheck | Where-Object { $_.Direction -eq "Inbound" }).DisplayName | Select-Object -First 1
                    Write-Host "Inbound block rule already exists for $($exe.Name). Rule name: `"$($existingRuleName)`"" 
                }

                #Outbound rule
                if ($null -eq ($rulesPrecheck | Where-Object { $_.Direction -eq "Outbound" })) {
                    try {
                        New-NetFirewallRule -DisplayName $exe.Name -Direction Outbound -Enabled "True" -Group "PS-SetProgramRule" -Action Block -Profile "Any" -Program $exe.FullName -ErrorAction SilentlyContinue -ErrorVariable NewFirewallRuleVar | Out-Null
                        Write-Host "Blocked outbound: $($exe.Name)"
                    }
                    catch {
                        Write-Host "Failed to outbound rule for $($exe.Name)."
                    }
                }
                else {
                    $existingRuleName = ($rulesPrecheck | Where-Object { $_.Direction -eq "Outbound" }).DisplayName | Select-Object -First 1
                    Write-Host "Outbound block rule already exists for $($exe.Name). Rule name: `"$($existingRuleName)`"" 
                }
            }
        }
    }

    function unblockPrograms {
        [cmdletbinding()]
        param ($executables)
        
        foreach ($exe in $executables) {
            $rulesPrecheck = Get-NetFirewallApplicationFilter -Program $exe.Name -ErrorAction Ignore | Get-NetFirewallRule -ErrorAction Ignore
            if ($rulesPrecheck.Count -ge 1) {
                foreach ($rule in $rulesPrecheck) {
                    try {
                        $rule | Remove-NetFirewallRule
                        Write-Host "Removed $($rule.Direction) rule for: $($exe.Name)"
                    }
                    catch { Write-Host "Failed to remove $($rule.Direction) rule for: $($exe.Name)" }
                }
            }
            else {
                Write-Host "No rules exist for: $($exe.Name)"
            }
        }
    }

    function PurgeOrphans {
        [cmdletbinding()]
        param()

        $OrphanedFilters = @(Get-NetFirewallRule -Group "PS-SetProgramRule" | Get-NetFirewallApplicationFilter | Where-Object { !(Test-Path $_.Program) })
        
        $OrphanPaths = $OrphanedFilters | Select-Object -Unique -ExpandProperty Program
        $OrphanedRules = $OrphanedFilters | Get-NetFirewallRule

        if ($OrphanedRules.Count -ge 1) {
            $OrphanedRules | Remove-NetFirewallRule
            Write-Host "Removed $(($OrphanedRules).Count) rules for the following Path(s):`n$($OrphanPaths -join "`n")"
        }
        else {
            Write-Host "No Orphans were found."
        }
    }

    switch ($true) {
        $Block {
            $executables = (Get-Executables $Path)[0]
            if ($executables.Count -ge 1) {
                blockPrograms $executables
            }
        }
        $Unblock {
            $executables = (Get-Executables $Path)[0]
            if ($executables.Count -ge 1) {
                unblockPrograms $executables
            }
        }
        $Purge {
            PurgeOrphans
        }
    }
}