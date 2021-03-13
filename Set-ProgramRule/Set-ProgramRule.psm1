function Set-ProgramRule{
    Param(
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="unblock")]
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="block")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true,ParameterSetName="block")]
        [switch]$Block,

        [Parameter(Mandatory=$true,ParameterSetName="unblock")]
        [switch]$Unblock,

        [Parameter(Mandatory=$true,ParameterSetName="purge")]
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
        The path to file or executables in folder to block/unblock. Passing a string without passing -Path will still default to -Path.

    .PARAMETER -Purge
        Purges orphaned/defunct rules - removes firewall rules whose paths are not valid anymore that were created by Set-ProgramRule.

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
        Removes all orphaned firewall rules whose paths don't exist anymore that were created by Set-ProgramRule.
    #>

    function isPathValid {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$path
        )
        if(Test-Path -LiteralPath $path -ErrorAction SilentlyContinue){
            return $true
        }
        else{
            Write-Error -Message "The provided path is not valid." -Category InvalidData -CategoryReason "Invalid path" -CategoryActivity "The provided path is not valid." -RecommendedAction "Review the provided path."
            return $false
        }
    }

    function Get-Executables {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$path
        )
        if(isPathValid $path){
            $executables = @()
            #If given path is a folder
            if((Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).PSIsContainer -eq $true){
                $executables = Get-ChildItem -LiteralPath $path -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | Foreach-Object {$_.FullName}
            }
            #If given path is a file
            else{
                if($path.EndsWith(".exe")){
                    $executables += $path
                }
            }
        }
        return $executables,$error
    }

    function blockPrograms {
        [cmdletbinding()]
        param ([array]$executables)
        if($executables.Count -ge 1){
            Write-Host "" #Formatting
            foreach($exe in $executables){
                $shortName = $exe | Split-Path -Leaf
                $rulesPrecheck = Get-NetFirewallApplicationFilter -Program $exe -ErrorAction Ignore | Get-NetFirewallRule -ErrorAction Ignore #Check existing rules for the current .exe path
                
                #Inbound rule
                if($null -eq ($rulesPrecheck | Where-Object {$_.Direction -eq "Inbound"})){
                    
                    New-NetFirewallRule -DisplayName $shortName -Direction Inbound -Enabled "True" -Group "PS-SetProgramRule" -Action Block -Profile "Any" -Program $exe -ErrorAction SilentlyContinue -ErrorVariable NewFirewallRuleVar | Out-Null
                    if($NewFirewallRuleVar.Count -eq 0){
                        Write-Host "Blocked inbound: $shortName"
                    }
                    else{
                        Write-Host "Failed to inbound for $shortName\: $($NewFirewallRuleVar.Exception)"
                    }
                }
                else{
                    $existingRuleName = $rulesPrecheck | Where-Object {$_.Direction -eq "Inbound"} | Foreach-Object {$_.DisplayName}
                    Write-Host "Inbound block rule already exists for $shortName. Rule name: ""$existingRuleName""" 
                }

                #Outbound rule
                if($null -eq ($rulesPrecheck | Where-Object {$_.Direction -eq "Outbound"})){
                    
                    New-NetFirewallRule -DisplayName $shortName -Direction Outbound -Enabled "True" -Group "PS-SetProgramRule" -Action Block -Profile "Any" -Program $exe -ErrorAction SilentlyContinue -ErrorVariable NewFirewallRuleVar | Out-Null
                    if($NewFirewallRuleVar.Count -eq 0){
                        Write-Host "Blocked outbound: $shortName"
                    }
                    else{
                        Write-Host "Failed to outbound for $shortName\: $($NewFirewallRuleVar.Exception)"
                    }
                }
                else{
                    $existingRuleName = $rulesPrecheck | Where-Object {$_.Direction -eq "Outbound"} | Foreach-Object {$_.DisplayName}
                    Write-Host "Outbound block rule already exists for $shortName. Rule name: ""$existingRuleName""`n"
                }
            }
        }
    }

    function unblockPrograms {
        [cmdletbinding()]
        param ($executables)
        
        foreach($exe in $executables){
            $rulesPrecheck = Get-NetFirewallApplicationFilter -Program $exe -ErrorAction Ignore | Get-NetFirewallRule -ErrorAction Ignore
            $shortName = $exe | Split-Path -Leaf
            if($rulesPrecheck.Count -ge 1){
                foreach($rule in $rulesPrecheck){
                    try{
                        $rule | Remove-NetFirewallRule
                        Write-Host "Removed $($rule.Direction) rule for: $shortname"
                    }
                    catch{Write-Host "Failed to remove $($rule.Direction) rule for: $shortname"}
                }
            }
            else{
                Write-Host "No rules exist for: $shortname"
            }
        }
    }

    function purgeOrphans {
        [cmdletbinding()]
        param()
        $orphanJob = Start-Job -ScriptBlock {@(Get-NetFirewallRule -Group "PS-SetProgramRule" | Get-NetFirewallApplicationFilter | Where-Object {!(Test-Path $_.Program)})} | Wait-Job
        $orphanApplicationFilter = $orphanJob | Receive-Job -AutoRemoveJob -Wait
        $orphanPaths = $orphanApplicationFilter.Program | Select-Object -Unique
        $orphanedRules = $orphanApplicationFilter | Get-NetFirewallRule

        if($orphanedRules.Count -ge 1){
            $orphanedRules | Remove-NetFirewallRule
            Write-Host "Removed $(($orphanedRules | Select-Object -Unique).Count) rules for the following path(s):`n$($orphanPaths -join "`n")"
        }
        else{
            Write-Host "No orphans were found."
        }
    }

    switch ($true){
        $Block {
            $executables = (Get-Executables $path)[0]
            if($executables.Count -ge 1){
                blockPrograms $executables
            }
        }
        $Unblock {
            $executables = (Get-Executables $path)[0]
            if($executables.Count -ge 1){
                unblockPrograms $executables
            }
        }
        $Purge {
            purgeOrphans
        }
    }
}