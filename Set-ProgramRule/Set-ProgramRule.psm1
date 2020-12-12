function Set-ProgramRule{
    #Requires -RunAsAdministrator
    <#
    .Synopsis
        Block or unblock single or multiple executables recursively in a provided folder.
    .PARAMETER -block
        Sets the action to block in firewall.
    .PARAMETER -unblock
        Sets the action to unblock in firewall.
    .PARAMETER -path
        The path to file or executables in folder to block/unblock.
    .Example
        Set-ProgramRule -block "C:\Program Files (x86)\SomeProgram"
        Adds blocking firewall rules for all executables that are recursively found under "C:\Program Files (x86)\SomeProgram".
    .Example
        Set-ProgramRule -block "C:\Program Files (x86)\SomeProgram\program.exe"
        Blocks inbound and outbound internet connections for "C:\Program Files (x86)\SomeProgram\program.exe".
    .Example
        Set-ProgramRule -unblock "C:\Program Files (x86)\SomeProgram"
        Removes all firewall rules found for all executables that are recursively found under "C:\Program Files (x86)\SomeProgram".
    .Example
        Set-ProgramRule -unblock "C:\Program Files (x86)\SomeProgram\program.exe"
        Removes all firewall rules found regarding "C:\Program Files (x86)\SomeProgram\program.exe".
        
    #>
    $argList = ($MyInvocation.Line -replace ('^.*' + [regex]::Escape($MyInvocation.InvocationName)) -split '[;|]')[0].Trim()

    $type = $argList[0]
    $path = $argList[1]

    function Get-Executables {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$path
        )
        if(Test-Path -LiteralPath $path -ErrorAction SilentlyContinue){
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

    function blockPrograms{
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
            #Formatting
            #Write-Host "" 
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
    
    #Argument handling
    if($args.Count -eq 2){
        $type = $args[0]
        $path = $args[1]
        if($type -like "-block"){
            #$block = $true
            $executables = (Get-Executables $path)[0]
            if($executables.Count -ge 1){
                blockPrograms $executables
            }
        }
        elseif($type -like "-unblock"){
            #$block = $false
            $executables = (Get-Executables $path)[0]
            if($executables.Count -ge 1){
                unblockPrograms $executables
            }
        }
        else{
            Write-Error -Message "Invalid argument ""$type""." -Category InvalidArgument
            return
        }
    }
    else{
        Write-Error -Message "Invalid amount of arguments passed. You need to pass 2 arguments." -Category InvalidOperation
    }
}
