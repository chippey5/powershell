$path = Read-Host Enter the program path or root folder

if(Test-Path -LiteralPath $path -ErrorAction SilentlyContinue){ #Check path validity
    if((Get-Item $path).PSIsContainer -eq $false -and $path.EndsWith(".exe")){ #If the given path is an executable
        $executables = @($path)
    }
    elseif((Get-Item $path).PSIsContainer -eq $true){ #If the given path is a folder
        $executables = Get-ChildItem $path -Recurse -Filter "*.exe" | Foreach-Object {$_.FullName}
    }
    else{ #If the given path is reachable, but invalid
        Write-Host "The specified path is not an "".exe"" or a folder. Try again.`n"
        exit
    }
    if($executables.Count -ge 1){
        Write-Host "" #Formatting
        foreach($exe in $executables){
            $shortName = $exe | Split-Path -Leaf
            $rulesPrecheck = Get-NetFirewallApplicationFilter -Program $exe -ErrorAction Ignore | Get-NetFirewallRule #Check existing rules for the current .exe path
            
            #Inbound rule
            if($null -eq ($rulesPrecheck | Where-Object {$_.Direction -eq "Inbound"})){
                New-NetFirewallRule -DisplayName $shortName -Direction Inbound -Enabled "True" -Action Block -Profile "Any" -Program $exe | Out-Null
                Write-Host "Blocked inbound: $shortName"
            }
            else{
                $existingRuleName = $rulesPrecheck | Where-Object {$_.Direction -eq "Inbound"} | Foreach-Object {$_.DisplayName}
                Write-Host "Inbound block rule already exists for $shortName. Rule name: ""$existingRuleName""" 
            }

            #Outbound rule
            if($null -eq ($rulesPrecheck | Where-Object {$_.Direction -eq "Outbound"})){
                New-NetFirewallRule -DisplayName $shortName -Direction Outbound -Enabled "True" -Action Block -Profile "Any" -Program $exe | Out-Null
                Write-Host "Blocked outbound: $shortName`n" 
            }
            else{
                $existingRuleName = $rulesPrecheck | Where-Object {$_.Direction -eq "Outbound"} | Foreach-Object {$_.DisplayName}
                Write-Host "Outbound block rule already exists for $shortName. Rule name: ""$existingRuleName""`n"
            }
        }
        #Formatting
        Write-Host "" 
    }
    else{
        Write-Host "No "".exe"" files found in the given path. Try again.`n"
        exit
    }
}
else{
    Write-Host "Invalid path. Try again."
}
