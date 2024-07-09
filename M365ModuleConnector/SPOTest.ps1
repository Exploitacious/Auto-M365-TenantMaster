

try {
    Connect-PnPOnline -Url "https://$TenantDomain-admin.sharepoint.com" -Credentials $Credential
    Write-Output "Successfully connected to SharePoint Online using PnP PowerShell."
    return $true
}
catch {
    Write-Output "Failed to connect to SharePoint Online using PnP PowerShell. Error: $_"
    return $false
}




$connectionModules = @(
    @{Name = "SharePoint Online"; Cmd = {
            Connect-SharePointOnlinePnP -TenantDomain $Global:TenantDomain -Credential $Global:Credential
        }
    }
)

foreach ($module in $connectionModules) {
    # Gotta fix connection Checking
    #$isConnected = Test-ServiceConnection -ServiceName $module.Name
    $isConnected = $Global:existingConnections -contains $module.Name
    if ($isConnected) {
        Write-Host "$($module.Name) Connected" -ForegroundColor Green
        $connectionSummary += [PSCustomObject]@{
            Module = $module.Name
            Status = "Connected"
        }
    }
    else {
        try {
            $connected = & $module.Cmd # Connection Magic
            if ($connected) {
                Write-Log "$($module.Name) Connected" "INFO"
                Write-Host "$($module.Name) Connected!" -ForegroundColor Green
                $connectionSummary += [PSCustomObject]@{
                    Module = $module.Name
                    Status = "Connected"
                }
            }
            else {
                throw "Connection failed"
            }
        }
        catch {
            Write-Host "Failed to connect to $($module.Name). Error: $_" -ForegroundColor Red
            Write-Log "Failed to connect to $($module.Name). Error: $_"
            $connectionSummary += [PSCustomObject]@{
                Module = $module.Name
                Status = "FAILED"
            }
        }
    }
    Write-Host
}
return $connectionSummary
