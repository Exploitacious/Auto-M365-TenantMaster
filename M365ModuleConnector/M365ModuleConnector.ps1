# M365 Module Connector
Write-Host
Write-Host "================ M365 Module Connector ================"
Write-Host

# Function to connect to all services
function Connect-AllServices {
    param (
        [PSCredential]$Credential
    )

    Write-Host
    Write-Host "Please be patient as we import modules..."
    Write-Host

    foreach ($Module in $Modules) {
        try {
            Import-Module $Module.Name -Verbose
            Write-Log "Imported $($Module.Name) module" "INFO"
        }
        catch {
            Write-Log "Unable to import $($Module.Name). Details: $($_.Exception.Message)" "ERROR"
        }
        
    }

    Write-Host
    Write-Host "Connecting Modules..."
    Write-Host
    Write-Host "You will be prompted for authentication for each service. Please complete the MFA process when required." -ForegroundColor Green
    Write-Host

    $connectionSummary = @()

    $connectionModules = @(
        @{Name = "Exchange Online"; Cmd = { Connect-ExchangeOnline -UserPrincipalName $Credential.UserName } },
        @{Name = "Security & Compliance Center"; Cmd = { Connect-IPPSSession -UserPrincipalName $Credential.UserName -UseRPSSession:$false } },
        @{Name = "Microsoft Graph"; Cmd = { 
                $Scopes = @(
                    "User.Read.All",
                    "Group.ReadWrite.All",
                    "Policy.ReadWrite.ConditionalAccess",
                    "DeviceManagementServiceConfig.ReadWrite.All",
                    "SecurityEvents.ReadWrite.All" 
                )
                Connect-MgGraph -Scopes $Scopes -UseDeviceAuthentication -Verbose
            }
        },
        @{Name = "Microsoft Online"; Cmd = { Connect-MsolService } },
        @{Name = "Azure AD Preview"; Cmd = { Connect-AzureAD } },
        #@{Name = "Microsoft Teams"; Cmd = { Connect-MicrosoftTeams -Credential $Credential.UserName } },
        <#@{Name = "SharePoint Online"; Cmd = { 
                $orgName = $Credential.UserName.Split('@')[1].Split('.')[0]
                Connect-SPOService -Url "https://$orgName-admin.sharepoint.com" -Credential $Credential.UserName 
            }
        },#>
        @{Name = "Azure Information Protection"; Cmd = { Connect-AipService } }
    )

    foreach ($module in $connectionModules) {
        try {
            & $module.Cmd
            Write-Host "$($module.Name) Connected!" -ForegroundColor Green
            $connectionSummary += [PSCustomObject]@{
                Module = $module.Name
                Status = "Connected"
            }
        }
        catch {
            Write-Host "Failed to connect to $($module.Name). Error: $_" -ForegroundColor Red
            $connectionSummary += [PSCustomObject]@{
                Module = $module.Name
                Status = "Connection Failed"
            }
        }
        Write-Host
    }

    return $connectionSummary
}

##############################################################################
### Main script logic
##############################################################################

Write-Log "Starting M365 Module Connector" "INFO"
Write-Host
Write-Host

# Module connection
$Answer = Read-Host "Would you like to connect to all required services? (Y/N)"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {

    # Enter Admin Creds
    try {
        $Credential = Get-Credential -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "Credentials not entered. Exiting..."
        exit
    }
    Write-Host

    # Begin Connecting
    $connectionSummary = Connect-AllServices $Credential

    Write-Host
    Write-Host

    # Display connection summary
    Write-Host "Service Connection Summary:"
    $connectionSummary | Format-Table -AutoSize
}
