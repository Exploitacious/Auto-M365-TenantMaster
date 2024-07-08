# M365 Module Connector
Write-Host
Write-Host "================ M365 Module Connector ================"
Write-Host

$logFile = Join-Path $PSScriptRoot "ModuleConnector_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Max Function Count
$maximumfunctioncount = 32768

# Function to write log messages
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage
}

# Function to Import All Services
function Import-AllServices {

    Write-Host
    Write-Host "Please be patient as we import modules..."
    Write-Host

    foreach ($Module in $Global:Modules) {
        #GraphModules
        if ($Module -eq "Microsoft.Graph") {
            # Import specific SubModules for Microsoft.Graph
            $SubModules = @(
                "Microsoft.Graph.Identity.SignIns"
                "Microsoft.Graph.Intune"
                "Microsoft.Graph.DeviceManagement"
                "Microsoft.Graph.Compliance"
                "Microsoft.Graph.Users"
                "Microsoft.Graph.Groups"
                "Microsoft.Graph.Authentication"
                "Microsoft.Graph.Security"
            )

            try {
                foreach ($SubModule in $SubModules) {
                    Import-Module $SubModule
                    Write-Log "Imported Graph Module: $SubModule" "INFO"
                }                
            }
            catch {
                Write-Log "Unable to import Graph Module $SubModule. Details: $_" "ERROR"
                Write-Host
                Write-Host "You may need to re-run the Module installation script" -ForegroundColor Yellow
                Exit
            }

        }
        else {
            #Normal Modules
            try {
                Import-Module $Module
                Write-Log "Imported Module: $Module" "INFO"
            }
            catch {
                Write-Log "Unable to import $Module. Details: $_" "ERROR"
                Write-Host
                Write-Host "You may need to re-run the Module installation script" -ForegroundColor Yellow
                Exit
            }
        }
    }
}

# Funciton to Connect All Services
function Connect-AllServices {
    param (
        [PSCredential]$Global:Credential
    )

    Write-Host
    Write-Host "Connecting Modules..."
    Write-Host
    Write-Host "You will be prompted for authentication for each service. Please complete the MFA process when required." -ForegroundColor Green
    Write-Host

    $connectionSummary = @()
    $connectionModules = @(
        # @{Name = "Exchange Online"; Cmd = { Connect-ExchangeOnline -UserPrincipalName $Global:Credential.UserName } },
        # @{Name = "Security & Compliance Center"; Cmd = { Connect-IPPSSession -UserPrincipalName $Global:Credential.UserName -UseRPSSession:$false } },
        <#@{Name = "Microsoft Graph"; Cmd = { 
                $Scopes = @(
                    "User.ReadWrite.All"
                    "Group.ReadWrite.All"
                    "Directory.ReadWrite.All"
                    "Organization.ReadWrite.All"
                    "Device.ReadWrite.All"
                    "DeviceManagementConfiguration.ReadWrite.All"
                    #"Policy.ReadWrite.All"
                    "SecurityEvents.ReadWrite.All"
                    "MailboxSettings.ReadWrite"
                    "Reports.Read.All"
                    "AuditLog.Read.All"
                    "RoleManagement.ReadWrite.Directory"
                    "Application.ReadWrite.All"
                    "TeamSettings.ReadWrite.All"
                    #"Channel.ReadWrite.All"
                    "Sites.FullControl.All"
                    "IdentityRiskyUser.ReadWrite.All"
                    "ThreatAssessment.ReadWrite.All"
                    #"ComplianceManager.ReadWrite.All"
                    "UserAuthenticationMethod.ReadWrite.All"
                )
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
            }
        }#>
        # @{Name = "Microsoft Online"; Cmd = { Connect-MsolService } },
        # @{Name = "Azure AD Preview"; Cmd = { Connect-AzureAD } },
        # @{Name = "Azure Information Protection"; Cmd = { Connect-AipService } },
        # @{Name = "Microsoft Teams"; Cmd = { Connect-MicrosoftTeams } },
        @{Name = "SharePoint Online"; Cmd = { 
                Connect-SPOService -Url "https://$Global:TenantDomain-admin.sharepoint.com" -UseWebLogin
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
                & $module.Cmd # Connection Magic
                Write-Log "$($module.Name) Connected" "INFO"
                Write-Host "$($module.Name) Connected!" -ForegroundColor Green
                $connectionSummary += [PSCustomObject]@{
                    Module = $module.Name
                    Status = "Connected"
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
}

##############################################################################
### Main script logic
##############################################################################

Write-Log "Starting M365 Module Connector" "INFO"
Write-Host
Write-Host
Write-Host "Please enter the Global Admin Account into the PowerShell Credential Prompt" -ForegroundColor Green
Write-Host

# Check/Enter Admin Creds
If ($null -eq $Global:Credential.UserName) {
    try {
        $Global:Credential = Get-Credential -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "Credentials not entered. Exiting..."
        exit
    }
    Write-Host
}
else {
    Write-Log "$Global:TenantDomain Credentials $($Global:Credential.UserName) being used"
}

# Begin Checking and Connecting Services
Import-AllServices
Start-Sleep -Seconds 2
$connectionSummary = Connect-AllServices $Global:Credential

Write-Host
Write-Host

# Display connection summary
Write-Host "Service Connection Summary:"
$connectionSummary | Format-Table -AutoSize