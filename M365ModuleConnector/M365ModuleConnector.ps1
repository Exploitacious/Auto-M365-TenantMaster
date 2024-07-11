# M365 Module Connector
# Verify/Elevate Admin Session.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 
}

# Set the MaximumFunctionCount
$MaximumFunctionCount = 32768

# Directly set the MaximumFunctionCount using $ExecutionContext
try {
    $executionContext.SessionState.PSVariable.Set('MaximumFunctionCount', $MaximumFunctionCount)
}
catch {
    Write-Error "Failed to set MaximumFunctionCount: $_"
    exit
}

Write-Host
Write-Host "================ M365 Module Connector ================" -ForegroundColor DarkCyan
Write-Host

$logFile = Join-Path $PSScriptRoot "ModuleConnector_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
                    Write-Host "Imported Graph Module: $SubModule"
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
                Import-Module $Module -ErrorAction Stop
                Write-Host "Imported Module: $Module"
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

    # Module Connections
    $connectionSummary = @()
    $connectionModules = @(
    
        # Exchange Online Management     
        @{Name = "Exchange Online"; Cmd = { Connect-ExchangeOnline -UserPrincipalName $Global:Credential.UserName } },

        # Security Compliance Center
        @{Name = "Security and Compliance"; Cmd = { Connect-IPPSSession -UserPrincipalName $Global:Credential.UserName -UseRPSSession:$false } },

        # NEW Graph API
        @{Name = "MG Graph"; Cmd = { 
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
        },

        # Microsoft Online MSOL
        @{Name = "MSOnline"; Cmd = { Connect-MsolService } },

        # Azure AD
        @{Name = "Azure AD"; Cmd = { Connect-AzureAD } },

        # Information Protection
        @{Name = "AIPService"; Cmd = { Connect-AipService } },

        # Teams Admin
        @{Name = "Teams"; Cmd = { Connect-MicrosoftTeams } },

        # SharePoint Admin
        @{Name = "SharePoint"; Cmd = { 
                Connect-SPOService -Url "https://$Global:TenantDomain-admin.sharepoint.com"
            }
        }
    )

    foreach ($module in $connectionModules) {
        # Check if the module is already connected
        $isConnected = $Global:existingConnections | Select-String -Pattern $module.Name
    
        if ($isConnected) {
            Write-Host "$($module.Name) Connected" -ForegroundColor DarkGreen
            $connectionSummary += [PSCustomObject]@{
                Module = $module.Name
                Status = "Connected"
            }
        }
        else {
            try {
                & $module.Cmd # Connection Magic
                Write-Log "$($module.Name) Connected" "INFO"
                Write-Host "$($module.Name) Connected!" -ForegroundColor DarkGreen
                Start-Sleep 3 # Wait needed for successful connections...
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

# Display connection summary
Write-Host
Write-Host -ForegroundColor Green "Module Connections Complete. Service Connection Summary:"
$connectionSummary | Format-Table -AutoSize

# More Info
Write-Host
Write-Host "IMPORTANT" -ForegroundColor Cyan
Write-Host "Please double check and make there are absolutely NO errors." -ForegroundColor Cyan
Write-Host "You may re-run this as many times as needed until all modules are successfully connected" -ForegroundColor Cyan
Write-Host
Write-Host "=== If you continue seeing errors for a problematic module: " -ForegroundColor Yellow
Write-Host " - Open a new PowerShell Window as Admin and attempt to connect the module manually" -ForegroundColor Yellow
Write-Host " - You can use the 'R' menu option to Refresh Connections to verify if you have successfully connected all modules" -ForegroundColor Yellow
Write-Host
Write-Log "M365 Module Connector Log $logFile" "INFO"