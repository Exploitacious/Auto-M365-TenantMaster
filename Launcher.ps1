### M365 Configuration Launcher

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

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "This script requires PowerShell 5.1 or later. Your version is $($PSVersionTable.PSVersion). Please upgrade PowerShell and try again." -ForegroundColor Red
    exit
}

# Import required modules
Import-Module Microsoft.PowerShell.Utility

# Initialize variables
$scriptPath = $PSScriptRoot
$logFile = Join-Path $PSScriptRoot "Launcher_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$configFile = Join-Path $PSScriptRoot "config.json"

# Modules Required
$Global:Modules = @(
    "ExchangeOnlineManagement"
    "AzureADPreview"
    "MSOnline"
    "MSGRAPH"
    "Microsoft.Graph"
    "AIPService"
    "MicrosoftTeams"
    "Microsoft.Online.SharePoint.PowerShell"
)

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
Write-Log "Starting up the M365 Configurator..." "INFO"

# Random String Generation for Passwords
function genRandString ([int]$length, [string]$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%()') {
    return -join ((1..$length) | ForEach-Object { Get-Random -InputObject $chars.ToCharArray() })
}

# Function to load and validate configuration
function Load-Configuration {
    if (Test-Path $configFile) {
        Write-Output "Loading configuration from $configFile"
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        if (-not $config.ScriptPaths) {
            throw "Configuration file does not contain ScriptPaths. Unable to proceed."
        }
    }
    # Creating new config file with default values
    else {
        Write-Log "Configuration file not found. Generating new one with DEFAULT values.." "WARNING"
        Write-Host

        # Gather some details 
        Write-Host "Enter a one-word name of your MSP, with NO spaces or symbols (Example: Umbrella or UmbrellaIT)" -ForegroundColor DarkYellow
        $Global:mspName = Read-Host 
        Write-Host

        # Alerts Address
        Write-Host "Enter the Alerting Mailbox Address for your MSP (Example: alerting@umbrellaitgroup.com)" -ForegroundColor DarkYellow
        $Global:mspAlertsAddress = Read-Host
        Write-Host

        # Alerts Address
        Write-Host "Enter the URL for the logo of the company" -ForegroundColor DarkYellow
        $CompanyLogo = Read-Host
        Write-Host

        # New Password for BreakGlass
        $BGUserPWString = genRandString 25

        $config = @{
            BreakGlassAccountPass       = $BGUserPWString
            MSPAlertsAddress            = $Global:mspAlertsAddress
            MSPName                     = $Global:mspName
            AdminAccessToMailboxes      = $true
            DisableFocusedInbox         = $true
            DisableSecurityDefaults     = $true
            DeleteStaleDevices          = $true
            StaleDeviceThresholdDays    = 90
            AuditLogAgeLimit            = 730
            DevicePilotGroupName        = "Pilot-DeviceCompliance"
            GroupCreatorsGroupName      = "Group Creators"
            GuestCreatorAdminsGroupName = "Guest Creators"
            ExcludeFromCAGroupName      = "Exclude From CA"
            AllowedAutoForwardingGroup  = "AutoForwarding-Allowed"
            Language                    = "en-US"
            Timezone                    = "Eastern Standard Time"
            LogoURL                     = $CompanyLogo
            TeamsConfig                 = @{
                AllowOrgWideTeamCreation  = $false
                AllowFederatedUsers       = $true
                AllowTeamsConsumer        = $false
                AllowTeamsConsumerInbound = $false
                AllowGuestAccess          = $true
                DisableAnonymousJoin      = $true
                AllowBox                  = $false
                AllowDropBox              = $false
                AllowEgnyte               = $false
                AllowEmailIntoChannel     = $true
                AllowGoogleDrive          = $false
            }
            SharePointOneDriveConfig    = @{
                OneDriveStorageQuota              = 1048576
                SharingCapability                 = "ExternalUserAndGuestSharing"
                DefaultSharingLinkType            = "Internal"
                PreventExternalUsersFromResharing = $true
                BccExternalSharingInvitations     = $true
            }
            CompliancePolicies          = @{
                EmailRetentionYears              = 10
                SharePointOneDriveRetentionYears = 10
            }
            ScriptPaths                 = @{
                DLPConfig            = "DataLossPrevention\DLPConfig.ps1"
                ModuleUpdater        = "M365ModuleUpdater\M365ModuleUpdater.ps1"
                TenantExchangeConfig = "TenantExchangeConfig\TenantExchangeConfig.ps1"
                ModuleConnector      = "M365ModuleConnector\M365ModuleConnector.ps1"
                ATPConfig            = "AdvancedThreatProtection\ATPConfig.ps1"
            }
        }
        $Config | ConvertTo-Json | Out-File "$scriptPath\config.json"

        # Optional Exit / Confirmation
        Clear-Host
        Write-Host
        Write-Host "A new config file [config.json] has been generated and placed at script root (Same directory as this Launcher script)." -ForegroundColor DarkYellow
        Write-Host
        Write-Host "The password for your BreakGlass account will be (no spaces):   $BGUserPWString" -ForegroundColor Green
        Write-Host
        Write-Host "This password is also recorded in the config file."-ForegroundColor DarkGreen
        Write-Host "Be sure to delete this file and change the password when you are finished." -ForegroundColor DarkGreen
        Write-Host
        Write-Host "Press any button to continue, or exit script (Ctrl-C) to review the config file before proceeding (See README)" -ForegroundColor DarkYellow
        Read-Host 

        write-title

    }
    return $config
}

# Function to display menu and get user choice
function Show-Menu {
    param (
        [string]$Title = 'M365 Configuration Menu'
    )

    Write-Host
    Write-Host "================ $Title ================" -ForegroundColor DarkCyan
    Write-Host
    Write-Host "R: Refresh Connections"
    Write-Host "1: Install and Update Required Modules"
    Write-Host "2: Connect All Modules to M365 Tenant"
    Write-Host "3: Configure M365 Tenant and Exchange Online"
    Write-Host "4: Configure ATP (Advanced Threat Protection)"
    Write-Host "5: Configure DLP (Data Loss Prevention)"
    Write-Host "Q: Quit - Consolidate logs, Disconnect Sessions"
    Write-Host
}

# Function to run a script with error handling and logging
function Run-Script {
    param (
        [string]$ScriptPath,
        [string]$ScriptName
    )
    Write-Log "Starting $ScriptName" "INFO"
    try {
        if (Test-Path $ScriptPath) {
            & $ScriptPath
            Write-Host
            Write-Log "$ScriptName completed successfully" "INFO"
        }
        else {
            Write-Log "Error: $ScriptName not found at $ScriptPath" "ERROR"
        }
    }
    catch {
        # Fixed line: Properly expanding variables in the error message
        Write-Log "Error executing $ScriptName : $($_.Exception.Message)" "ERROR"
    }
}

# Function to combine and consilidate log files generated by the scripts
function Consolidate-LogFiles {
    # Get the current date and time for the new log file name
    $dateTime = Get-Date -Format "yyyyMMdd_HH-mm"
    
    # Create the new log file name, using "noTenant" if $Global:TenantDomain is null
    $tenantName = if ($null -eq $Global:TenantDomain) { "noTenant" } else { $Global:TenantDomain }
    $newLogFileName = "${tenantName}_${dateTime}.log"
    $newLogFilePath = Join-Path $PSScriptRoot $newLogFileName

    # Get all directories from the config file, fallback to script root if empty
    $directories = @($PSScriptRoot)
    if ($null -ne $config -and $null -ne $config.ScriptPaths -and $config.ScriptPaths.Count -gt 0) {
        $configDirs = $config.ScriptPaths.Values | Where-Object { $_ -ne $null } | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique
        if ($configDirs.Count -gt 0) {
            $directories = $configDirs
        }
    }

    # Initialize an array to store all log entries
    $allLogEntries = @()

    # Search for log files in all directories and subdirectories
    foreach ($directory in $directories) {
        if (Test-Path $directory) {
            $logFiles = Get-ChildItem -Path $directory -Recurse -Filter "*.log"
            foreach ($logFile in $logFiles) {
                $content = Get-Content $logFile.FullName
                $allLogEntries += $content
            }
        }
        else {
            Write-Host "Directory not found: $directory" -ForegroundColor Yellow
        }
    }

    # Sort all entries chronologically and remove duplicates
    $uniqueSortedEntries = $allLogEntries | Sort-Object -Unique

    # Write the consolidated entries to the new log file
    $uniqueSortedEntries | Set-Content $newLogFilePath

    Write-Host "Consolidated log file created: $newLogFilePath" -ForegroundColor Green

    # Delete all old log files, excluding the newly created consolidated log
    foreach ($directory in $directories) {
        if (Test-Path $directory) {
            $logFiles = Get-ChildItem -Path $directory -Recurse -Filter "*.log" | Where-Object { $_.FullName -ne $newLogFilePath }
            foreach ($logFile in $logFiles) {
                Remove-Item $logFile.FullName -Force
                Write-Host "Deleted old log file: $($logFile.FullName)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Log consolidation complete. Old log files have been deleted." -ForegroundColor Green
}

# Function to check existing connections
function Check-ExistingConnections {
    $connections = @()
    $DisplayConnections = @()

    # Check Config File
    try {
        $config = Get-Content $configFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($config.MSPName) {
            $connections += "Config File"
            $DisplayConnections += "Config File"
        }
    }
    catch {
        Write-Log "CRITICAL: Config file not found" "ERROR"
        Load-Configuration
    }

    # Check Exchange Online Management connection
    try {
        $exchangeConnection = Get-Module -Name ExchangeOnlineManagement -ListAvailable
        if ($exchangeConnection) {
            $tenantInfo = Get-OrganizationConfig -ErrorAction Stop
            $connections += "ExchangeOnlineManagement"
            $DisplayConnections += "Exchange Online (Tenant: $($tenantInfo.DisplayName))"
        }
    }
    catch {
        Write-Host " - Not connected to Exchange Online"
    }

    # Check Security and Compliance Center connection
    try {
        Get-ComplianceSearch -ErrorAction Stop
        $connections += "IPPSSession"
        $DisplayConnections += "Security and Compliance Center"
    }
    catch {
        Write-Host " - Not connected to Security & Compliance Center"
    }

    # Check Azure AD connection
    try {
        $azureADInfo = Get-AzureADTenantDetail -ErrorAction Stop
        $connections += "AzureADPreview"
        $DisplayConnections += "Azure AD (Tenant: $($azureADInfo.DisplayName))"
    }
    catch {
        Write-Host " - Not connected to Azure AD"
    }

    # Check MSOnline connection
    try {
        $msolCompanyInfo = Get-MsolCompanyInformation -ErrorAction Stop
        $connections += "MSOnline"
        $DisplayConnections += "MSOnline (Tenant: $($msolCompanyInfo.DisplayName))"
    }
    catch {
        Write-Host " - Not connected to MSOnline"
    }

    # Check Teams connection
    try {
        $teamsConnection = Get-CsOnlineUser -ResultSize 1 -ErrorAction Stop
        if ($teamsConnection) {
            $tenantInfo = (Get-CsTenant).TenantId
            $connections += "MicrosoftTeams"
            $DisplayConnections += "Teams (Tenant ID: $tenantInfo)"
        }
    }
    catch {
        Write-Host " - Not connected to Microsoft Teams"
    }

    # Check SharePoint Online connection
    try {
        $spoConnection = Get-SPOSite -Limit ALL -ErrorAction Stop
        if ($spoConnection) {
            $connections += "Microsoft.Online.SharePoint.PowerShell"
            $DisplayConnections += "SharePoint"
        }
    }
    catch {
        Write-Host " - Not connected to SharePoint Online"
    }

    # Check MS Graph connection
    try {
        $graphConnection = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction Stop
        if ($graphConnection) {
            $tenantInfo = (Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/organization").value[0]
            $connections += "MSGRAPH"
            $DisplayConnections += "MS Graph (old) (Tenant: $($tenantInfo.DisplayName))"
        }
    }
    catch {
        Write-Host " - Not connected to MS Graph"
    }

    # Check Microsoft.Graph connection
    try {
        $graphInfo = Get-MgOrganization -ErrorAction Stop
        $connections += "Microsoft.Graph"
        $DisplayConnections += "MG Graph (new) (Tenant: $($graphInfo.DisplayName))"
    }
    catch {
        Write-Host " - Not connected to Microsoft.Graph"
    }

    # Check AIPService connection
    try {
        $aipConnection = Get-AIPServiceConfiguration -ErrorAction Stop
        if ($aipConnection) {
            $connections += "AIPService"
            $DisplayConnections += "AIPService"
        }
    }
    catch {
        Write-Host " - Not connected to AIPService"
    }

    #return $connections
    return $DisplayConnections
}

# Function to Compare Necessary Connections
function Check-AllNecessaryConnections {
    $necessaryConnections = @(
        "Exchange Online",
        "Security and Compliance Center",
        "Azure AD",
        "MSOnline",
        "Teams",
        "SharePoint",
        "MS Graph (old)",
        "MG Graph (new)",
        "AIPService"
    )

    $missingConnections = @()

    foreach ($connection in $necessaryConnections) {
        if (-not ($Global:existingConnections | Where-Object { $_ -like "*$connection*" })) {
            $missingConnections += $connection
        }
    }

    if ($missingConnections.Count -eq 0) {
        return $true
    }
    else {
        return $missingConnections
    }
}

# Function to display existing connections and prompt for action
function Prompt-ExistingConnections {
    $Global:existingConnections = Check-ExistingConnections
    if ($Global:existingConnections.Count -gt 1) {
        Write-Host
        Write-Host "Prerequisites Established:"
        $Global:existingConnections | ForEach-Object { Write-Host " - $_" -ForegroundColor Cyan }
        Write-Host
        Write-Log "Proceeding with established connections." "INFO"
    }
    else {
        Write-Host
        Write-Host
        Write-Log "No existing tenant connections detected." "WARNING"
    }

    # Admin/Tenant in Use
    if ($null -eq $Global:Credential) {
        Write-Log "No Admin Account being used" "WARNING"
    }
    else {
        #Set Tenant Domain and ID
        $Global:TenantDomain = $Global:Credential.UserName.Split('@')[1].Split('.')[0]
        try {
            $Global:TenantID = (Get-CsTenant).TenantId
        }
        catch {
            $Global:TenantID = "CRITICAL ERROR"
        } 
        Write-Log "Established Creds to $Global:TenantDomain with $($Global:Credential.UserName)" "INFO"
        Write-Host
        Write-Host "Global Variables" -ForegroundColor  DarkGreen
        Write-Host " -= Tenant: $Global:TenantDomain" -ForegroundColor DarkGreen
        Write-Host " -= Tenant ID : $Global:TenantID" -ForegroundColor  DarkGreen
        Write-Host " -= Credential: $($Global:Credential.UserName)" -ForegroundColor  DarkGreen
    }

    # Check if all necessary connections are established and set global variable
    $Global:connectionCheck = Check-AllNecessaryConnections
    if ($Global:connectionCheck -eq $true) {
        Write-Host
        Write-Host " All necessary connections are established! Proceed with Configuration." -ForegroundColor Green
    }
    else {
        Write-Host
        Write-Host
        Write-Host "Some required module connections are missing:" -ForegroundColor Yellow
        $Global:connectionCheck | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
    }
}

# Function to disconnect from all open connections
function Close-ExistingConnections {
    Write-Host "Disconnecting all sessions..." -ForegroundColor Yellow
    Write-Host

    # Exchange Online
    if (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" }) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from Exchange Online" -ForegroundColor DarkYellow
    }

    # Security & Compliance Center
    if (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.ComputerName -eq "ps.compliance.protection.outlook.com" }) {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.ComputerName -eq "ps.compliance.protection.outlook.com" } | Remove-PSSession -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from Security & Compliance Center" -ForegroundColor DarkYellow
    }

    # Azure AD
    if (Get-Module -Name AzureAD -ListAvailable) {
        Disconnect-AzureAD -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from Azure AD" -ForegroundColor DarkYellow
    }

    # MSOnline
    if (Get-Module -Name MSOnline -ListAvailable) {
        # MSOnline doesn't have a disconnect cmdlet, so we'll just remove the module
        Remove-Module -Name MSOnline -Force -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from MSOnline" -ForegroundColor DarkYellow
    }

    # Teams
    if (Get-Module -Name MicrosoftTeams -ListAvailable) {
        Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from Microsoft Teams" -ForegroundColor DarkYellow
    }

    # SharePoint Online
    if (Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable) {
        try {
            $spSession = Get-SPOSession -ErrorAction SilentlyContinue
            if ($spSession) {
                Disconnect-SPOService -ErrorAction SilentlyContinue
                Write-Host " - Disconnected from SharePoint Online" -ForegroundColor DarkYellow
            }
        }
        catch {
            # Do nothing, as we're suppressing errors
        }
    }

    # Microsoft Graph (old)
    if (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable) {
        Disconnect-Graph -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from MS Graph (old)" -ForegroundColor DarkYellow
    }

    # Microsoft Graph (new)
    if (Get-Module -Name Microsoft.Graph -ListAvailable) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from MG Graph (new)" -ForegroundColor DarkYellow
    }

    # AIPService
    if (Get-Module -Name AIPService -ListAvailable) {
        Disconnect-AipService -ErrorAction SilentlyContinue
        Write-Host " - Disconnected from AIPService" -ForegroundColor DarkYellow
    }

    # Clear all remaining PS Sessions
    Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue

    # Remove all imported modules
    Get-Module | Where-Object { $_.ModuleType -eq "Script" } | Remove-Module -Force -ErrorAction SilentlyContinue

    Write-Host
    Write-Log "All connections have been closed." "INFO"
}

# Main Title Function
function write-title {
    Clear-Host
    Write-Host "                            .___  ___.  ____      __    _____                                               "
    Write-Host "                            |   \/   | |___ \    / /   | ____|                                              "
    Write-Host "                            |  \  /  |   __) |  / /_   | |__                                                "
    Write-Host "                            |  |\/|  |  |__ <  | '_ \  |___ \                                               "
    Write-Host "                            |  |  |  |  ___) | | (_) |  ___) |                                              "
    Write-Host "                            |__|  |__| |____/   \___/  |____/                                               "
    Write-Host "                                                                                                            "
    Write-Host "   ______   ______   .__   __.  _______  __    _______  __    __  .______          ___   .___________.  ______   .______       "
    Write-Host "  /      | /  __  \  |  \ |  | |   ____||  |  /  _____||  |  |  | |   _  \        /   \  |           | /  __  \  |   _  \      "
    Write-Host " |  ,----'|  |  |  | |   \|  | |  |__   |  | |  |  __  |  |  |  | |  |_)  |      /  ^  \ '---|  |----'|  |  |  | |  |_)  |     "
    Write-Host " |  |     |  |  |  | |  . '  | |   __|  |  | |  | |_ | |  |  |  | |      /      /  /_\  \    |  |     |  |  |  | |      /      "
    Write-Host " |  '----.|  '--'  | |  |\   | |  |     |  | |  |__| | |  '--'  | |  |\  \----./  _____  \   |  |     |  '--'  | |  |\  \----. "
    Write-Host "  \______| \______/  |__| \__| |__|     |__|  \______|  \______/  | _| '._____/__/     \__\  |__|      \______/  | _| '._____| "
    Write-Host                                                                                                                                                         
    Write-Host
    Write-Host " Created by Alex Ivantsov @Exploitacious "
    Write-Host
}

##################################################
### Main script logic
##################################################

# Load configuration
$config = Load-Configuration

write-title

# Menu Loop
do {
    Write-Host
    Write-Host
    Write-Host "Checking for connections..."
    Write-Host

    Prompt-ExistingConnections
    
    Write-Host
    Write-Host
    Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input) {
        'r' { 
            #Refresh the Menu Loop
            continue
        }
        '1' {
            Run-Script $config.ScriptPaths.ModuleUpdater "Module Updater"
        }
        '2' {
            Run-Script $config.ScriptPaths.ModuleConnector "Module Connector"
        } 
        '3' {
            Run-Script $config.ScriptPaths.TenantExchangeConfig "Tenant and Exchange Configuration"
        }
        '4' { Run-Script $config.ScriptPaths.ATPConfig "ATP Configuration" }
        '5' { Run-Script $config.ScriptPaths.DLPConfig "DLP Configuration" }
        'q' { 
            Write-Log "Wrapping up, please be patient..." "INFO"
            Write-Host
            Close-ExistingConnections
            $Global:existingConnections = $null
            $Global:Credential = $null
            $Global:Modules = $null
            Consolidate-LogFiles
        }
    }
    pause
}
until ($input -eq 'q')

Write-Host
Write-Host "Use the log file for information regarding the work completed for the work/time/ticket entry."
Write-Host
Read-Host "Press any key to exit"