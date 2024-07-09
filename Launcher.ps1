# M365 Configuration Launcher

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

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "This script requires PowerShell 5.1 or later. Your version is $($PSVersionTable.PSVersion). Please upgrade PowerShell and try again." -ForegroundColor Red
    exit
}

# Verify/Elevate Admin Session.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 
}

# Import required modules
Import-Module Microsoft.PowerShell.Utility

# Initialize variables
$logFile = Join-Path $PSScriptRoot "Launcher_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$configFile = Join-Path $PSScriptRoot "paths.json"
$CombinedLogFile = Join-Path $PSScriptRoot "AutoM365Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Modules
$Global:Modules = @(
    "ExchangeOnlineManagement"
    "AzureADPreview"
    "MSOnline"
    "MSGRAPH"
    "Microsoft.Graph"
    "AIPService"
    "MicrosoftTeams"
    "PnP.PowerShell"
)

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

# Function to load and validate configuration
function Load-Configuration {
    if (Test-Path $configFile) {
        Write-Output "Loading configuration from $configFile"
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        if (-not $config.ScriptPaths) {
            Write-Log "Configuration file does not contain ScriptPaths. Using default configuration." "WARNING"
            $config = $null
        }
    }
    else {
        Write-Log "Configuration file not found. Using default configuration." "WARNING"
        $config = $null
    }

    if (-not $config) {
        Write-Output "Creating default configuration."
        $config = @{
            ScriptPaths = @{
                ModuleUpdater        = "M365ModuleUpdater\M365ModuleUpdater.ps1"
                ModuleConnector      = "M365ModuleConnector\M365ModuleConnector.ps1"
                TenantExchangeConfig = "TenantExchangeConfig\TenantExchangeConfig.ps1"
                ATPConfig            = "AdvancedThreatProtection\ATPConfig.ps1"
                DLPConfig            = "DataLossPrevention\DLPConfig.ps1"
            }
        }
        $config | ConvertTo-Json | Set-Content $configFile
        Write-Output "Default configuration saved to $configFile"
    }
    return $config
}

# Function to display menu and get user choice
function Show-Menu {
    param (
        [string]$Title = 'M365 Configuration Menu'
    )

    Write-Host
    Write-Host "================ $Title ================"
    Write-Host
    Write-Host "1: Install and Update Required Modules"
    Write-Host "2: Connect All Modules to an M365 Tenant"
    Write-Host "3: Configure M365 Tenant and Exchange Online"
    Write-Host "4: Configure ATP (Advanced Threat Protection)"
    Write-Host "5: Configure DLP (Data Loss Prevention)"
    Write-Host "6: Run All Configurations"
    Write-Host "Q: Terminate Connections and Quit"
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

# Function to combine log files
function Combine-LogFiles {
    # Extract directories from config
    $directories = @()
    foreach ($key in $config.ScriptPaths.Keys) {
        $scriptPath = $config.ScriptPaths[$key]
        $directory = Split-Path -Path $scriptPath -Parent

        # Convert to absolute path if not already absolute
        if (-not [System.IO.Path]::IsPathRooted($directory)) {
            $absoluteDirectory = [System.IO.Path]::Combine($PSScriptRoot, $directory)
        }
        else {
            $absoluteDirectory = $directory
        }

        # Debug output to verify each directory
        Write-Output "Attempting to extract directory from script path: $scriptPath"
        Write-Output "Extracted directory path: $absoluteDirectory"

        if (Test-Path -Path $absoluteDirectory) {
            $fullDirectoryPath = (Get-Item $absoluteDirectory).FullName
            $directories += $fullDirectoryPath
            Write-Output "Verified and added directory: $fullDirectoryPath"
        }
        else {
            Write-Error "Directory not found: $absoluteDirectory"
        }
    }

    # Debug output to verify the directories array
    Write-Output "Directories extracted: $($directories | Out-String)"

    # Check if any directories were found
    if ($directories.Count -eq 0) {
        Write-Error "No directories found in config."
        return
    }

    # Create or clear the output file
    try {
        New-Item -Path $CombinedLogFile -ItemType File -Force | Out-Null
        Write-Output "Output file created: $CombinedLogFile"
    }
    catch {
        Write-Error "Unable to create or clear the output file: $CombinedLogFile"
        return
    }

    $logFilesFound = $false

    # Loop through each directory and combine log files
    foreach ($directory in $directories) {
        Write-Output "Processing directory: $directory"
        if (Test-Path -Path $directory) {
            $logFiles = Get-ChildItem -Path $directory -Filter *.log -File
            if ($logFiles.Count -gt 0) {
                $logFilesFound = $true
                foreach ($logFile in $logFiles) {
                    Get-Content -Path $logFile.FullName | Add-Content -Path $CombinedLogFile
                    Write-Output "Combined log file: $($logFile.FullName)"
                }
            }
            else {
                Write-Output "No log files found in directory: $directory"
            }
        }
        else {
            Write-Error "Directory not found: $directory"
        }
    }

    if (-Not $logFilesFound) {
        Write-Output "No log files found. Exiting..."
    }
    else {
        Write-Output "Log files combined into: $CombinedLogFile"
    }
}

# Function to check existing connections
function Check-ExistingConnections {
    $connections = @()

    # Check Exchange Online connection
    try {
        $exchangeConnection = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" }
        if ($exchangeConnection) {
            $tenantInfo = Get-OrganizationConfig -ErrorAction Stop
            $connections += "Exchange Online (Tenant: $($tenantInfo.DisplayName))"
        }
    }
    catch {
        Write-Log "Error checking Exchange Online connection: $($_.Exception.Message)" "WARNING"
    }

    # Check Azure AD connection
    try {
        $azureADInfo = Get-AzureADTenantDetail -ErrorAction Stop
        $connections += "Azure AD (Tenant: $($azureADInfo.DisplayName))"
    }
    catch {
        Write-Log "Not connected to Azure AD" "WARNING"
    }

    # Check MSOnline connection
    try {
        $msolCompanyInfo = Get-MsolCompanyInformation -ErrorAction Stop
        $connections += "MSOnline (Tenant: $($msolCompanyInfo.DisplayName))"
    }
    catch {
        Write-Log "Not connected to MSOnline" "WARNING"
    }

    # Check Teams connection
    try {
        $teamsConnection = Get-CsOnlineUser -ResultSize 1 -ErrorAction Stop
        $connections += "Microsoft Teams"
    }
    catch {
        Write-Log "Not connected to Microsoft Teams" "WARNING"
    }

    # Check SharePoint Online connection
    try {
        $spoConnection = Get-SPOTenant -ErrorAction Stop
        $connections += "SharePoint Online"
    }
    catch {
        Write-Log "Not connected to SharePoint Online" "WARNING"
    }

    # Check MS Graph connection
    try {
        $graphConnection = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction Stop
        if ($graphConnection) {
            $connections += "MS Graph"
        }
    }
    catch {
        Write-Log "Not connected to MS Graph" "WARNING"
    }

    # Check Microsoft.Graph connection
    try {
        $graphInfo = Get-MgOrganization -ErrorAction Stop
        $connections += "Microsoft.Graph (Tenant: $($graphInfo.DisplayName))"
    }
    catch {
        Write-Log "Not connected to Microsoft.Graph" "WARNING"
    }

    # Check AIPService connection
    try {
        $aipConnection = Get-AIPServiceConfiguration -ErrorAction Stop
        $connections += "AIPService"
    }
    catch {
        Write-Log "Not connected to AIPService" "WARNING"
    }

    return $connections
}

# Function to display existing connections and prompt for action
function Prompt-ExistingConnections {
    $Global:existingConnections = Check-ExistingConnections
    if ($Global:existingConnections.Count -gt 0) {
        Write-Host
        Write-Host "Connections Established:" -ForegroundColor Yellow
        $Global:existingConnections | ForEach-Object { Write-Host "- $_" -ForegroundColor Cyan }
        Write-Host
        Write-Host
        Write-Log "Proceeding with existing connections." "INFO"
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
        #Set Tenant Domain
        $Global:TenantDomain = $Global:Credential.UserName.Split('@')[1].Split('.')[0]
        Write-Log "Connected to $Global:TenantDomain with $($Global:Credential.UserName)" "INFO"
        Write-Host
        Write-Host "-= Tenant Domain: $Global:TenantDomain" -ForegroundColor Green
        Write-Host "-=== Credential: $($Global:Credential.UserName)" -ForegroundColor Green
    }
}

##################################################
### Main script logic
##################################################

# Load configuration
$config = Load-Configuration

# Menu Loop
do {
    Write-Host
    Write-Host
    Write-Host "Please be patient as we check for connections..."
    Write-Host

    Prompt-ExistingConnections
    
    Write-Host
    Write-Host
    Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input) {
        '1' { Run-Script $config.ScriptPaths.ModuleUpdater "Module Updater" }
        '2' { Run-Script $config.ScriptPaths.ModuleConnector "Module Connector" } 
        '3' { Run-Script $config.ScriptPaths.TenantExchangeConfig "Tenant and Exchange Configuration" }
        '4' { Run-Script $config.ScriptPaths.ATPConfig "ATP Configuration" }
        '5' { Run-Script $config.ScriptPaths.DLPConfig "DLP Configuration" }
        'q' { 
            Write-Log "Exiting script..." "INFO"

            # Attempt Combine
            # Combine-LogFiles # Gotta fix this
            
            # Terminating Module Connections
            Write-Host "Disconnecting all sessions" -ForegroundColor Yellow
            try {
                $Global:Credential = $null
                Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
                Disconnect-AzureAD -ErrorAction SilentlyContinue
                Write-Log "Existing connections have been closed." "INFO"
            } 
            catch {
                Write-Log "Existing connections have been closed." "INFO"
            }
            return
        }
    }
    pause
}
until ($input -eq 'q')