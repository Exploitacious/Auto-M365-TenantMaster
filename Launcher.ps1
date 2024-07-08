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


# Import required modules
Import-Module Microsoft.PowerShell.Utility

# Initialize variables
$logFile = Join-Path $PSScriptRoot "Launcher_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$configFile = Join-Path $PSScriptRoot "paths.json"
$CombinedLogFile = Join-Path $PSScriptRoot "AutoM365Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Modules
$Global:Modules = @(
    "ExchangeOnlineManagement",
    "MSOnline",
    "AzureADPreview",
    "MSGRAPH",
    "Microsoft.Graph",
    "AIPService",
    "MicrosoftTeams",
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
    Write-Host "Q: Consolidate logs and Quit"
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
            $tenantInfo = Get-OrganizationConfig
            $connections += "Exchange Online (Tenant: $($tenantInfo.DisplayName))"
        }
    }
    catch {
        Write-Host "Error checking Exchange Online connection: $($_.Exception.Message)" "WARNING"
    }

    # Check Azure AD connection
    try {
        $azureADInfo = Get-AzureADTenantDetail -ErrorAction Stop
        $connections += "Azure AD (Tenant: $($azureADInfo.DisplayName))"
    }
    catch {
        Write-Host "Not connected to Azure AD"
    }

    # Check MSOnline connection
    try {
        $msolCompanyInfo = Get-MsolCompanyInformation -ErrorAction Stop
        $connections += "MSOnline (Tenant: $($msolCompanyInfo.DisplayName))"
    }
    catch {
        Write-Host "Not connected to MSOnline"
    }

    # Check Teams connection
    try {
        $teamsConnection = Get-CsOnlineUser -ResultSize 1 -ErrorAction Stop
        $connections += "Microsoft Teams"
    }
    catch {
        Write-Host "Not connected to Microsoft Teams"
    }

    # Check SharePoint Online connection
    try {
        $spoConnection = Get-SPOTenant -ErrorAction Stop
        $connections += "SharePoint Online"
    }
    catch {
        Write-Host "Not connected to SharePoint Online"
    }

    # Check MS Graph connection
    try {
        $graphConnection = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction Stop
        if ($graphConnection) {
            $connections += "MS Graph"
        }
    }
    catch {
        Write-Host "Not connected to MS Graph"
    }

    # Check Microsoft.Graph connection
    try {
        $graphInfo = Get-MgOrganization -ErrorAction Stop
        $connections += "Microsoft.Graph"
    }
    catch {
        Write-Host "Not connected to Microsoft.Graph"
    }

    # Check AIPService connection
    try {
        $aipConnection = Get-AIPServiceConfiguration -ErrorAction Stop
        $connections += "AIPService"
    }
    catch {
        Write-Host "Not connected to AIPService"
    }

    return $connections
}

# Function to display existing connections and prompt for action
function Prompt-ExistingConnections {
    $existingConnections = Check-ExistingConnections
    if ($existingConnections.Count -gt 0) {
        Write-Host "Connections Established:" -ForegroundColor Yellow
        $existingConnections | ForEach-Object { Write-Host "- $_" -ForegroundColor Cyan }
        $action = Read-Host "`nDo you want to disconnect these sessions before proceeding? (Y/N)"
        if ($action -eq 'Y' -or $action -eq 'y') {
            Get-PSSession | Remove-PSSession
            Disconnect-AzureAD -ErrorAction SilentlyContinue
            Write-Log "Existing connections have been closed." "INFO"
        }
        else {
            Write-Host
            Write-Log "Proceeding with existing connections." "INFO"
        }
    }
    else {
        Write-Host
        Write-Log "No existing tenant connections detected." "INFO"
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
        '6' {
            # Run all configurations in parallel
            $jobs = @(
                Start-Job -ScriptBlock { Run-Script $using:config.ScriptPaths.ModuleUpdater "Module Updater" }
                Start-Job -ScriptBlock { Run-Script $using:config.ScriptPaths.TenantExchangeConfig "Tenant and Exchange Configuration" }
                Start-Job -ScriptBlock { Run-Script $using:config.ScriptPaths.ATPConfig "ATP Configuration" }
                Start-Job -ScriptBlock { Run-Script $using:config.ScriptPaths.DLPConfig "DLP Configuration" }
            )
            
            # Wait for all jobs to complete
            $jobs | Wait-Job

            # Get the results
            $jobs | ForEach-Object {
                Receive-Job -Job $_
                Remove-Job -Job $_
            }
        }
        'q' { 
            Write-Log "Exiting script" "INFO"

            # Attempt Combine
            # Combine-LogFiles # Gotta fix this later.

            return
        }
    }
    pause
}
until ($input -eq 'q')