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
$configFile = Join-Path $PSScriptRoot "config.json"

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

# Function to load configuration
function Load-Configuration {
    if (Test-Path $configFile) {
        $config = Get-Content $configFile | ConvertFrom-Json
    }
    else {
        $config = @{
            ScriptPaths = @{
                ModuleUpdater        = "M365ModuleUpdater\M365ModuleUpdater.ps1"
                TenantExchangeConfig = "TenantExchangeConfig\TenantExchangeConfig.ps1"
                ATPConfig            = "AdvancedThreatProtection\ATPConfig.ps1"
                DLPConfig            = "DataLossPrevention\DLPConfig.ps1"
            }
        }
        $config | ConvertTo-Json | Set-Content $configFile
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
    Write-Host "1: Install/Update and Connect Required Modules"
    Write-Host "2: Configure M365 Tenant and Exchange Online"
    Write-Host "3: Configure ATP (Advanced Threat Protection)"
    Write-Host "4: Configure DLP (Data Loss Prevention)"
    Write-Host "5: Run All Configurations"
    Write-Host "Q: Quit"
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
        Write-Host "The following connections are already established:" -ForegroundColor Yellow
        $existingConnections | ForEach-Object { Write-Host "- $_" -ForegroundColor Cyan }
        $action = Read-Host "`nDo you want to disconnect these sessions before proceeding? (Y/N)"
        if ($action -eq 'Y' -or $action -eq 'y') {
            Get-PSSession | Remove-PSSession
            Disconnect-AzureAD -ErrorAction SilentlyContinue
            Write-Log "Existing connections have been closed." "INFO"
        }
        else {
            Write-Log "Proceeding with existing connections. This may affect the module update process." "WARNING"
        }
    }
    else {
        Write-Log "No existing tenant connections detected." "INFO"
    }
}


# Load configuration
$config = Load-Configuration

# Main script logic
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
        '2' { Run-Script $config.ScriptPaths.TenantExchangeConfig "Tenant and Exchange Configuration" }
        '3' { Run-Script $config.ScriptPaths.ATPConfig "ATP Configuration" }
        '4' { Run-Script $config.ScriptPaths.DLPConfig "DLP Configuration" }
        '5' {
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
            return
        }
    }
    pause
}
until ($input -eq 'q')

Write-Log "Script execution completed" "INFO"