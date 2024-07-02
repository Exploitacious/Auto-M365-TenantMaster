# M365 Module Updater
Write-Host
Write-Host "================ M365 Module Install and Updater ================"
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
$modulesSummary = @()
$logFile = Join-Path $PSScriptRoot "ModuleUpdater_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$rollbackInfo = @{}

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

# Function to install or update a module
function Update-Module {
    param (
        [string]$ModuleName
    )

    Write-Log "Processing module: $ModuleName" "INFO"

    $currentVersion = $null
    if ($null -ne (Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue)) {
        $currentVersion = (Get-InstalledModule -Name $ModuleName -AllVersions).Version
        $rollbackInfo[$ModuleName] = $currentVersion
    }

    $latestModule = Find-Module -Name $ModuleName

    $status = "Unknown"
    $version = "N/A"

    if ($null -eq $currentVersion) {
        Write-Log "$($latestModule.Name) - Installing $ModuleName from PowerShellGallery. Version: $($latestModule.Version). Release date: $($latestModule.PublishedDate)" "INFO"
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber
            $status = "Installed"
            $version = $latestModule.Version
        }
        catch {
            Write-Log "Error installing $ModuleName. Details: $($_.Exception.Message)" "ERROR"
            $status = "Installation Failed"
        }
    }
    elseif ($latestModule.Version -eq $currentVersion) {
        Write-Log "$($latestModule.Name) is up to date. Version: $currentVersion. Release date: $($latestModule.PublishedDate)" "INFO"
        $status = "Up to Date"
        $version = $currentVersion
    }
    else {
        Write-Log "$($latestModule.Name) - Updating from version $currentVersion to $($latestModule.Version). Release date: $($latestModule.PublishedDate)" "INFO"
        try {
            Update-Module -Name $ModuleName -Force -AllowClobber
            $status = "Updated"
            $version = $latestModule.Version
        }
        catch {
            Write-Log "Error updating $ModuleName. Details: $($_.Exception.Message)" "ERROR"
            $status = "Update Failed"
        }
    }

    return [PSCustomObject]@{
        Module  = $ModuleName
        Status  = $status
        Version = $version
    }
}

# Function to rollback module updates
function Rollback-ModuleUpdates {
    Write-Log "Starting rollback process" "WARNING"
    foreach ($module in $rollbackInfo.Keys) {
        $version = $rollbackInfo[$module]
        Write-Log "Rolling back $module to version $version" "INFO"
        try {
            Uninstall-Module -Name $module -AllVersions -Force
            Install-Module -Name $module -RequiredVersion $version -Force -AllowClobber
            Write-Log "Successfully rolled back $module to version $version" "INFO"
        }
        catch {
            Write-Log "Failed to rollback $module. Error: $($_.Exception.Message)" "ERROR"
        }
    }
    Write-Log "Rollback process completed" "WARNING"
}

# List of modules to install/update
$Modules = @(
    "ExchangeOnlineManagement", 
    "MSOnline",
    "AzureADPreview",
    "MSGRAPH",
    "Microsoft.Graph.Intune",
    "Microsoft.Graph.DeviceManagement",
    "Microsoft.Graph.Compliance",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Authentication",
    "AIPService"
)

# Main script logic
$Answer = Read-Host "Would you like to update/install the required modules? (Y/N)"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {
    Write-Log "Starting module update process" "INFO"

    foreach ($Module in $Modules) {
        $result = Update-Module -ModuleName $Module
        $modulesSummary += $result
    }

    # Display summary
    Write-Log "Module Installation/Update Summary:" "INFO"
    $modulesSummary | Format-Table -AutoSize

    # Check for failures and offer rollback
    $failures = $modulesSummary | Where-Object { $_.Status -like "*Failed" }
    if ($failures) {
        Write-Log "Some module updates failed. Would you like to rollback all changes? (Y/N)" "WARNING"
        $rollbackAnswer = Read-Host
        if ($rollbackAnswer -eq 'Y' -or $rollbackAnswer -eq 'yes') {
            Rollback-ModuleUpdates
        }
    }
}

# Module connection
$Answer = Read-Host "Would you like to connect to the required modules? (Y/N)"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {
    $Cred = Get-Credential

    $connectionModules = @(
        @{Name = "Exchange Online"; Cmd = { Connect-ExchangeOnline -UserPrincipalName $Cred.Username } },
        @{Name = "Microsoft Online"; Cmd = { Connect-MsolService } },
        @{Name = "Azure AD Preview"; Cmd = { Connect-AzureAD } },
        @{Name = "Azure Information Protection"; Cmd = { Connect-AipService } },
        @{Name = "Information Protection Service"; Cmd = { Connect-IPPSSession } }
    )

    $connectionSummary = @()

    foreach ($module in $connectionModules) {
        try {
            & $module.Cmd
            Write-Host "$($module.Name) Connected!"
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

    # Display connection summary
    Write-Host "Module Connection Summary:"
    $connectionSummary | Format-Table -AutoSize
}

Write-Log "Script execution completed. Please review the log file at $logFile for details." "INFO"
Read-Host "Press Enter to continue"