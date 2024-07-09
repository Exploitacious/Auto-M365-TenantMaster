# M365 Module Updater
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
Write-Host "================ M365 Module Install and Updater ================" -ForegroundColor DarkCyan
Write-Host

# Import required modules
Import-Module Microsoft.PowerShell.Utility

# Initialize variables
$modulesSummary = @()
$logFile = Join-Path $PSScriptRoot "ModuleUpdater_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ModuleBlacklist = @(
    "AzureAD"
    "PnP.PowerShell"
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

# Function to remove specified modules
function Remove-Modules {
    param (
        [string[]]$ModuleName
    )
    
    foreach ($module in $ModuleName) {
        Write-Log "Checking for un-needed module: $module" "INFO"
        $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
        
        if ($installedModule) {
            Write-Log "Removing module: $module" "INFO"
            try {
                Uninstall-Module -Name $module -AllVersions -Force
                Write-Log "Attempted to remove module: $module" "INFO"
            }
            catch {
                Write-Log "Failed to remove module: $module. Error: $($_.Exception.Message)" "ERROR"
            }
        }
    }
}

# Update Modules with specific versioning enabled
function Update-Modules {
    param (
        [string]$ModuleName
    )

    # Ensure the ModuleName is not null or empty
    if ([string]::IsNullOrEmpty($ModuleName)) {
        Write-Log "ModuleName is null or empty at the start of Update-Module function" "ERROR"
        return
    }

    # Get all Current Versions
    $installedModules = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue
    $currentVersions = $installedModules.Version -join " "
    $installedVersions = $installedModules.Version

    # Log the current version
    Write-Log "Current version(s) of ${ModuleName}: ${currentVersions}" "INFO"

    # Set Required Versions
    if ($ModuleName -eq "ExchangeOnlineManagement") {
        $requiredVersion = "3.2.0"
    }
    else {
        $requiredVersion = (Find-Module -Name $ModuleName).Version
    }

    # Log the required version
    Write-Log "Required version for ${ModuleName}: ${requiredVersion}" "INFO"

    # Get Latest Versions
    $CurrentModule = Find-Module -Name $ModuleName -RequiredVersion $requiredVersion
    if ($null -eq $CurrentModule) {
        Write-Log "Unable to find module ${ModuleName} with version ${requiredVersion}" "ERROR"
        return
    }

    $status = "Unknown"
    $version = "N/A"

    # Function to attempt to close a module in use
    function Attempt-ForceCloseModule {
        param (
            [string]$ModuleName
        )
        Write-Log "Attempting to close module ${ModuleName} which is currently in use" "WARNING"
        try {
            # Attempt to remove the module forcibly
            Get-Module -Name $ModuleName -ListAvailable | ForEach-Object {
                Remove-Module -Name $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Failed to forcibly remove module ${ModuleName}. Details: $($_.Exception.Message)" "ERROR"
        }
    }

    # Function to verify module version
    function Verify-ModuleVersion {
        param (
            [string]$ModuleName,
            [string]$ExpectedVersion
        )
        $installedVersion = (Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue).Version
        if ($installedVersion -eq $ExpectedVersion) {
            return $true
        }
        else {
            return $false
        }
    }

    # Ensure only the required version is installed
    function Ensure-SingleVersion {
        param (
            [string]$ModuleName,
            [string]$TargetVersion
        )
        $installedModules = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue
        foreach ($module in $installedModules) {
            if ($module.Version -ne $TargetVersion) {
                Write-Log "Uninstalling ${ModuleName}" "INFO"
                try {
                    Attempt-ForceCloseModule -ModuleName $ModuleName
                    Uninstall-Module -Name $ModuleName -Force
                }
                catch {
                    Attempt-ForceCloseModule -ModuleName $ModuleName
                    try {
                        Uninstall-Module -Name $ModuleName -RequiredVersion $module.Version -Force
                    }
                    catch {
                        Write-Log "Failed to uninstall version ${module.Version} of ${ModuleName}. Details: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
    }

    #####
    # Main Logic
    #####

    # Check for Azure AD over Azure AD Preview
    if ($ModuleName -eq "AzureADPreview") {
        # Check if AzureAD is installed
        $azureADInstalled = Get-InstalledModule -Name "AzureAD" -ErrorAction SilentlyContinue
        if ($azureADInstalled) {
            Write-Log "AzureAD module detected. Uninstalling before installing AzureADPreview." "WARNING"
            try {
                Attempt-ForceCloseModule "AzureAD"
                Uninstall-Module -Name "AzureAD" -AllVersions -Force
                Write-Log "AzureAD module uninstall attempted." "INFO"
            }
            catch {
                Write-Log "Failed to uninstall AzureAD module. Error: $($_.Exception.Message)" "ERROR"
                $status = "AzureAD Uninstall Failed"
                return
            }
        }
    }

    if ($null -eq $currentVersions) {
        # New Install
        Write-Log "$($CurrentModule.Name) - Installing ${ModuleName} from PowerShellGallery. Version: $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)" "INFO"
        try {
            Install-Module -Name $ModuleName -RequiredVersion $requiredVersion -Force -SkipPublisherCheck
            if (Verify-ModuleVersion -ModuleName $ModuleName -ExpectedVersion $requiredVersion) {
                $status = "Installed"
                $version = $CurrentModule.Version
            }
            else {
                $status = "Installation Failed"
            }
        }
        catch {
            Write-Log "Something went wrong when installing ${ModuleName}. Please uninstall and try re-installing this module. (Remove-Module, Install-Module) Details:" "ERROR"
            Write-Log "$_.Exception.Message" "ERROR"
            $status = "Installation Failed"
        }
    }
    elseif ($installedVersions -contains $requiredVersion -and $installedVersions.Count -eq 1) {
        # Already Installed
        Write-Log "$($CurrentModule.Name) is installed and ready. Version: (${requiredVersion}). Release date: $($CurrentModule.PublishedDate))" "INFO"
        $status = "Up to Date"
        $version = $currentVersions
    }
    else {
        # Multiple Versions or Different Version
        Write-Warning "${ModuleName} is installed in multiple versions or different version (versions: $($installedVersions -join ' | '))"
        Write-Log "Uninstalling non-target versions of ${ModuleName}" "INFO"
        Ensure-SingleVersion -ModuleName $ModuleName -TargetVersion $requiredVersion

        Write-Log "$($CurrentModule.Name) - Installing version from PowerShellGallery $requiredVersion. Release date: $($CurrentModule.PublishedDate)" "INFO"

        try {
            Install-Module -Name $ModuleName -RequiredVersion $requiredVersion -Force -SkipPublisherCheck
            if (Verify-ModuleVersion -ModuleName $ModuleName -ExpectedVersion $requiredVersion) {
                Write-Log "${ModuleName} Successfully Installed" "INFO"
                $status = "Updated"
                $version = $requiredVersion
            }
            else {
                $status = "Installation Failed"
            }
        }
        catch {
            Write-Log "Something went wrong with installing ${ModuleName}. Details:" "ERROR"
            Write-Log -ForegroundColor red "$_.Exception.Message" "ERROR"
            $status = "Update Failed"
        }
    }

    $modulesSummary += [PSCustomObject]@{
        Module  = $ModuleName
        Status  = $status
        Version = $version
    }
    return
}

##############################################################################
### Main script logic
##############################################################################

Write-Log "Starting M365 Module Updater" "INFO"

# List of modules to Remove/Install/Update
$installedModules = Get-InstalledModule * | Select-Object -ExpandProperty Name
$FullModuleList = $Global:Modules
$FullModuleList = $FullModuleList += $installedModules
$FullModuleList = $FullModuleList | Sort-Object -Unique
$FullModuleList = $FullModuleList | Where-Object { $_ -notin $ModuleBlacklist }

Write-Host
Write-Host
Write-Host "Checking for Installed Modules..." -ForegroundColor Yellow

# Remove Modules
foreach ($Module in $ModuleBlacklist) {
    if (![string]::IsNullOrEmpty($Module)) {
        Write-Host
        Remove-Modules -ModuleName $Module
    }
}

Write-Host
Write-Host "Installing Required M365 Modules and Updating All PS Modules..." -ForegroundColor Yellow

# Install/Update Modules
foreach ($Module in $FullModuleList) {
    if (![string]::IsNullOrEmpty($Module)) {
        Write-Host
        Write-Log "Processing module: $Module" "INFO"
        Update-Modules -ModuleName $Module
    }
}

Write-Host
Write-Host -ForegroundColor Green "Module Updates Complete."
Write-Host
Write-Host "Please double check and make there are absolutely NO errors." -ForegroundColor Cyan
Write-Host "You may re-run this as many times as needed until all modules are correctly installed." -ForegroundColor Cyan
Write-Host
Write-Host "=== If you continue seeing errors for a problematic module: " -ForegroundColor Yellow
Write-Host " - Restart your PC. You can try to use 'Uninstall-Module xxx -RequiredVersion ... ' to remove modules in another powershell admin window" -ForegroundColor Yellow
Write-Host " - Try running this script as a last resort to obliterate any busted modules: " -ForegroundColor Yellow
Write-Host " PSModuleTerminator https://github.com/Exploitacious/Windows_Toolz/tree/main/Production/General/PSModuleTerminator" -ForegroundColor Yellow
Write-Host
Write-Log "M365 Module Updater Log $logFile" "INFO"