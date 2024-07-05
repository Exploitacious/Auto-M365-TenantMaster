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

# Update Modules with specific versioning enabled
function Update-Module {
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

    # Main Logic
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
                Connect-MgGraph -Scopes $Scopes -UseDeviceAuthentication
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

Write-Log "Starting M365 Module Updater" "INFO"
Write-Host
Write-Host "Please be patient as we check for prerequisites..."
Write-Host

Prompt-ExistingConnections

Write-Host
$Answer = Read-Host "Would you like to update/install the required modules? (Y/N)"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {

    # List of modules to install/update
    Write-Host
    Write-Host "Checking for Installed Modules..."
    $Modules = @(
        "ExchangeOnlineManagement",
        "MSOnline",
        "AzureADPreview",
        "MSGRAPH",
        "Microsoft.Graph",
        "AIPService",
        "MicrosoftTeams",
        "Microsoft.Online.SharePoint.PowerShell"
    )

    $installedModules = Get-InstalledModule * | Select-Object -ExpandProperty Name
    $Modules += $installedModules
    $Modules = $Modules | Sort-Object -Unique
    Write-Host
    Write-Host "Installing Required M365 Modules and Updating All Modules..."
    Write-Host

    foreach ($Module in $Modules) {
        if (![string]::IsNullOrEmpty($Module)) {
            Write-Host
            Write-Log "Processing module: $Module" "INFO"
            Update-Module -ModuleName $Module
        }
        else {
            Write-Log "Encountered an empty module name in the list, skipping." "WARNING"
        }
    }
    # Display summary
    Write-Log "Module Installation/Update Summary:" "INFO"
    $modulesSummary | Format-Table -AutoSize

    Write-Host
    Write-Host -ForegroundColor Green "Module Updates Complete."
    Write-Host "Please double check and make there are no errors and you are running Exchange Online Management Module version 3.2.0 and NOT the latest version."
    Write-Host "You may re-run this as many times as needed until all modules are correctly installed. If you continue seeing errors, restart your PC."
}

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

Write-Log "Script execution completed. Please review the log file at $logFile for details." "INFO"
Read-Host "Press Enter to continue"
