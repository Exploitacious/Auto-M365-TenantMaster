

write-host ".___  ___.  ____      __    _____     .___  ___.   ______    _______   __    __   __       _______     _______."
write-host "|   \/   | |___ \    / /   | ____|    |   \/   |  /  __  \  |       \ |  |  |  | |  |     |   ____|   /       |"
write-host "|  \  /  |   __) |  / /_   | |__      |  \  /  | |  |  |  | |  .--.  ||  |  |  | |  |     |  |__     |   (----'"
write-host "|  |\/|  |  |__ <  | '_ \  |___ \     |  |\/|  | |  |  |  | |  |  |  ||  |  |  | |  |     |   __|     \   \    "
write-host "|  |  |  |  ___) | | (_) |  ___) |    |  |  |  | |  `--'  | |  '--'  ||  `--'  | |  `----.|  |____.----)   |   "
write-host "|__|  |__| |____/   \___/  |____/     |__|  |__|  \______/  |_______/  \______/  |_______||_______|_______/    "
write-host "                                                                                                               "
write-host "                __    __  .______    _______       ___   .___________. _______ .______                         "
write-host "               |  |  |  | |   _  \  |       \     /   \  |           ||   ____||   _  \                        "
write-host "               |  |  |  | |  |_)  | |  .--.  |   /  ^  \ `---|  |----`|  |__   |  |_)  |                       "
write-host "               |  |  |  | |   ___/  |  |  |  |  /  /_\  \    |  |     |   __|  |      /                        "
write-host "               |  `--'  | |  |      |  '--'  | /  _____  \   |  |     |  |____ |  |\  \----.                   "
write-host "                \______/  | _|      |_______/ /__/     \__\  |__|     |_______|| _| `._____|                   "
write-host "                                                                                                               "
write-host " "
write-host " Created by Alex Ivantsov @Exploitacious "
write-host " "
Write-Host

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "This script requires PowerShell 5.1 or later. Your version is $($PSVersionTable.PSVersion). Please upgrade PowerShell and try again." -ForegroundColor Red
    exit
}

# Verify/Elevate Admin Session.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$modulesSummary = @()

$Answer = Read-Host "Would you like this script to run a pre-requisite check to make sure you have all the modules correctly installed? * RECOMMENDED * (Will automatically install and update all required modules) Y or N"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {

    Write-Host
    Write-Host "Checking for Installed Modules..."

    try {
        Get-InstalledModule "AzureAD" -ErrorAction Stop
        Write-Host "AzureAD (non Preview) was found. Attempting to remove before continuing."
        Get-InstalledModule -Name "AzureAD" -AllVersions | Uninstall-Module -Force
    }
    catch {
        Write-Host "AzureAD (non Preview) was not detected. Good!"
    }

    $Modules = @(
        "ExchangeOnlineManagement"; 
        "MSOnline";
        "AzureADPreview";
        "MSGRAPH";
        "Microsoft.Graph.Intune";
        "Microsoft.Graph.DeviceManagement";
        "Microsoft.Graph.Compliance";
        "Microsoft.Graph.Users";
        "Microsoft.Graph.Groups";
        "Microsoft.Graph.Identity.SignIns";
        "Microsoft.Graph.Authentication";
        "AIPService"
    )

    Foreach ($Module In $Modules) {
        $currentVersion = $null
        if ($null -ne (Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue)) {
            $currentVersion = (Get-InstalledModule -Name $module -AllVersions).Version
        }

        $CurrentModule = Find-Module -Name $module

        $status = "Unknown"
        $version = "N/A"

        if ($null -eq $currentVersion) {
            Write-Host "$($CurrentModule.Name) - Installing $Module from PowerShellGallery. Version: $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)"
            try {
                Install-Module -Name $module -Force
                $status = "Installed"
                $version = $CurrentModule.Version
            }
            catch {
                Write-Host "Something went wrong when installing $Module. Please uninstall and try re-installing this module. (Remove-Module, Install-Module) Details:"
                Write-Host "$_.Exception.Message"
                $status = "Installation Failed"
            }
        }
        elseif ($CurrentModule.Version -eq $currentVersion) {
            Write-Host "$($CurrentModule.Name) is installed and ready. Version: ($currentVersion. Release date: $($CurrentModule.PublishedDate))"
            $status = "Up to Date"
            $version = $currentVersion
        }
        elseif ($currentVersion.count -gt 1) {
            Write-Warning "$module is installed in $($currentVersion.count) versions (versions: $($currentVersion -join ' | '))"
            Write-Host "Uninstalling previous $module versions and will attempt to update."
            try {
                Get-InstalledModule -Name $module -AllVersions | Where-Object { $_.Version -ne $CurrentModule.Version } | Uninstall-Module -Force
            }
            catch {
                Write-Host "Something went wrong with Uninstalling $Module previous versions. Please Completely uninstall and re-install this module. (Remove-Module) Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
                $status = "Uninstallation Failed"
            }
        
            Write-Host "$($CurrentModule.Name) - Installing version from PowerShellGallery $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)"  
    
            try {
                Install-Module -Name $module -Force
                Write-Host "$Module Successfully Installed"
                $status = "Updated"
                $version = $CurrentModule.Version
            }
            catch {
                Write-Host "Something went wrong with installing $Module. Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
                $status = "Update Failed"
            }
        }
        else {       
            Write-Host "$($CurrentModule.Name) - Updating from PowerShellGallery from version $currentVersion to $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)" 
            try {
                Update-Module -Name $module -Force
                Write-Host "$Module Successfully Updated"
                $status = "Updated"
                $version = $CurrentModule.Version
            }
            catch {
                Write-Host "Something went wrong with updating $Module. Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
                $status = "Update Failed"
            }
        }

        $modulesSummary += [PSCustomObject]@{
            Module  = $Module
            Status  = $status
            Version = $version
        }
    }

    Write-Host
    Write-Host
    Write-Host "Check the modules listed in the verification above. If you see any errors, please check the module(s) or restart the script to try and auto-fix."
    Write-Host "Most common error is that you have 'AzureAD' instead of 'AzureADPreview' installed. Please remove AzureAD and try again."
    Write-Host "You can re-run this part of the script as many times as necessary until all modules are up to date and correctly installed."
    Write-Host
} 

$connectionSummary = @()

$Answer = Read-Host "Would you like the script to CONNECT all modules? ('N' to skip automatic module connection, if you have already done so.) Y or N"
if ($Answer -eq 'Y' -or $Answer -eq 'yes') {

    Write-Host
    Write-Host "Enter your Tenant's Global Admin Credentials - You may see the PS credential prompt pop-up behind this window."
    Write-Host "You may be asked to sign in multiple times as each module loads and connects."

    $Cred = Get-Credential

    Write-Host
    Write-Host "Removing old Powershell Sessions and establishing new ones..."
    Get-PSSession | Remove-PSSession

    $connectionModules = @(
        @{Name = "Exchange Online"; Cmd = { Connect-ExchangeOnline -UserPrincipalName $Cred.Username } },
        @{Name = "Microsoft Online"; Cmd = { Connect-MsolService } },
        @{Name = "Azure AD Preview"; Cmd = { Connect-AzureAD } },
        @{Name = "Azure Information Protection"; Cmd = { Connect-AipService } },
        @{Name = "Information Protection Service"; Cmd = { Connect-IPPSSession } }
        #@{Name = "MG Graph"; Cmd = { Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "DeviceManagementServiceConfiguration.ReadWrite.All", "DeviceManagementServiceConfig.ReadWrite.All" } },
    )

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

    Write-Host
    Write-Host "Verify your module connections. You should see no errors above and all connected below."
}

# Display summary
Write-Host
Write-Host "Module Installation/Update Summary:"
$modulesSummary | Format-Table -AutoSize

if ($connectionSummary.Count -gt 0) {
    Write-Host "Module Connection Summary:"
    $connectionSummary | Format-Table -AutoSize
}

Read-Host "`nScript execution completed. Please review the summaries above for any issues. Press Enter to continue"