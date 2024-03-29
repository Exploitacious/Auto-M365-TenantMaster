<#
#################################################
## Tenant & Exchange Configs Master v2
#################################################

This script automates a lot of the set up process of M365 Tenants and some of Exchange Online.
This script is safe to run in any stage of the tenant deployment procedure (but should be run in the begining) and should have none, if any negative end-user experience disruption if tenant already in production.


Install all modules on your powershell. Be sure to use AzureAD Preview for Connect-AzureAD.

    Connect to Exchange Online via PowerShell using MFA (Connect-ExchangeOnline)
    https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

    Connect to Azure Active Directory via PowerShell using MFA (Connect-MsolService)
    https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0

    Connect to Azure Active Directory Preview Service via Powershell using MFA (Connect-AzureAD)
    https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0

    Connect to the Microsoft Graph API Service via Powershell using MFA (Connect-MGGraph)
    https://docs.microsoft.com/en-us/graph/powershell/installation

#>

#################################################
## Variables & Options
#################################################

$AuditLogAgeLimit = 730 # This is the max retention limit for Business Premium License

$MSPName = "Umbrella"
$GroupCreatorName = "Group Creators"
$ExcludeFromCAGroup = "Exclude From CA"
$DevicePilotGroup = "Pilot-Compliance"
$AllowedAutoForwarding = "AutoForwarding-Allowed"

$BreakGlassAcccount = $MSPName + "BG"
$BGAccountPass = "Powershellisbeast8442!"

##### Optional Items: Depending on your configuration, you may or may not want to set these. Set Value to $False if you want the script to skip this step.
    
## Allow Admin to Access ALL Mailboxes in Tenant True/False
$addAdminToMailboxes = $True

## Disable Focused Inbox
$disableFocusedInbox = $True

## Delete Azure AD Devices Older than x number of days
$confirmDeletion = $True
$deletionTresholdDays = 90 

## Disable Microsoft Security Defaults in Azure
$SecurityDefaultsDisabled = $True

# Set Mailbox Language and timezone
$language = "en-US"
$timezone = "Eastern Standard Time"

# Other
$MessageColor = "Green"
$AssessmentColor = "Yellow"
$ErrorColor = "Red"
# Increase the Function Count in Powershell
$MaximumFunctionCount = 32768
# Increase the Variable Count in Powershell
$MaximumVariableCount = 32768


#################################################
## Pre-Reqs
#################################################

$Answer = Read-Host "Would you like this script to run a pre-requisite check to make sure you have all the modules correctly installed? * RECOMMENDED * (Will automatically install and updated required modules)"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Checking for Installed Modules..."


    try {
        Get-InstalledModule "AzureAD" -ErrorAction Stop
        Write-Host -ForegroundColor $ErrorColor "AzureAD (non Preview) was found. Attempting to remove before continuing."
        Get-InstalledModule -Name "AzureAD" -AllVersions | Uninstall-Module -Force
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "AzureAD (non Preview) was not detected."
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

        if ($null -eq $currentVersion) {
            Write-Host -ForegroundColor $AssessmentColor "$($CurrentModule.Name) - Installing $Module from PowerShellGallery. Version: $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)"
            try {
                Install-Module -Name $module -Force
            }
            catch {
                Write-Host -ForegroundColor $ErrorColor "Something went wrong when installing $Module. Please uninstall and try re-installing this module. (Remove-Module, Install-Module) Details:"
                Write-Host -ForegroundColor $ErrorColor "$_.Exception.Message"
            }
        }
        elseif ($CurrentModule.Version -eq $currentVersion) {
            Write-Host -ForegroundColor $MessageColor "$($CurrentModule.Name) is installed and ready. Version: ($currentVersion. Release date: $($CurrentModule.PublishedDate))"
        }
        elseif ($currentVersion.count -gt 1) {
            Write-Warning "$module is installed in $($currentVersion.count) versions (versions: $($currentVersion -join ' | '))"
            Write-Host -ForegroundColor $ErrorColor "Uninstalling previous $module versions and will attempt to update."
            try {
                Get-InstalledModule -Name $module -AllVersions | Where-Object { $_.Version -ne $CurrentModule.Version } | Uninstall-Module -Force
            }
            catch {
                Write-Host -ForegroundColor $ErrorColor "Something went wrong with Uninstalling $Module previous versions. Please Completely uninstall and re-install this module. (Remove-Module) Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
            }
        
            Write-Host -ForegroundColor $AssessmentColor "$($CurrentModule.Name) - Installing version from PowerShellGallery $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)"  
    
            try {
                Install-Module -Name $module -Force
                Write-Host -ForegroundColor $MessageColor "$Module Successfully Installed"
            }
            catch {
                Write-Host -ForegroundColor $ErrorColor "Something went wrong with installing $Module. Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
            }
        }
        else {       
            Write-Host -ForegroundColor $AssessmentColor "$($CurrentModule.Name) - Updating from PowerShellGallery from version $currentVersion to $($CurrentModule.Version). Release date: $($CurrentModule.PublishedDate)" 
            try {
                Update-Module -Name $module -Force
                Write-Host -ForegroundColor $MessageColor "$Module Successfully Updated"
            }
            catch {
                Write-Host -ForegroundColor $ErrorColor "Something went wrong with updating $Module. Details:"
                Write-Host -ForegroundColor red "$_.Exception.Message"
            }
        }
    }

    Write-Host
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Check the modules listed in the verification above. If you see an errors, please check the module(s) or restart the script to try and auto-fix."
    Write-Host "Most common error is that you have 'AzureAD' instead of 'AzureADPreview' installed. Please remove AzureAD and try again."
    Write-Host "You can re-run this part of the script as many times as necessary until all modules are up to date and correctly installed."
    Write-Host -ForegroundColor $MessageColor "You should see ALL GREEN above."
    Write-Host

} 

$Answer = Read-Host "Would you like the script to CONNECT all modules? ('N' to skip automatic module connection, if you have already done so.)"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

    Write-Host
    Write-Host -ForegroundColor $MessageColor "Enter your Tenant's Global Admin Credentials - You may see the PS credential prompt pop-up behind this window."
    Write-Host -ForegroundColor $AssessmentColor "You may be asked to sign in multiple times as each module loads and connects."

    $Cred = Get-Credential

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Removing old Powershell Sessions and establishing new ones..."
    Get-PSSession | Remove-PSSession

    # Exchange
    Connect-ExchangeOnline -UserPrincipalName $Cred.Username
    Write-Host -ForegroundColor $MessageColor "Exchange Online Connected!"
    Write-Host

    # MSOnlinePreview
    Connect-MsolService -Credential $Cred -AzureEnvironment AzureCloud
    Write-Host -ForegroundColor $MessageColor "Microsoft Online Connected!"
    Write-Host

    # AzureAD Preview
    Connect-AzureAD 
    Write-Host -ForegroundColor $MessageColor "Azure AD Preview Powershell Connected!"
    Write-Host

    # MS.Graph Management
    Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "DeviceManagementServiceConfiguration.ReadWrite.All", "DeviceManagementServiceConfig.ReadWrite.All"
    Write-Host -ForegroundColor $MessageColor "MG Graph Management Connected!"
    Write-Host

    # Azure Information Protection
    Connect-AipService
    Write-Host -ForegroundColor $MessageColor "Azure Information Protection Connected!"
    Write-Host

    # Information Protection Service
    Connect-IPPSSession
    Write-Host -ForegroundColor $MessageColor "Information Protection Service Connected!"            
    Write-Host

    # MSGRAPH (Old School)
    Connect-MSGraph
    Write-Host -ForegroundColor $MessageColor "MS Graph Service Connected!"
    Write-Host

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Verify your module connections. You should see all green above with no errors."

}

$Answer = Read-Host "Are you ready to configure your Microsoft 365 Environment? (Y / N)"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {


    #################################################
    ## Let the Scripting Begin!
    #################################################

    ## Set a few more variables

    $SharedMailboxes = Get-Mailbox -ResultSize Unlimited -Filter { RecipientTypeDetails -Eq "SharedMailbox" }
    $CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
    $OrgConfig = Get-OrganizationConfig 
    $DefaultDomain = Get-AcceptedDomain | Where-Object { $_.Default -eq 'True' }
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
    $PasswordProfile.Password = $BGAccountPass
    $GlobalAdmin = $Cred.UserName #Do not change this here. You will be prompted to input your Admin Account later in the script if you elect not to log in with PSCred 
    $BreakGlassAccountUPN = "$BreakGlassAcccount" + "@" + "$DefaultDomain"

    if ($null -eq $GlobalAdmin) {
        Write-Host
        Write-Host
        $GlobalAdmin = Read-Host "Please enter your Tenant's Global Admin Full E-Mail Address or User Principal Name"
    }


    # Enable Organization Customization Features
    Write-Host
    Enable-OrganizationCustomization -ErrorAction SilentlyContinue
    Write-Host
    Enable-AipService -ErrorAction SilentlyContinue
    Write-Host
    Write-Host "Organization Customization & AIP are enabled!"
    Write-Host

    ## Disable Microsoft Security Defaults in Azure
    if ($SecurityDefaultsDisabled -eq $True) {
        Import-Module Microsoft.Graph.Identity.SignIns
        $params = @{
            IsEnabled = $false
        }
        Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
        Write-Host
        Write-Host -ForegroundColor $MessageColor "Microsoft Security Defaults in Azure have been disabled!"
        Write-Host -ForegroundColor $AssessmentColor "Make sure you enable Conditional Access Policies!"
    }
    else {
        Write-Host -ForegroundColor $MessageColor "Leaving Microsoft Security Defaults as Default!"
    }

    Write-Host
    Write-Host

    ## New Security Groups and BG User for easier management purposes

    # Create Group Exclude From CA
    try {
        $SearchCAGroupID = Get-MsolGroup -SearchString "$ExcludeFromCAGroup" | Select-Object ObjectId
        Write-Host "Starting Query"
        Get-MsolGroup -ObjectId $SearchCAGroupID.ObjectId -ErrorAction Stop
    } 
    catch [System.Management.Automation.RuntimeException] {
        Write-Host -ForegroundColor $MessageColor "Creating New Group - $ExcludeFromCAGroup"
        New-AzureADGroup -DisplayName $ExcludeFromCAGroup -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Users Excluded from any Conditional Access Policies"
    }
           
    # Create Group Device Pilot Group
    try {
        $SearchDPGroupID = Get-MsolGroup -SearchString "$DevicePilotGroup" | Select-Object ObjectId
        Get-MsolGroup -ObjectId $SearchDPGroupID.ObjectId -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-Host -ForegroundColor $MessageColor "Creating New Group - $DevicePilotGroup"
        New-AzureADGroup -DisplayName $DevicePilotGroup -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Intune Device Pilot Group for Testing and Deployment"
    }

    # Create Allowed Auto-Forwarding Group
    try {
        $SearchFAGroupID = Get-MsolGroup -SearchString "$AllowedAutoForwarding" | Select-Object ObjectId
        Get-MsolGroup -ObjectId $SearchFAGroupID.ObjectId -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-Host -ForegroundColor $MessageColor "Creating New Group - $AllowedAutoForwarding"
        New-DistributionGroup -Name $AllowedAutoForwarding -DisplayName $AllowedAutoForwarding -PrimarySmtpAddress $AllowedAutoForwarding@$DefaultDomain -Type "Security" -MemberJoinRestriction "Closed" -Notes "Users Allowed to set Auto-Forwarding Rules in Exchange Online"
    }

    # Create Group Creators Security Group
    try {
        $SearchGCGroupID = Get-MsolGroup -SearchString "$GroupCreatorName" | Select-Object ObjectId
        Get-MsolGroup -ObjectId $SearchGCGroupID.ObjectId -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-Host -ForegroundColor $MessageColor "Creating New Group - $GroupCreatorName"
        New-AzureADGroup -DisplayName $GroupCreatorName -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Users Allowed to create M365 and Teams Groups"
    }

    # Create Break-Glass User & make it an Admin
    try {
        $SearchBGUserID = Get-MsolUser -SearchString "$BreakGlassAcccount" | Select-Object ObjectId
        Get-MsolUser -ObjectId $SearchBGUserID.ObjectId -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-Host -ForegroundColor $MessageColor "Creating New User - $BreakGlassAcccount"

        New-AzureADUser -AccountEnabled $True -DisplayName "$MSPName Break-Glass" -PasswordProfile $PasswordProfile -MailNickName "$BreakGlassAcccount" -UserPrincipalName $BreakGlassAccountUPN
            
        $BGUserID = Get-AzureADUser -SearchString $BreakGlassAcccount | Select-Object -ExpandProperty ObjectId

        $Role = Get-AzureADDirectoryRole | Where-Object { $_.displayName -eq "Global Administrator" }
        Add-AzureADDirectoryRoleMember -ObjectId $Role.ObjectId -RefObjectId $BGUserID.ObjectId
    }


    Write-Host -ForegroundColor $MessageColor "Users and Groups have been created. Please allow the script to idle for about 2 minutes before continuing."
    Write-Host "This will allow the new users and groups to settle in and make their UID's availble for us. You can end this script here and come back later if necessary."

    # Timeout to let the groups and users settle in
    Start-Sleep -Seconds 120

    # Re-Setup User and Group Object ID Variables

    $GlobalAdminUserID = Get-AzureADUser -SearchString $GlobalAdmin | Select-Object -ExpandProperty ObjectId
    $BGUserID = Get-AzureADUser -SearchString $BreakGlassAcccount | Select-Object -ExpandProperty ObjectId

    $SearchCAGroupID = Get-MsolGroup -SearchString "$ExcludeFromCAGroup" | Select-Object -ExpandProperty ObjectId
    $SearchDPGroupID = Get-MsolGroup -SearchString "$DevicePilotGroup" | Select-Object -ExpandProperty ObjectId
    $SearchFAGroupID = Get-MsolGroup -SearchString "$AllowedAutoForwarding" | Select-Object -ExpandProperty ObjectId
    $SearchGCGroupID = Get-MsolGroup -SearchString "$GroupCreatorName" | Select-Object -ExpandProperty ObjectId
        

    Write-Host "Groups have been created. Adding Admin users to groups."

    # Exclude from CA - Add BGAdmin
    try {
        Add-AzureADGroupMember -ObjectId $SearchCAGroupID -RefObjectId $BGUserID
        Write-Host -ForegroundColor $MessageColor "Adding $BreakGlassAccountUPN to Group $ExcludeFromCAGroup"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$BreakGlassAccountUPN is already a member of $ExcludeFromCAGroup"
    }

    # Pilot Device Group - Add BGAdmin & Global Admin
    try {
        Add-AzureADGroupMember -ObjectId $SearchDPGroupID -RefObjectId $BGUserID
        Write-Host -ForegroundColor $MessageColor "Adding $BreakGlassAccountUPN to Group $DevicePilotGroup"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$BreakGlassAccountUPN is already a member of $DevicePilotGroup"
    }

    try {
        Add-AzureADGroupMember -ObjectId $SearchDPGroupID -RefObjectId $BGlobalAdminUser
        Write-Host -ForegroundColor $MessageColor "Adding $GlobalAdmin to Group $DevicePilotGroup"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$GlobalAdmin is already a member of $DevicePilotGroup"
    }

    # Group Creators Group - Add BGAdmin and Global Admin
    try {
        Add-AzureADGroupMember -ObjectId $SearchGCGroupID -RefObjectId $BGUserID
        Write-Host -ForegroundColor $MessageColor "Adding $BreakGlassAcccount to Group $GroupCreatorName"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$BreakGlassAcccount is already a member of $GroupCreatorName"
    }
        
    try {
        Add-AzureADGroupMember -ObjectId $SearchGCGroupID -RefObjectId $BGlobalAdminUser
        Write-Host -ForegroundColor $MessageColor "Adding $GlobalAdmin to Group $GroupCreatorName"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$GlobalAdmin is already a member of $GroupCreatorName"
    }
            
    # Allowed Email Forwarding Group - Add Global Admin
    try {
        Add-AzureADGroupMember -ObjectId $SearchFAGroupID -RefObjectId $GlobalAdminUserID
        Write-Host -ForegroundColor $MessageColor "Adding $GlobalAdmin to Group $AllowedAutoForwarding"
    }
    catch {
        Write-Host -ForegroundColor $MessageColor "$GlobalAdmin is already a member of $AllowedAutoForwarding"
    }
                
    Write-Host
    Write-Host

    ## Create a new EOP/Azure Admin Role with all available admin permissions and add the Admin accounts to it
    $Roles = @(
        "Attack Simulator Admin",
        "Audit Logs",
        "Billing Admin",
        "Case Management",
        "Communication",
        "Communication Compliance Admin",
        "Compliance Administrator",
        "Compliance Manager Administration",
        "Compliance Search",
        "Custodian",
        "Data Classification Content Viewer",
        "Data Classification Feedback Provider",
        "Data Classification Feedback Reviewer",
        "Data Classification List Viewer",
        "Data Connector Admin",
        "Data Investigation Management",
        "Device Management",
        "Disposition Management",
        "DLP Compliance Management",
        "Export",
        "Hold",
        "IB Compliance Management",
        "Information Protection Admin",
        "Insider Risk Management Admin",
        "Knowledge Admin",
        "Manage Alerts",
        "MyBaseOptions",
        "Organization Configuration",
        "Preview",
        "Privacy Management Admin",
        "Quarantine",
        "RecordManagement",
        "Retention Management",
        "Review",
        "RMS Decrypt",
        "Role Management",
        # "Search And Purge", this one's broken or something
        "Security Administrator",
        "Sensitivity Label Administrator",
        "Service Assurance View",
        "Subject Rights Request Admin",
        "Supervisory Review Administrator",
        "Tag Manager",
        "Tenant AllowBlockList Manager"
    )

    $Members = @(
        "$GlobalAdmin",
        "$BreakGlassAccountUPN"
    )

    try {
        Get-RoleGroup "$MSPName Super Admin" -ErrorAction Stop
    }
    catch {
        New-RoleGroup -Name "$MSPName Super Admin" -DisplayName "$MSPName Super Admin" -Description "Includes All Standard EOP Admin Roles for $MSPName" -Roles $Roles -Members $Members
        Write-Host -ForegroundColor $MessageColor "'$MSPName Super Admin' Role Group created"
    }


    ## Enable Send-from-Alias Preview Feature
    if ($OrgConfig.SendFromAliasEnabled) {
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Send-From-Alias for Exchange Online is already enabled"
    }
    else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Send-From-Alias for Exchange online is not enabled... enabling now"
        Write-Host 
        Set-OrganizationConfig -SendFromAliasEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Send-From-Alias is now enabled"
    }


    ## Turn Off Focused Inbox Mode
    if ($disableFocusedInbox -eq $true) {
        Set-OrganizationConfig -FocusedInboxOn $false
        Write-Host -ForegroundColor $MessageColor "Focused Inbox has been disabled across the entire Organization"
        Write-Host
        Write-Host
    }
    else {
        Write-Output "Skipping disable Focus Inbox on mailboxes..."
    }

    ## Enable Naming Scheme for Distribution Lists
    Set-OrganizationConfig -DistributionGroupNamingPolicy "DL_<GroupName>"
    Write-Host -ForegroundColor $MessageColor "Enabled Naming Scheme for Distribution Lists: 'DL_<GroupName>'"

    ## Enable Plus Addressing
    #    Set-OrganizationConfig -AllowPlusAddressInRecipients $True
    Set-OrganizationConfig -DisablePlusAddressInRecipients $False
    Write-Host -ForegroundColor $MessageColor "Plus Addressing Enabled. Find out more here: https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/plus-addressing-in-exchange-online"

    ## Enable (Not Annoying) Available Mail-Tips for Office 365
    Set-OrganizationConfig -MailTipsAllTipsEnabled $True
    Set-OrganizationConfig -MailTipsExternalRecipientsTipsEnabled $False
    Set-OrganizationConfig -MailTipsGroupMetricsEnabled $True
    Set-OrganizationConfig -MailTipsMailboxSourcedTipsEnabled $True
    Set-OrganizationConfig -MailTipsLargeAudienceThreshold $True
    Set-OrganizationConfig -MailTipsLargeAudienceThreshold "10"
    Write-Host -ForegroundColor $MessageColor "All Mail-Tip Features Enabled"

    ## Enable Read Email Tracking
    Set-OrganizationConfig -ReadTrackingEnabled $True
    Write-Host -ForegroundColor $MessageColor "Email Read-Tracking Enabled"

    ## Enable Public Computer Detection (For OWA)
    Set-OrganizationConfig -PublicComputersDetectionEnabled $True
    Write-Host -ForegroundColor $MessageColor "Public Computer Tracking is enabled"

    ## Disable Outlook Pay (Microsoft Pay)
    Set-OrganizationConfig -OutlookPayEnabled $False
    Write-Host -ForegroundColor $MessageColor "Outlook Pay (Microsoft Pay) is disabled"

    ## Enable Lean Pop-Outs for OWA in Edge
    Set-OrganizationConfig -LeanPopoutEnabled $True
    Write-Host -ForegroundColor $MessageColor "Lean Pop-Outs for OWA in Edge are Enabled"
            
    ## Enable Outlook Events Recognition
    Set-OrganizationConfig -EnableOutlookEvents $True
    Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -LocalEventsEnabled $True
    Write-Host -ForegroundColor $MessageColor "Outlook Events Tracking is Enabled"

    ## Disable Feedback in Outlook Online
    Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -FeedbackEnabled $False
    Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -UserVoiceEnabled $false
    Write-Host -ForegroundColor $MessageColor "Feedback & User Voice in OWA is disabled"


    ## Check if Intune is MDM Authority. If not, set it.
    $mdmAuth = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/organization('$OrgId')?`$select=mobiledevicemanagementauthority" -HttpMethod Get -ErrorAction Stop).mobileDeviceManagementAuthority
    if ($mdmAuth -notlike "intune") {
        Write-Progress -Activity "Setting Intune as the MDM Authority" -Status "..."
        $OrgID = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization" -HttpMethod Get -ErrorAction Stop).value.id
        Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization/$OrgID/setMobileDeviceManagementAuthority" -HttpMethod Post -ErrorAction Stop
    }
    Write-Host -ForegroundColor $MessageColor "Intune is set as the MDM Authority"
    Write-Host


    ## Enable Modern Authentication
    if ($OrgConfig.OAuth2ClientProfileEnabled) {
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Modern Authentication for Exchange Online is already enabled"
    }
    else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Modern Authentication for Exchange online is not enabled... enabling now"
        Write-Host 
        Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Modern Authentication is now enabled"
    }


    ## Delete all devices not contacted system in set number of days
    if ($confirmDeletion -eq $true) {

        $deletionTreshold = (Get-Date).AddDays(-$deletionTresholdDays)
        $allDevices = Get-AzureADDevice -All:$true | Where-Object { $_.ApproximateLastLogonTimeStamp -le $deletionTreshold }

        $exportPath = $(Join-Path $PSScriptRoot "AzureADDeviceExport_$DefaultDomain $(Get-Date -f yyyy-MM-dd).csv")
        $allDevices | Select-Object -Property DisplayName, ObjectId, ApproximateLastLogonTimeStamp, DeviceOSType, DeviceOSVersion, IsCompliant, IsManaged `
        | Export-Csv -Path $exportPath -UseCulture -NoTypeInformation

        $allDevices | ForEach-Object {
            Write-Output "Removing device $($PSItem.ObjectId)"
            Remove-AzureADDevice -ObjectId $PSItem.ObjectId
        }    

        Write-Output "Find report with all deleted devices under: $exportPath"
        Write-Host
        Write-Host


        ## Allow Admin to Access all Mailboxes in Tenant
        if ($addAdminToMailboxes -eq $true) {
            Write-Host -ForegroundColor $AssessmentColor ""
            Get-Mailbox -ResultSize unlimited -Filter { (RecipientTypeDetails -eq 'UserMailbox') -and (Alias -ne 'Admin') } | Add-MailboxPermission -User $GlobalAdmin -AutoMapping:$false -AccessRights fullaccess -InheritanceType all
            Get-Mailbox -ResultSize unlimited -Filter { (RecipientTypeDetails -eq 'UserMailbox') -and (Alias -ne 'Admin') } | Add-MailboxPermission -User $BreakGlassAccountUPN -AutoMapping:$false -AccessRights fullaccess -InheritanceType all
            Write-Host
            Write-Host -ForegroundColor $MessageColor "Access to all mailboxes has been granted to the Global Admin account supplied"
            Write-Host
        }
        else {
            Write-Output "Skipping add admin to all mailboxes..."
        }


        ## Set Time and language on all mailboxes to Set Timezone and English-USA
        Write-Host -ForegroundColor $AssessmentColor "Configuring Date/Time and Locale settings for each mailbox"
        Write-Host -ForegroundColor $MessageColor "The script may hang at this step for a while. Do not interrupt or close it."


        Get-Mailbox -ResultSize unlimited | ForEach-Object {
            Set-MailboxRegionalConfiguration -Identity $PsItem.alias -Language $language -TimeZone $timezone
        }
            
        Write-Host
        Write-Host -ForegroundColor $MessageColor "Time, Date and Locale configured for each mailbox"


        ## Disable Group Creation unless User is member of 'Group Creators' Group

        $AllowGroupCreation = $False
            
        Write-Host -ForegroundColor $AssessmentColor "Configuring Group for those allowed to create O365 Groups"

        $settingsObjectID = (Get-AzureADDirectorySetting | Where-Object -Property Displayname -Value "Group.Unified" -EQ).id
        if (!$settingsObjectID) {
            $template = Get-AzureADDirectorySettingTemplate | Where-Object { $_.displayname -eq "group.unified" }
            $settingsCopy = $template.CreateDirectorySetting()
            New-AzureADDirectorySetting -DirectorySetting $settingsCopy
            $settingsObjectID = (Get-AzureADDirectorySetting | Where-Object -Property Displayname -Value "Group.Unified" -EQ).id
        }

        $settingsCopy = Get-AzureADDirectorySetting -Id $settingsObjectID
        $settingsCopy["EnableGroupCreation"] = $AllowGroupCreation

        if ($GroupName) {
            $settingsCopy["GroupCreationAllowedGroupId"] = (Get-AzureADGroup -SearchString $GroupName).objectid
        }
        else {
            $settingsCopy["GroupCreationAllowedGroupId"] = $GroupName
        }

        Set-AzureADDirectorySetting -Id $settingsObjectID -DirectorySetting $settingsCopy

            (Get-AzureADDirectorySetting -Id $settingsObjectID).Values
            
        Write-Host -ForegroundColor $MessageColor "Only members of the 'Group Creators' group will be able to create groups within the Tenant"
        Write-Host
        Write-Host


        ## Block Consumer Storage in OWA
        $OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
        if ($OwaPolicy.AdditionalStorageProvidersAvailable) {
            Write-Host 
            Write-Host -ForegroundColor $AssessmentColor "Connecting consumer storage locations like GoogleDrive and OneDrive (personal) are currently enabled by the default OWA policy"
            Write-Host 
            Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "Consumer storage locations like GoogleDrive and OneDrive (personal) are now disabled"
            Write-Host
            Write-Host
        }
        Else {
            Write-Host
            Write-Host
            Write-Host -ForegroundColor $MessageColor "Consumer storage locations like GoogleDrive and OneDrive (personal) are already disabled"
            Write-Host
            Write-Host
        }


        ## Disable Shared Mailbox Logon
        $SharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox
        Foreach ($user in $SharedMailboxes) {
            Set-MsolUser -UserPrincipalName $user.UserPrincipalName -BlockCredential $true 
        }
        Write-Host -ForegroundColor $MessageColor "Shared Mailboxes will be blocked from interactive logon"
        Write-Host
        Write-Host
     

        ## Block Attachment Download on Unmanaged Assets OWA
        $OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
        if ($OwaPolicy.ConditionalAccessPolicy -eq 'Off') {
            Write-Host 
            Write-Host -ForegroundColor $AssessmentColor "Attachment download is currently enabled for unmanaged devices by the default OWA policy"
            Write-Host 
            Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -ConditionalAccessPolicy ReadOnly
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "Attachment download on unmanaged devices is now disabled"
            Write-Host
            Write-Host
        }
        Else {
            Write-Host
            Write-Host -ForegroundColor $MessageColor "Attachment download on unmanaged devices is already disabled"
            Write-Host
            Write-Host
        }


        ## Set Retention Limit on deleted items
        Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
        $CurrentRetention | Group-Object | Select-Object name, count | Format-Table

        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
        Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Deleted items will be retained for the maximum of 30 days for all mailboxes"
        Write-Host
        Write-Host


        ## Enable Unified Audit Log Search
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Enabling Unified Audit Log"
        Write-Host
        $AuditLogConfig = Get-AdminAuditLogConfig
        if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
            Write-Host
            Write-Host
        }
        else {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled"
            Write-Host
            Write-Host
        }


        ## Configure the audit log retention limit on all mailboxes

        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Configuring Audit Log Retention"
        Set-OrganizationConfig -AuditDisabled $False
        Write-Host
       
        if ($null -eq $AuditLogAgeLimit -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no') {
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The audit log age limit is already enabled"
        }
        else {
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
            Write-Host
            Write-Host
            ## Enable all mailbox auditing actions
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add = "Copy", "Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules", "UpdateCalendarDelegation" }
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditDelegate @{Add = "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules" }
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditOwner @{Add = "Create", "HardDelete", "Move", "Mailboxlogin", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules", "UpdateCalendarDelegation" }
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "All auditing actions are now enabled on all mailboxes"
            Write-Host
            Write-Host
        }  
        


        ## Set up Archive Mailbox and Legal Hold for all available users (Must have Proper Licensing from Microsoft)

        $Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? (Recommended)"
        if ($Answer -eq 'y' -or $Answer -eq 'yes') {

            ## Check whether the auto-expanding archive feature is enabled, and if not, enable it
            $OrgConfig = Get-OrganizationConfig 
            if ($OrgConfig.AutoExpandingArchiveEnabled) {
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is already enabled"
                Write-Host
                Write-Host
            }
            else {
                Set-OrganizationConfig -AutoExpandingArchive
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is now enabled"
                Write-Host
                Write-Host
            }

            ## Prompt whether or not to enable the Archive mailbox for all users
            Write-Host 
            $ArchiveAnswer = Read-Host "Do you want to enable the Archive mailbox for all user mailboxes? Y or N (Recommended)"
            if ($ArchiveAnswer -eq 'y' -or $ArchiveAnswer -eq 'yes') {
                Get-Mailbox -ResultSize Unlimited -Filter { ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox" } | Enable-Mailbox -Archive
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "The Archive mailbox has been enabled for all user mailboxes"
                Write-Host
                Write-Host
            }
            Else {
                Write-Host 
                Write-Host -ForegroundColor $AssessmentColor "The Archive mailbox will not be enabled for all user mailboxes"
                Write-Host
                Write-Host
            }

            ## Prompt whether or not to enable Litigation Hold for all mailboxes
            Write-Host 
            $LegalHoldAnswer = Read-Host "Do you want to enable Litigation Hold for all mailboxes? Type Y or N and press Enter to continue. NOTE: Requires Exchange Online Plan 2. You can hit Y and ligitation will be attempted to be enabled, but the process might fail because ExoPlan2 is not available. This is non-destructve and you can continue/restart the script."
            if ($LegalHoldAnswer -eq 'y' -or $LegalHoldAnswer -eq 'yes') {
                Get-Mailbox -ResultSize Unlimited -Filter { LitigationHoldEnabled -Eq "False" -AND RecipientTypeDetails -ne "DiscoveryMailbox" } | Set-Mailbox -LitigationHoldEnabled $True
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "Litigation Hold has been enabled for all mailboxes"
                Write-Host
                Write-Host
            }
            Else {
                Write-Host 
                Write-Host -ForegroundColor $AssessmentColor "Litigation Hold will not be enabled for all mailboxes"
                Write-Host
                Write-Host
            }

        }
        Else {
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "Archiving and Litigation Hold will not be configured"
            Write-Host
            Write-Host
        }

        # Terminate any existing management sessions
        #   Get-PSSession | Remove-PSSession

        Write-Host -ForegroundColor $MessageColor "This concludes the script for Baseline Tenant Configs"

    }
}

    