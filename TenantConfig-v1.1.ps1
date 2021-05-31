<#
#################################################
## Tenant & Exchange Configs Master v1.1
#################################################

This script automates a lot of the set up process of M365 Tenants and Exchange Online.
This script is safe to run in any stage of the tenant deployment procedure and should have none, if any negative end-user experience disruption if it's already in production.

The following items will be configured automatically:

- Set Intune as MDM Authority
- Enable Modern Authentication (non-destructive and will leave legacy turned on)
- Delete all intune devices that haven't contacted the tenant in x days (90 is default)
- Turn Off Focused Inbox Mode Organization-Wide
- Set Time and language on all mailboxes to Eastern Standard, English USA
- Allow Admin to Access all Mailboxes in Tenant
- Disable Group Creation unless User is member of 'Group Creators' Group
  - Creates new group called "Group Creators" and adds specified Global Admin as member
- Block Consumer Storage in OWA
- Disable Shared Mailbox Interractive Logon
- Block Attachment Download on Unmanaged Assets OWA (Only works after correstponding CA POLICY IS ENABLED)
- Set Retention Limit on deleted items (Default 36 Days)
- Enable Unified Audit Logging and search
- Configure the audit log retention limit on all mailboxes (2 Years)
- Set up Archive Mailbox and Legal Hold for all available users (if licensing allows)


Install all modules on your powershell. Be sure to use AzureAD Preview for Connect-AzureAD.


    Connect to Exchange Online via PowerShell using MFA (Connect-ExchangeOnline)
    https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

    Connect to Azure Active Directory via PowerShell using MFA (Connect-MsolService)
    https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0

    Connect to Azure Active Directory Preview Service via Powershell using MFA (Connect-AzureAD)
    https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0

    Connect to the Microsoft Graph API Service via Powershell using MFA (Connect-MSGraph)

#>


#################################################
## Pre-Reqs
#################################################

$Answer = Read-Host "Would you like this script to configure your Microsoft 365 Environment, and do you have AzureAD Preview Installed?"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {

    $Answer = Read-Host "Have you connected all the required PowerShell CMDlets? (ExchangeOnline, MSOLService, MSGraph, AzureAD-Preview) Y or N"
        if ($Answer -eq 'N' -or $Answer -eq 'no') {

        Connect-ExchangeOnline

        Connect-MsolService

        Connect-MSGraph

        Connect-AzureAD

        } else {

#################################################
## Variables
#################################################

        $AuditLogAgeLimit = 730
        $GroupCreatorName = "Group Creators"
        $deletionTresholdDays= 90

        $MessageColor = "Green"
        $AssessmentColor = "Yellow"

        $AlertAddress = Read-Host "Enter the Customer's Tenant GLOBAL ADMIN EMAIL ADDRESS. This is where you will recieve alerts, notifications and set up admin access to all mailboxes. MUST BE AN INTERNAL ADMIN ADDRESS"
        $MSPForwardingAddress = Read-Host "Enter your administrative alerting address where you would like to receive alerts and communication regarding this tenant"

        $SharedMailboxes = Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -Eq "SharedMailbox"}
        $CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
                

#################################################
## Let the Scripting Begin!
#################################################

    ## Check if Intune is MDM Authority. If not, set it.
            $mdmAuth = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/organization('$OrgId')?`$select=mobiledevicemanagementauthority" -HttpMethod Get -ErrorAction Stop).mobileDeviceManagementAuthority
            if($mdmAuth -notlike "intune")            {                Write-Progress -Activity "Setting Intune as the MDM Authority" -Status "..."                $OrgID = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization" -HttpMethod Get -ErrorAction Stop).value.id                Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization/$OrgID/setMobileDeviceManagementAuthority" -HttpMethod Post -ErrorAction Stop            }
            Write-Host -ForegroundColor $MessageColor "Intune is set as the MDM Authority"
            Write-Host


    ## Enable Modern Authentication
            $OrgConfig = Get-OrganizationConfig 
             if ($OrgConfig.OAuth2ClientProfileEnabled) {
                 Write-Host 
                 Write-Host -ForegroundColor $MessageColor "Modern Authentication for Exchange Online is already enabled"
             } else {
                Write-Host
                Write-Host -ForegroundColor $AssessmentColor "Modern Authentication for Exchange online is not enabled... enabling now"
                Write-Host 
                Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "Modern Authentication is now enabled"
             }


    ## Turn Off Focused Inbox Mode
            Set-OrganizationConfig -FocusedInboxOn $false
            Write-Host -ForegroundColor $MessageColor "Focused Inbox has been disabled across the entire Organization"
            Write-Host
            Write-Host


    ## Delete all devices not contacted system in 90 days
            $deletionTreshold= (Get-Date).AddDays(-$deletionTresholdDays)
            $allDevices=Get-AzureADDevice -All:$true | Where-Object {$_.ApproximateLastLogonTimeStamp -le $deletionTreshold}
            $exportPath=$(Join-Path $PSScriptRoot "AzureADDeviceExport.csv")
            $allDevices | Select-Object -Property DisplayName, ObjectId, ApproximateLastLogonTimeStamp, DeviceOSType, DeviceOSVersion, IsCompliant, IsManaged `
            | Export-Csv -Path $exportPath -UseCulture -NoTypeInformation

            Write-Output "Find report with all devices under: $exportPath"
            $confirmDeletion=$null

            while ($confirmDeletion -notmatch "[y|n]"){
                $confirmDeletion = Read-Host "Delete all Azure AD devices which haven't contacted your tenant since $deletionTresholdDays days (Y/N)"
            }
            if ($confirmDeletion -eq "y"){
                $allDevices | ForEach-Object {
                    Write-Output "Removing device $($PSItem.ObjectId)"
                    Remove-AzureADDevice -ObjectId $PSItem.ObjectId
                }
            } else {
                Write-Output "Skipping devie deletion, continuing script..."
            }


    ## Allow Admin to Access all Mailboxes in Tenant
            Get-Mailbox -ResultSize unlimited -Filter {(RecipientTypeDetails -eq 'UserMailbox') -and (Alias -ne 'Admin')} | Add-MailboxPermission -User $AlertAddress -AutoMapping:$false -AccessRights fullaccess -InheritanceType all
            Write-Host
            Write-Host -ForegroundColor $MessageColor "Access to all mailboxes has been granted to the Global Admin account supplied"
            Write-Host


    ## Set Time and language on all mailboxes to Eastern Standard, English USA
            Get-Mailbox -ResultSize unlimited -RecipientTypeDetails UserMailbox | Foreach-Object {
                Set-MailboxRegionalConfiguration -Identity $PsItem.alias -Language "en-US" -TimeZone "Eastern Standard Time"
            }


    ## Disable Group Creation unless User is member of 'Group Creators' Group

            New-AzureADGroup -DisplayName $GroupCreatorName -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Users allowed to create M365 groups"

            $AllowGroupCreation = $False
            $GroupCreatorsGroup = Get-AzureADGroup -SearchString $GroupCreatorName
            $GroupCreatorsID = $GroupCreatorsGroup.ObjectID
            $GroupCreatorMember = Get-MsolUser -UserPrincipalName $AlertAddress
            $GroupCreatorMemberID = $GroupCreatorMember.ObjectID

            Add-AzureADGroupMember -ObjectID $GroupCreatorsID -RefObjectId $GroupCreatorMemberID
            
            $settingsObjectID = (Get-AzureADDirectorySetting | Where-object -Property Displayname -Value "Group.Unified" -EQ).id
            if(!$settingsObjectID)
                {
                    $template = Get-AzureADDirectorySettingTemplate | Where-object {$_.displayname -eq "group.unified"}
                    $settingsCopy = $template.CreateDirectorySetting()
                    New-AzureADDirectorySetting -DirectorySetting $settingsCopy
                    $settingsObjectID = (Get-AzureADDirectorySetting | Where-object -Property Displayname -Value "Group.Unified" -EQ).id
                }

            $settingsCopy = Get-AzureADDirectorySetting -Id $settingsObjectID
            $settingsCopy["EnableGroupCreation"] = $AllowGroupCreation

            if($GroupName) {
                  $settingsCopy["GroupCreationAllowedGroupId"] = (Get-AzureADGroup -SearchString $GroupName).objectid
            } else {
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
                    }  Else {
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
                } Else {
                Write-Host
                Write-Host -ForegroundColor $MessageColor "Attachment download on unmanaged devices is already disabled"
                Write-Host
                Write-Host
            }


    ## Set Retention Limit on deleted items
            Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
            $CurrentRetention | group | select name, count | ft

            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
            Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "Deleted items will be retained for the maximum of 30 days for all mailboxes"
            Write-Host
            Write-Host


    ## Enable Unified Audit Log Search
            $AuditLogConfig = Get-AdminAuditLogConfig
            if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
                Write-Host
                Write-Host
            } else {
                    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                    Write-Host 
                    Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled"
                    Write-Host
                    Write-Host
                }


    ## Configure the audit log retention limit on all mailboxes       
            if ($AuditLogAgeLimit -eq $null -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no'){
                Write-Host
                Write-Host -ForegroundColor $MessageColor "The audit log age limit is already at best-practice"
            } else {
                Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
                Write-Host 
                Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
                Write-Host
                Write-Host
                ## Enable all mailbox auditing actions
                Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add="Copy","Create","FolderBind","HardDelete","MessageBind","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
                Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditDelegate @{Add="Create","FolderBind","HardDelete","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules"}
                Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditOwner @{Add="Create","HardDelete","Move","Mailboxlogin","MoveToDeletedItems","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
                Write-Host 
                Write-host -ForegroundColor $MessageColor "All auditing actions are now enabled on all mailboxes"
                Write-Host
                Write-Host
                }  
        


    ## Set up Archive Mailbox and Legal Hold for all available users (Must have Proper Licensing from Microsoft)

            $Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? NOTE: Requires Exchange Online Plan 2 or Exchange Online Archiving add-on; Y or N "
            if($Answer -eq 'y' -or $Answer -eq 'yes') {

            ## Check whether the auto-expanding archive feature is enabled, and if not, enable it
                $OrgConfig = Get-OrganizationConfig 
                 if ($OrgConfig.AutoExpandingArchiveEnabled) {
                    Write-Host 
                    Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is already enabled"
                    Write-Host
                    Write-Host
                 } else {
                    Set-OrganizationConfig -AutoExpandingArchive
                    Write-Host 
                    Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is now enabled"
                    Write-Host
                    Write-Host
                 }

            ## Prompt whether or not to enable the Archive mailbox for all users
                Write-Host 
                $ArchiveAnswer = Read-Host "Do you want to enable the Archive mailbox for all user mailboxes? Y or N "
                if ($ArchiveAnswer -eq 'y'-or $ArchiveAnswer -eq 'yes') {
                    Get-Mailbox -ResultSize Unlimited -Filter {ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox"} | Enable-Mailbox -Archive
                    Write-Host 
                    Write-Host -ForegroundColor $MessageColor "The Archive mailbox has been enabled for all user mailboxes"
                    Write-Host
                    Write-Host
                } Else {
                    Write-Host 
                    Write-Host -ForegroundColor $AssessmentColor "The Archive mailbox will not be enabled for all user mailboxes"
                    Write-Host
                    Write-Host
                }

            ## Prompt whether or not to enable Litigation Hold for all mailboxes
                Write-Host 
                $LegalHoldAnswer = Read-Host "Do you want to enable Litigation Hold for all mailboxes? Type Y or N and press Enter to continue. NOTE: Requires Exchange Online Plan 2. You can hit Y and ligitation will be attempted to be enabled, but the process might fail because ExoPlan2 is not available. This is non-destructve and you can continue/restart the script."
                if ($LegalHoldAnswer -eq 'y' -or $LegalHoldAnswer -eq 'yes') {
                    Get-Mailbox -ResultSize Unlimited -Filter {LitigationHoldEnabled -Eq "False" -AND RecipientTypeDetails -ne "DiscoveryMailbox"} | Set-Mailbox -LitigationHoldEnabled $True
                    Write-Host 
                    Write-Host -ForegroundColor $MessageColor "Litigation Hold has been enabled for all mailboxes"
                    Write-Host
                    Write-Host
                } Else {
                    Write-Host 
                    Write-Host -ForegroundColor $AssessmentColor "Litigation Hold will not be enabled for all mailboxes"
                    Write-Host
                    Write-Host
            }

            } Else {
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "Archiving and Litigation Hold will not be configured"
            Write-Host
            Write-Host
            }

<#

This makes more sense to be enabled in the ATP script.

        ## Reset Forwarding on Customer's Admin Account to MSP
                Write-Host
                Set-Mailbox -Identity $AlertAddress -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $MSPForwardingAddress
                Write-Host
                Write-Host
                Write-Host -ForegroundColor $MessageColor "Forwarding has successfully been configured for the specified mailbox. Please make sure to run the ATP Master script to allow outbound forwarding from the specified account."
                Write-Host
                get-mailbox -Identity $AlertAddress | Format-List Username,ForwardingSMTPAddress,DeliverToMailboxandForward
                
                #>

    } # Pre-req Question 2

} # Pre-Req Question 1



    Write-Host
    Write-Host -ForegroundColor green "This concludes the script for Baseline Tenant Configs"

