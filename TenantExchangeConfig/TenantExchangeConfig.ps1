### Comprehensive M365 Tenant and Exchange Configuration

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

# Initialize variables
$scriptPath = $PSScriptRoot
$parentDir = Split-Path $scriptPath -Parent
$logFile = Join-Path $scriptPath "TenantExchangeConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Check parent directory
if ((Split-Path $parentDir -Leaf) -ne "Auto-M365-TenantMaster") {
    throw "The parent directory must be Auto-M365-TenantMaster."
}

# Construct the path to the config file in the parent directory
$configFile = Join-Path $parentDir "config.json"

function Verify-ServiceConnections {
    # Check Global Variables and Status
    Write-Host
    #TenantID
    if ($null -eq $Global:TenantID -or $Global:TenantID -eq "CRITICAL ERROR") {
        Write-Log "Critical Failure: Tenant ID not found in global variable TenantID" "ERROR"
        exit
    }
    else {
        Write-Host " -= Tenant ID : $Global:TenantID" -ForegroundColor  DarkGreen
        $TenantID = $Global:TenantID
    }
    #TenantDomain
    if ($null -eq $Global:TenantDomain) {
        Write-Log "Critical Failure: Tenant Domain not found in global variable TenantDomain" "ERROR"
        exit
    }
    else {
        Write-Host " -= Tenant Domain: $Global:TenantDomain" -ForegroundColor DarkGreen
        $TenantDomain = $Global:TenantDomain
    }
    #Credential
    if ($null -eq $Global:Credential) {
        Write-Log "Critical Failure: Credential not found in global variable Credential" "ERROR"
        exit
    }
    else {
        Write-Host " -= Credential: $($Global:Credential.UserName)" -ForegroundColor  DarkGreen
    }
    # Check if all necessary connections are established and set global variable
    if ($Global:connectionCheck -eq $true) {
        Write-Host
        Write-Host " All necessary connections are established! Proceed with Configuration." -ForegroundColor Green
        Write-Host
    }
    else {
        Write-Host
        Write-Host
        Write-Host "Some required module connections are missing:" -ForegroundColor Yellow
        $Global:connectionCheck | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
        exit
    }
}

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
        throw "Configuration file not found. Unable to proceed without config file in the Launcher directory."
    }
    return $config
}

################################################
# # # Function to configure Exchange Online settings
function Set-ExchangeOnlineConfig {
    param ($Config)
    
    try {
        # Enable Organization Customization
        Enable-OrganizationCustomization -ErrorAction SilentlyContinue
        Enable-AipService -ErrorAction SilentlyContinue
        Write-Host
        Write-Log "Organization Customization & AIP are enabled" "INFO"

        # Configure Send-from-Alias
        if (!(Get-OrganizationConfig).SendFromAliasEnabled) {
            Set-OrganizationConfig -SendFromAliasEnabled $true
            Write-Log "Send-From-Alias is now enabled" "INFO"
        }

        # Disable Focused Inbox
        if ($Config.DisableFocusedInbox) {
            Set-OrganizationConfig -FocusedInboxOn $false
            Write-Log "Focused Inbox has been disabled across the entire Organization" "INFO"
        }

        # Enable Naming Scheme for Distribution Lists
        Set-OrganizationConfig -DistributionGroupNamingPolicy "DL_<GroupName>"
        Write-Log "Enabled Naming Scheme for Distribution Lists: 'DL_<GroupName>'" "INFO"

        # Enable Plus Addressing
        Set-OrganizationConfig -DisablePlusAddressInRecipients $False
        Write-Log "Plus Addressing Enabled" "INFO"

        # Configure Mail-Tips
        Set-OrganizationConfig -MailTipsAllTipsEnabled $True -MailTipsExternalRecipientsTipsEnabled $False -MailTipsGroupMetricsEnabled $True -MailTipsMailboxSourcedTipsEnabled $True -MailTipsLargeAudienceThreshold "10"
        Write-Log "Mail-Tip Features Configured" "INFO"

        # Enable Read Email Tracking
        Set-OrganizationConfig -ReadTrackingEnabled $True
        Write-Log "Email Read-Tracking Enabled" "INFO"

        # Enable Public Computer Detection (For OWA)
        Set-OrganizationConfig -PublicComputersDetectionEnabled $True
        Write-Log "Public Computer Tracking is enabled" "INFO"

        # Disable Outlook Pay
        Set-OrganizationConfig -OutlookPayEnabled $False
        Write-Log "Outlook Pay (Microsoft Pay) is disabled" "INFO"

        # Enable Lean Pop-Outs for OWA in Edge
        Set-OrganizationConfig -LeanPopoutEnabled $True
        Write-Log "Lean Pop-Outs for OWA in Edge are Enabled" "INFO"

        # Enable Outlook Events Recognition
        Set-OrganizationConfig -EnableOutlookEvents $True
        Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -LocalEventsEnabled $True
        Write-Log "Outlook Events Tracking is Enabled" "INFO"

        # Disable Feedback in Outlook Online
        Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -FeedbackEnabled $False -UserVoiceEnabled $false
        Write-Log "Feedback & User Voice in OWA is disabled" "INFO"

        # Enable Modern Authentication
        if (!(Get-OrganizationConfig).OAuth2ClientProfileEnabled) {
            Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
            Write-Log "Modern Authentication is now enabled" "INFO"
        }

        # Block Consumer Storage in OWA
        if ((Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default).AdditionalStorageProvidersAvailable) {
            Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False
            Write-Log "Consumer storage locations in OWA are now disabled" "INFO"
        }

        # Block Attachment Download on Unmanaged Assets OWA
        if ((Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default).ConditionalAccessPolicy -eq 'Off') {
            Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -ConditionalAccessPolicy ReadOnly
            Write-Log "Attachment download on unmanaged devices is now disabled" "INFO"
        }

        # Set Retention Limit on deleted items
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
        Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
        Write-Log "Deleted items will be retained for 30 days for all mailboxes" "INFO"

        # Enable Unified Audit Log Search
        if (!(Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
            Write-Log "Unified Audit Log Search is now enabled" "INFO"
        }

        # Configure Audit Log Retention
        Set-OrganizationConfig -AuditDisabled $False
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $Config.AuditLogAgeLimit
        Write-Log "Audit Log Retention configured for all mailboxes" "INFO"

        # Enable all mailbox auditing actions
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add = "Copy", "Create", "FolderBind", "HardDelete", "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules", "UpdateCalendarDelegation" }
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditDelegate @{Add = "Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules" }
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditOwner @{Add = "Create", "HardDelete", "Move", "Mailboxlogin", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules", "UpdateCalendarDelegation" }
        Write-Log "All auditing actions are now enabled on all mailboxes" "INFO"

        # Configure External Sender Tags
        Write-Log "Configuring External Sender Tags in Outlook" "INFO"
        Set-ExternalInOutlook -Enabled $true
        Write-Log "External Sender Tags enabled in Outlook" "INFO"

        # Create or update the allow list for admin users (for external sender tags)
        $allowList = (Get-ExternalInOutlook).AllowList
        $adminUsers = @($($Global:Credential.UserName), $Global:breakGlassUPN)

        foreach ($user in $adminUsers) {
            if ($user -notin $allowList) {
                $allowList += $user
                Write-Log "Added $user to External Sender Tags exception list" "INFO"
            }
            else {
                Write-Log "$user already in External Sender Tags exception list" "INFO"
            }
        }

        # Update the allow list
        Set-ExternalInOutlook -AllowList $allowList
        Write-Log "Updated External Sender Tags exception list" "INFO"

        Write-Host
        Write-Log "All Exchange Online configurations completed successfully" "INFO"
    }
    catch {
        Write-Log "Error configuring Exchange Online: $($_.Exception.Message)" "ERROR"
        throw
    }
}

################################################
# # # Function to configure Azure AD settings
function Set-AzureADConfig {
    param ($Config)
    try {
        Write-Log "Starting Azure AD configuration" "INFO"

        # Enable or Disable Security Defaults
        try {
            # Get current security defaults status
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
            # Check if the current state matches the desired state
            if ($securityDefaults.IsEnabled -eq !$Config.DisableSecurityDefaults) {
                Write-Log "Security Defaults are already in the desired state (Enabled: $(!$Config.DisableSecurityDefaults))" "INFO"
            }
            else {
                # Prepare the parameters for updating security defaults
                $params = @{
                    IsEnabled = !$Config.DisableSecurityDefaults
                }
        
                # Update security defaults
                Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
        
                $action = if ($Config.DisableSecurityDefaults) { "disabled" } else { "enabled" }
                Write-Log "Security Defaults have been $action" "INFO"
            }
        }
        catch {
            Write-Log "Error configuring Security Defaults: $($_.Exception.Message)" "ERROR"
            Write-Log "Error details: $($_.Exception.StackTrace)" "ERROR"
        }
                
        # Create Break-Glass Account
        if (!(Get-AzureADUser -Filter "UserPrincipalName eq '$Global:breakGlassUPN'")) {
            Write-Log "Creating Break-Glass account" "INFO"
            $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
            $PasswordProfile.Password = $Config.BreakGlassAccountPass
            New-AzureADUser -AccountEnabled $True -DisplayName "$($Config.MSPName) Break-Glass" -PasswordProfile $PasswordProfile -MailNickName "$($Config.MSPName)BG" -UserPrincipalName $Global:breakGlassUPN
            $bgUser = Get-AzureADUser -ObjectId $Global:breakGlassUPN
            $role = Get-AzureADDirectoryRole | Where-Object { $_.displayName -eq 'Global Administrator' }
            Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $bgUser.ObjectId
            Write-Log "Break-Glass account created and added to Global Administrator role" "INFO"
        }
        else {
            Write-Log "Break-Glass account already exists" "INFO"
        }

        # Ensure admin users are properly defined
        $adminUsers = @($($Global:Credential.UserName), $Global:breakGlassUPN) | Where-Object { $_ -ne $null -and $_ -ne '' }
        if ($adminUsers.Count -lt 2) {
            Write-Log "Admin users not properly defined. Check GlobalAdminUPN and breakGlassUPN in the configuration." "ERROR"
            throw "Admin users not properly defined"
        }

        # Delete old devices if configured
        if ($Config.DeleteStaleDevices) {
            Write-Log "Deleting stale devices" "INFO"
            $deletionThreshold = (Get-Date).AddDays(-$Config.StaleDeviceThresholdDays)
            $oldDevices = Get-AzureADDevice -All:$true | Where-Object { $_.ApproximateLastLogonTimeStamp -le $deletionThreshold }
            foreach ($device in $oldDevices) {
                Remove-AzureADDevice -ObjectId $device.ObjectId
                Write-Log "Removed old device: $($device.DisplayName)" "INFO"
            }
        }

        # Function to check if a group exists in Azure AD
        function Get-AzureADGroupIfExists {
            param ($GroupName)
            try {
                return Get-AzureADGroup -SearchString $GroupName -ErrorAction Stop
            }
            catch {
                return $null
            }
        }

        # Function to check if a distribution group exists in Exchange Online
        function Get-DistributionGroupIfExists {
            param ($GroupName)
            try {
                return Get-DistributionGroup -Identity $GroupName -ErrorAction Stop
            }
            catch {
                return $null
            }
        }

        # Function to check if a user is a member of an Azure AD group
        function Test-AzureADGroupMembership {
            param ($GroupId, $UserId)
            $groupMembers = Get-AzureADGroupMember -ObjectId $GroupId -All $true
            return ($groupMembers | Where-Object { $_.ObjectId -eq $UserId }).Count -gt 0
        }

        # Function to check if a user is a member of a distribution group
        function Test-DistributionGroupMembership {
            param ($GroupName, $UserEmail)
            $normalizedUserEmail = $UserEmail.ToLower()
            $groupMembers = Get-DistributionGroupMember -Identity $GroupName -ResultSize Unlimited
            foreach ($member in $groupMembers) {
                if ($null -ne $member.PrimarySmtpAddress -and $member.PrimarySmtpAddress.Trim() -ne "") {
                    $normalizedMemberEmail = $member.PrimarySmtpAddress.ToLower()
                    Write-Log "Checking member: $($member.PrimarySmtpAddress)" "INFO"
                    if ($normalizedMemberEmail -eq $normalizedUserEmail) {
                        Write-Log "$UserEmail is a member of $GroupName" "INFO"
                        return $true
                    }
                }
                else {
                    Write-Log "Member has no PrimarySmtpAddress or invalid address: $($member.Name) - $($member.RecipientType)" "INFO"
                }
            }
            Write-Log "Checking if $UserEmail is a member of $GroupName : False" "INFO"
            return $false
        }

        # Function to handle mail-enabled security group creation and verification
        function Check-MailEnabledSecurityGroup {
            param (
                [string]$GroupName,
                [string]$GroupDescription
            )
        
            $rawGroupName = $GroupName
            $prefixedGroupName = "DL_$GroupName"

            $group = Get-DistributionGroup -Identity $rawGroupName -ErrorAction SilentlyContinue
            if ($null -eq $group) {
                $group = Get-DistributionGroup -Identity $prefixedGroupName -ErrorAction SilentlyContinue
            }

            if ($null -ne $group) {
                Write-Log "Mail-enabled security group '$($group.Name)' already exists" "INFO"
                return $true
            }
            else {
                try {
                    $groupEmail = "$prefixedGroupName@$((Get-AzureADTenantDetail).VerifiedDomains[0].Name)"
                    New-DistributionGroup -Name $prefixedGroupName -DisplayName $prefixedGroupName -PrimarySmtpAddress $groupEmail -Type "Security" -MemberJoinRestriction "Closed" -Notes $GroupDescription
                    Write-Log "Created new mail-enabled security group: $prefixedGroupName" "INFO"
                    return $true
                }
                catch {
                    Write-Log "Error creating mail-enabled security group $prefixedGroupName : $($_.Exception.Message)" "ERROR"
                    return $false
                }
            }
        }

        # Define Groups
        Write-Log "Creating and configuring groups" "INFO"
        $nonMailGroups = @(
            @{Name = $Config.ExcludeFromCAGroupName; Description = "Users Excluded from any Conditional Access Policies" },
            @{Name = $Config.GroupCreatorsGroupName; Description = "Users Allowed to create M365 and Teams Groups" },
            @{Name = $Config.DevicePilotGroupName; Description = "Intune Device Pilot Group for Testing and Deployment" }
        )
        $MailGroups = @(
            @{Name = $Config.AllowedAutoForwardingGroup; Description = "Users Allowed to set Auto-Forwarding Rules in Exchange Online" }
        )
        # Create Groups
        foreach ($group in $nonMailGroups) {
            $existingGroup = Get-AzureADGroupIfExists -GroupName $group.Name
            if (!$existingGroup) {
                New-AzureADGroup -DisplayName $group.Name -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description $group.Description
                Write-Log "Created new group: $($group.Name)" "INFO"
            }
            else {
                Write-Log "Group already exists: $($group.Name)" "INFO"
            }
        }
        foreach ($group in $MailGroups) {
            $result = Check-MailEnabledSecurityGroup -GroupName $group.Name -GroupDescription $group.Description
            if (!$result) {
                throw "Failed to create or verify mail-enabled security group '$($group.Name)'."
            }
        }

        # Add Admin Users to Groups
        Write-Log "Adding admin users to groups" "INFO"
        $adminUsers = @($($Global:Credential.UserName), $Global:breakGlassUPN)
        foreach ($user in $adminUsers) {
            $azureADUser = Get-AzureADUser -ObjectId $user

            # Add to non-mail groups
            foreach ($group in $nonMailGroups) {
                $groupObject = Get-AzureADGroup -Filter "DisplayName eq '$($group.Name)'"
                if ($groupObject) {
                    if (!(Test-AzureADGroupMembership -GroupId $groupObject.ObjectId -UserId $azureADUser.ObjectId)) {
                        try {
                            Add-AzureADGroupMember -ObjectId $groupObject.ObjectId -RefObjectId $azureADUser.ObjectId -ErrorAction Stop
                            Write-Log "Added $user to non-mail group $($group.Name)" "INFO"
                        }
                        catch {
                            Write-Log "Error adding $user to non-mail group $($group.Name): $($_.Exception.Message)" "ERROR"
                        }
                    }
                    else {
                        Write-Log "$user is already a member of non-mail group $($group.Name)" "INFO"
                    }
                }
                else {
                    Write-Log "Non-mail group $($group.Name) not found" "WARNING"
                }
            }

            # Add to mail-enabled groups
            foreach ($group in $MailGroups) {
                $rawGroupName = $group.Name
                $prefixedGroupName = "DL_$($group.Name)"
    
                # Try with raw name first, then prefixed name
                foreach ($groupName in @($rawGroupName, $prefixedGroupName)) {
                    if (Get-DistributionGroup -Identity $groupName -ErrorAction SilentlyContinue) {
                        if (-not (Test-DistributionGroupMembership -GroupName $groupName -UserEmail $user)) {
                            try {
                                Add-DistributionGroupMember -Identity $groupName -Member $user -ErrorAction Stop
                                Write-Log "Added $user to mail-enabled group $groupName" "INFO"
                            }
                            catch {
                                Write-Log "Error adding $user to mail-enabled group $groupName : $($_.Exception.Message)" "ERROR"
                            }
                        }
                        else {
                            Write-Log "$user is already a member of mail-enabled group $groupName" "INFO"
                        }
                        break  # Exit the loop if we found and processed the group
                    }
                }
            }
        }

        # Create or Update Super Admin Role Group
        Write-Log "Configuring Super Admin role group" "INFO"

        # Get all available roles in the tenant
        $allRoles = Get-ManagementRole | Where-Object { $_.RoleType -eq "RoleAssignmentRole" } | Select-Object -ExpandProperty Name
        Write-Log "Available roles: $($allRoles -join ', ')" "INFO"

        $superAdminGroup = Get-RoleGroup -Identity "Super Admin" -ErrorAction SilentlyContinue
        if ($superAdminGroup) {
            Write-Log "Super Admin role group already exists. Updating roles and members." "INFO"
            
            # Update roles
            $currentRoles = (Get-RoleGroup -Identity "Super Admin").Roles
            $rolesToAdd = $allRoles | Where-Object { $_ -notin $currentRoles }
            
            if ($rolesToAdd) {
                try {
                    Update-RoleGroupMember -Identity "Super Admin" -Members $superAdminGroup.Members -Roles ($currentRoles + $rolesToAdd) -Confirm:$false -ErrorAction Stop
                    Write-Log "Added roles to Super Admin group: $($rolesToAdd -join ', ')" "INFO"
                }
                catch {
                    Write-Log "Error updating roles for Super Admin group: $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                Write-Log "No new roles to add to Super Admin group." "INFO"
            }

            # Update members
            $currentMembers = (Get-RoleGroup -Identity "Super Admin").Members
            foreach ($user in $adminUsers) {
                if ($user -notin $currentMembers) {
                    try {
                        Add-RoleGroupMember -Identity "Super Admin" -Member $user -Confirm:$false -ErrorAction Stop
                        Write-Log "Added $user to Super Admin role group" "INFO"
                    }
                    catch {
                        if ($_.Exception.Message -like "*is already a member of the group*") {
                            Write-Log "$user is already a member of Super Admin role group" "INFO"
                        }
                        else {
                            Write-Log "Error adding $user to Super Admin role group: $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
                else {
                    Write-Log "$user is already a member of Super Admin role group" "INFO"
                }
            }
        }
        else {
            try {
                New-RoleGroup -Name "Super Admin" -Roles $allRoles -Members $adminUsers -Confirm:$false -ErrorAction Stop
                Write-Log "Super Admin role group created with all available roles and specified members" "INFO"
            }
            catch {
                Write-Log "Error creating Super Admin role group: $($_.Exception.Message)" "ERROR"
            }
        }
        Write-Log "Super Admin role group configuration completed" "INFO"                

        # Create "Guest Admins" group and configure guest invite settings
        Write-Log "Configuring Guest Admins group and guest invite settings" "INFO"

        # Create "Guest Admins" group if it doesn't exist
        $guestAdminsGroupName = "Guest Admins"
        $guestAdminsGroup = Get-AzureADGroup -Filter "DisplayName eq '$guestAdminsGroupName'" -ErrorAction SilentlyContinue
        if (-not $guestAdminsGroup) {
            try {
                $guestAdminsGroup = New-AzureADGroup -DisplayName $guestAdminsGroupName -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Users allowed to invite guest users"
                Write-Log "Created new Guest Admins group" "INFO"
            }
            catch {
                Write-Log "Error creating Guest Admins group: $($_.Exception.Message)" "ERROR"
                throw
            }
        }
        else {
            Write-Log "Guest Admins group already exists" "INFO"
        }

        # Add admin users to the Guest Admins group
        foreach ($adminUser in $adminUsers) {
            try {
                $user = Get-AzureADUser -ObjectId $adminUser
                if (-not (Get-AzureADGroupMember -ObjectId $guestAdminsGroup.ObjectId -All $true | Where-Object { $_.ObjectId -eq $user.ObjectId })) {
                    Add-AzureADGroupMember -ObjectId $guestAdminsGroup.ObjectId -RefObjectId $user.ObjectId
                    Write-Log "Added $adminUser to Guest Admins group" "INFO"
                }
                else {
                    Write-Log "$adminUser is already a member of Guest Admins group" "INFO"
                }
            }
            catch {
                Write-Log "Error adding $adminUser to Guest Admins group: $($_.Exception.Message)" "ERROR"
            }
        }

        # Assign Guest Inviter role to individual members of the Guest Admins group
        try {
            $guestInviterRole = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Guest Inviter" }
            if (-not $guestInviterRole) {
                # If the role doesn't exist, activate it
                $guestInviterRoleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Guest Inviter" }
                Enable-AzureADDirectoryRole -RoleTemplateId $guestInviterRoleTemplate.ObjectId
                $guestInviterRole = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Guest Inviter" }
            }
    
            $groupMembers = Get-AzureADGroupMember -ObjectId $guestAdminsGroup.ObjectId -All $true
            foreach ($member in $groupMembers) {
                $existingRoleMember = Get-AzureADDirectoryRoleMember -ObjectId $guestInviterRole.ObjectId | 
                Where-Object { $_.ObjectId -eq $member.ObjectId }
        
                if (-not $existingRoleMember) {
                    Add-AzureADDirectoryRoleMember -ObjectId $guestInviterRole.ObjectId -RefObjectId $member.ObjectId
                    Write-Log "Assigned Guest Inviter role to $($member.UserPrincipalName)" "INFO"
                }
                else {
                    Write-Log "$($member.UserPrincipalName) already has the Guest Inviter role" "INFO"
                }
            }
        }
        catch {
            Write-Log "Error assigning Guest Inviter role: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Verify the configuration
        try {
            $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $guestInviterRole.ObjectId
            $groupMembers = Get-AzureADGroupMember -ObjectId $guestAdminsGroup.ObjectId -All $true
            $allMembersHaveRole = $true
            foreach ($member in $groupMembers) {
                if ($roleMembers.ObjectId -notcontains $member.ObjectId) {
                    $allMembersHaveRole = $false
                    Write-Log "Warning: $($member.UserPrincipalName) in Guest Admins group does not have the Guest Inviter role" "WARNING"
                }
            }
            if ($allMembersHaveRole) {
                Write-Log "Verified: All members of Guest Admins group have the Guest Inviter role" "INFO"
            }
        }
        catch {
            Write-Log "Error verifying guest invitation settings: $($_.Exception.Message)" "ERROR"
        }

        Write-Log "Guest Admins group configuration completed" "INFO"




        # Grant Admin Access to All Mailboxes
        if ($Config.AdminAccessToMailboxes) {
            Write-Log "Granting admin access to all mailboxes" "INFO"
            Get-Mailbox -ResultSize Unlimited | Add-MailboxPermission -User $($Global:Credential.UserName) -AccessRights FullAccess -InheritanceType All -AutoMapping $false
            Write-Log "Admin granted access to all mailboxes" "INFO"
        }

        # Configure group creation restrictions
        Write-Log "Configuring group creation restrictions" "INFO"
        $settingsObjectID = (Get-AzureADDirectorySetting | Where-Object -Property DisplayName -Value "Group.Unified" -EQ).id
        if (!$settingsObjectID) {
            $template = Get-AzureADDirectorySettingTemplate | Where-Object { $_.displayname -eq "group.unified" }
            $settingsCopy = $template.CreateDirectorySetting()
            New-AzureADDirectorySetting -DirectorySetting $settingsCopy
            $settingsObjectID = (Get-AzureADDirectorySetting | Where-Object -Property DisplayName -Value "Group.Unified" -EQ).id
        }
        $settingsCopy = Get-AzureADDirectorySetting -Id $settingsObjectID
        $settingsCopy["EnableGroupCreation"] = $false
        $groupCreators = Get-AzureADGroup -SearchString $Config.GroupCreatorsGroupName
        if ($groupCreators) {
            $settingsCopy["GroupCreationAllowedGroupId"] = $groupCreators.ObjectId
            Set-AzureADDirectorySetting -Id $settingsObjectID -DirectorySetting $settingsCopy
            Write-Log "Group creation restricted to members of $($Config.GroupCreatorsGroupName)" "INFO"
        }
        else {
            Write-Log "Group Creators group not found. Skipping group creation restriction." "WARNING"
        }

        # Hide admin users from the global address list
        Write-Log "Hiding admin users from the global address list" "INFO"
        foreach ($adminEmail in $adminUsers) {
            try {
                Set-Mailbox -Identity $adminEmail -HiddenFromAddressListsEnabled $true -ErrorAction Stop
                Write-Log "Successfully hid $adminEmail from the global address list" "INFO"
            }
            catch {
                Write-Log "Failed to hide $adminEmail from the global address list: $($_.Exception.Message)" "ERROR"
            }
        }

        # Setup Email Forwarding for Global Admin
        Write-Log "Setting up email forwarding for Global Admin" "INFO"
        try {
            # Get the current mailbox settings
            $mailbox = Get-Mailbox -Identity $($Global:Credential.UserName) -ErrorAction Stop

            if ($mailbox.ForwardingAddress -eq $Config.MSPAlertsAddress -and $mailbox.DeliverToMailboxAndForward -eq $true) {
                Write-Log "Email forwarding is already correctly configured for $($Global:Credential.UserName)" "INFO"
            }
            else {
                # Configure forwarding
                Set-Mailbox -Identity $($Global:Credential.UserName) -ForwardingAddress $Config.MSPAlertsAddress -DeliverToMailboxAndForward $true -ErrorAction Stop
                Write-Log "Email forwarding configured for $($Global:Credential.UserName) to $($Config.MSPAlertsAddress)" "INFO"
            }

            # Disable junk email rule
            $junkRule = Get-MailboxJunkEmailConfiguration -Identity $($Global:Credential.UserName) -ErrorAction Stop
            if ($junkRule.Enabled) {
                Set-MailboxJunkEmailConfiguration -Identity $($Global:Credential.UserName) -Enabled $false -ErrorAction Stop
                Write-Log "Junk email rule disabled for $($Global:Credential.UserName)" "INFO"
            }
            else {
                Write-Log "Junk email rule is already disabled for $($Global:Credential.UserName)" "INFO"
            }

            Write-Log "Email forwarding setup completed successfully" "INFO"
        }
        catch {
            Write-Log "Error setting up email forwarding: $($_.Exception.Message)" "ERROR"
            Write-Log "Error details: $($_.Exception.StackTrace)" "ERROR"
        }

        Write-Host
        Write-Log "Azure AD configuration completed successfully" "INFO"
    }
    catch {
        Write-Log "Error configuring Azure AD: $($_.Exception.Message)" "ERROR"
        Write-Log "Error details: $($_.Exception.StackTrace)" "ERROR"
        throw
    }
}

################################################
# # # Function to configure MSOL settings
function Set-MSOLConfig {
    param ($Config)
    
    try {
        # Disable Shared Mailbox Logon
        Get-Mailbox -RecipientTypeDetails SharedMailbox | ForEach-Object {
            Set-MsolUser -UserPrincipalName $_.UserPrincipalName -BlockCredential $true
        }
        Write-Log "Shared Mailboxes blocked from interactive logon" "INFO"

        # Set regional settings for all mailboxes
        Get-Mailbox -ResultSize unlimited | ForEach-Object {
            Set-MailboxRegionalConfiguration -Identity $_.Alias -Language $Config.Language -TimeZone $Config.Timezone
        }
        Write-Log "Regional settings configured for all mailboxes" "INFO"

    }
    catch {
        Write-Log "Error configuring MSOL: $($_.Exception.Message)" "ERROR"
        throw
    }
}

################################################
# # # Microsoft Teams configurations
function Set-TeamsConfiguration {
    param ($Config)
    try {
        Write-Log "Checking Teams connection" "INFO"
        $teamsConnection = Get-CsTenantFederationConfiguration -ErrorAction Stop
        
        Write-Log "Configuring Microsoft Teams settings" "INFO"
        
        # Set default team and channel settings
        Set-CsTeamsChannelsPolicy -Identity Global -AllowOrgWideTeamCreation $config.TeamsConfig.AllowOrgWideTeamCreation
        Write-Log "Disabled creation of Org-Wide Teams" "INFO"

        # Configure external access
        Set-CsTenantFederationConfiguration -AllowFederatedUsers $Config.TeamsConfig.AllowFederatedUsers -AllowTeamsConsumer $config.TeamsConfig.AllowTeamsConsumer -AllowTeamsConsumerInbound $config.TeamsConfig.AllowTeamsConsumerInbound
        Write-Log "Only Federated B2B Guests allowed in Teams" "INFO"

        # Configure guest access
        Set-CsTeamsClientConfiguration -Identity Global -AllowGuestUser $config.TeamsConfig.AllowGuestAccess
        Set-CsTeamsMeetingConfiguration -Identity Global -DisableAnonymousJoin $config.TeamsConfig.DisableAnonymousJoin
        Write-Log "Block Anonymous guests in Teams" "INFO"
        
        # Additional client configuration settings
        Set-CsTeamsClientConfiguration -Identity Global -AllowBox $config.TeamsConfig.AllowBox -AllowDropBox $config.TeamsConfig.AllowDropBox -AllowEgnyte $config.TeamsConfig.AllowEgnyte -AllowEmailIntoChannel $config.TeamsConfig.AllowEmailIntoChannel -AllowGoogleDrive $config.TeamsConfig.AllowGoogleDrive
        Write-Log "Blocked consumer service providers" "INFO"

        # Set Logo for Meeting Invites
        Set-CsTeamsMeetingConfiguration -Identity Global -LogoURL $config.LogoURL
        
        Write-Log "Microsoft Teams configuration completed" "INFO"
    }
    catch {
        if ($_.Exception.Message -like "*Session is not established*") {
            Write-Log "Teams connection not established. Please ensure you've run Connect-MicrosoftTeams before running this function." "ERROR"
        }
        else {
            Write-Log "Error configuring Microsoft Teams: $($_.Exception.Message)" "ERROR"
        }
        throw
    }
}

################################################
# # # SharePoint and OneDrive configurations
function Set-SharePointOneDriveConfig {
    param ($Config)
    try {
        Write-Log "Configuring SharePoint and OneDrive settings" "INFO"

        # Set default storage limits
        Set-SPOTenant -OneDriveStorageQuota $config.SharePointOneDriveConfig.OneDriveStorageQuota
        Write-Log "Set SP/OD Quota to 10GB" "INFO"

        # Configure external sharing settings
        Set-SPOTenant -SharingCapability $config.SharePointOneDriveConfig.SharingCapability -DefaultSharingLinkType $config.SharePointOneDriveConfig.DefaultSharingLinkType -PreventExternalUsersFromResharing $config.SharePointOneDriveConfig.PreventExternalUsersFromResharing
        Write-Log "Set Tenant Sharing Permission Defaults" "INFO"

        # Configure BCC on Sharing to Admin Mailbox
        Set-SPOTenant -BccExternalSharingInvitations $config.SharePointOneDriveConfig.BccExternalSharingInvitations -BccExternalSharingInvitationsList $($Global:Credential.UserName)
        Write-Log "Set BCC for external sharing to Admin Account" "INFO"

        <# Future Expandability
        -ApplyAppEnforcedRestrictionsToAdHocRecipients ??? Extra Security later?
        #>

        Write-Log "SharePoint and OneDrive configuration completed" "INFO"
    }
    catch {
        Write-Log "Error configuring SharePoint and OneDrive: $($_.Exception.Message)" "ERROR"
        throw
    }
}

################################################
# # # Configure basic compliance policies
function Set-RetentionPolicies {
    param ($Config)
    # Configure Compliance Policies
    Write-Log "Configuring Compliance Policies" "INFO"

    # Email Retention Policy
    try {
        $emailRetentionYears = $Config.CompliancePolicies.EmailRetentionYears
        $emailRetentionDays = $emailRetentionYears * 365

        New-RetentionCompliancePolicy -Name "Email $emailRetentionYears Year Retention" -ExchangeLocation All -ErrorAction Stop
        Write-Log "Created Email $emailRetentionYears Year Retention policy" "INFO"
    }
    catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Log "Email $emailRetentionYears Year Retention policy already exists. Skipping creation." "INFO"
        }
        else {
            Write-Log "Error creating Email $emailRetentionYears Year Retention policy: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    try {
        New-RetentionComplianceRule -Name "Email $emailRetentionYears Year Retention Rule" -Policy "Email $emailRetentionYears Year Retention" -RetentionDuration $emailRetentionDays -RetentionComplianceAction Keep -ErrorAction Stop
        Write-Log "Created Email $emailRetentionYears Year Retention Rule" "INFO"
    }
    catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Log "Email $emailRetentionYears Year Retention Rule already exists. Skipping creation." "INFO"
        }
        else {
            Write-Log "Error creating Email $emailRetentionYears Year Retention Rule: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    # SharePoint and OneDrive Retention Policy
    try {
        $spodRetentionYears = $Config.CompliancePolicies.SharePointOneDriveRetentionYears
        $spodRetentionDays = $spodRetentionYears * 365

        New-RetentionCompliancePolicy -Name "SharePoint and OneDrive $spodRetentionYears Year Retention" -SharePointLocation All -OneDriveLocation All -ErrorAction Stop
        Write-Log "Created SharePoint and OneDrive $spodRetentionYears Year Retention policy" "INFO"
    }
    catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Log "SharePoint and OneDrive $spodRetentionYears Year Retention policy already exists. Skipping creation." "INFO"
        }
        else {
            Write-Log "Error creating SharePoint and OneDrive $spodRetentionYears Year Retention policy: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    try {
        New-RetentionComplianceRule -Name "SP/OD $spodRetentionYears Year Retention Rule" -Policy "SharePoint and OneDrive $spodRetentionYears Year Retention" -RetentionDuration $spodRetentionDays -RetentionComplianceAction Keep -ErrorAction Stop
        Write-Log "Created SP/OD $spodRetentionYears Year Retention Rule" "INFO"
    }
    catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Log "SP/OD $spodRetentionYears Year Retention Rule already exists. Skipping creation." "INFO"
        }
        else {
            Write-Log "Error creating SP/OD $spodRetentionYears Year Retention Rule: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    Write-Log "Compliance Policies configuration completed" "INFO"
}

################################################
# # # Enhanced Security Alert Notifications
function Set-SecurityAlertNotifications {
    param ($Config)
    try {
        Write-Log "Configuring enhanced security alert notifications" "INFO"

        $notificationEmail = $($Global:Credential.UserName)

        # Function to create a new alert policy with error handling
        function New-AlertPolicy {
            param($Name, $Category, $NotifyUser, $Operation, $Severity, $ThreatType, $Description)
            try {
                Write-Log "Attempting to create alert policy: $Name" "INFO"
                $params = @{
                    Name            = $Name
                    Category        = $Category
                    NotifyUser      = $NotifyUser
                    ThreatType      = $ThreatType
                    Severity        = $Severity
                    AggregationType = "None"
                    Description     = $Description
                }
                # Only add Operation if it's not a malware rule
                if ($ThreatType -ne "Malware") {
                    $params.Add("Operation", $Operation)
                }
                New-ProtectionAlert @params -ErrorAction Stop
                Write-Log "Successfully created alert policy: $Name" "INFO"
            }
            catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Log "Alert policy '$Name' already exists. Skipping creation." "INFO"
                }
                else {
                    Write-Log "Error creating alert policy '$Name': $($_.Exception.Message)" "ERROR"
                    # Don't throw here, just log the error and continue with other policies
                }
            }
        }

        # Admin Activities Alerts
        Write-Log "Creating Admin Activities Alerts" "INFO"
        New-AlertPolicy -Name "Suspicious Admin Activity" -Category ThreatManagement -NotifyUser $notificationEmail `
            -Operation "AdminActivity" -Severity "High" -ThreatType "Activity" `
            -Description "Alerts when suspicious admin activities are detected"

        New-AlertPolicy -Name "Mass User Deletion" -Category ThreatManagement -NotifyUser $notificationEmail `
            -Operation "RemoveUserFromDirectory" -Severity "High" -ThreatType "Activity" `
            -Description "Alerts when a large number of users are deleted in a short time"

        # Malware Alerts
        Write-Log "Creating Malware Alerts" "INFO"
        New-AlertPolicy -Name "Malware Campaign Detected" -Category ThreatManagement -NotifyUser $notificationEmail `
            -ThreatType "Malware" -Severity "High" -Operation $null `
            -Description "Alerts when a malware campaign is detected in the organization"

        # Threat Policies Alerts
        Write-Log "Creating Threat Policies Alerts" "INFO"
        New-AlertPolicy -Name "Suspicious Email Sending Patterns" -Category ThreatManagement -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "MailItemsAccessed" -Severity "Medium" `
            -Description "Alerts when unusual email sending patterns are detected"

        New-AlertPolicy -Name "Suspicious File Activity" -Category ThreatManagement -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "FileAccessed" -Severity "Medium" `
            -Description "Alerts when suspicious file access activities are detected"

        # High Sensitivity Alerts
        Write-Log "Creating High Sensitivity Alerts" "INFO"
        New-AlertPolicy -Name "Sensitive Data Access" -Category DataLossPrevention -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "SensitiveFileAccessed" -Severity "High" `
            -Description "Alerts when sensitive data is accessed by unauthorized users"

        New-AlertPolicy -Name "Multiple Failed Login Attempts" -Category ThreatManagement -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "UserLoggedIn" -Severity "High" `
            -Description "Alerts when multiple failed login attempts are detected for a user"

        # Basic Informational Alerts (changed category to "Others")
        Write-Log "Creating Basic Informational Alerts" "INFO"
        New-AlertPolicy -Name "New Device Enrolled" -Category Others -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "DeviceEnrollment" -Severity "Low" `
            -Description "Informs when a new device is enrolled in Intune"

        New-AlertPolicy -Name "User Added to Admin Role" -Category Others -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "UserAdded" -Severity "Medium" `
            -Description "Informs when a user is added to an admin role"

        New-AlertPolicy -Name "New Mailbox Created" -Category Others -NotifyUser $notificationEmail `
            -ThreatType "Activity" -Operation "MailboxCreated" -Severity "Low" `
            -Description "Informs when a new mailbox is created"

        Write-Log "Security alert notifications configuration completed" "INFO"
    }
    catch {
        Write-Log "Error configuring security alert notifications: $($_.Exception.Message)" "ERROR"
        throw
    }
}

######################################################
### Main execution
######################################################

try {
    # Title Print

    Write-Host
    Write-Host
    Write-Host "================ M365 Tenant and Exchange Configuration ================" -ForegroundColor DarkCyan
    Write-Host
    
    Verify-ServiceConnections

    $config = Load-Configuration

    # Set some more variables
    $Global:breakGlassUPN = "$($Config.MSPName)BG@$((Get-AzureADTenantDetail).VerifiedDomains[0].Name)"

    Set-AzureADConfig -Config $config
    Set-ExchangeOnlineConfig -Config $config
    Set-MSOLConfig -Config $config

    Set-TeamsConfiguration -Config $config
    Set-SharePointOneDriveConfig -Config $config

    Set-RetentionPolicies -Config $config
    Set-SecurityAlertNotifications -Config $config

    Write-Log "Configuration completed successfully" "INFO"

    # Configure Archive and Litigation Hold if requested
    $Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? (Y/N) (Recommended)"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        # Enable Auto-Expanding Archive
        if (!(Get-OrganizationConfig).AutoExpandingArchiveEnabled) {
            Set-OrganizationConfig -AutoExpandingArchive
            Write-Log "Auto-Expanding Archive feature is now enabled" "INFO"
        }

        # Enable Archive Mailbox for all users
        $ArchiveAnswer = Read-Host "Do you want to enable the Archive mailbox for all user mailboxes? (Y/N) (Recommended)"
        if ($ArchiveAnswer -eq 'y' -or $ArchiveAnswer -eq 'yes') {
            Get-Mailbox -ResultSize Unlimited -Filter { ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox" } | Enable-Mailbox -Archive
            Write-Log "Archive mailbox enabled for all user mailboxes" "INFO"
        }

        # Enable Litigation Hold
        $LegalHoldAnswer = Read-Host "Do you want to enable Litigation Hold for all mailboxes? (Y/N) (Requires Exchange Online Plan 2)"
        if ($LegalHoldAnswer -eq 'y' -or $LegalHoldAnswer -eq 'yes') {
            Get-Mailbox -ResultSize Unlimited -Filter { LitigationHoldEnabled -Eq "False" -AND RecipientTypeDetails -ne "DiscoveryMailbox" } | Set-Mailbox -LitigationHoldEnabled $True
            Write-Log "Litigation Hold enabled for all eligible mailboxes" "INFO"
        }
    }

    Write-Log "All Tenant and Exchange Configuration changes completed successfully" "INFO"
    exit
}
catch {
    Write-Log "An error occurred during execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Error details: $($_.Exception.StackTrace)" "ERROR"
    Write-Host
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "The script will not continue. Please review the log file for detailed information: $logFile and manually check on script section that failed in your Tenant's Admin Center." -ForegroundColor DarkYellow
    Write-Host "This script is safe to run as many times as you want, setting up the tenant as the 'Desired State' based on the parameters and config file." -ForegroundColor DarkYellow
    Write-Host "After confirming and fixing any issues, you may run this script again till completion."  -ForegroundColor DarkYellow
}

Write-Host
Write-Host " - Press any key to escape - " -ForegroundColor Yellow
Read-Host