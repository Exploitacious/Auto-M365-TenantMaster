# M365 ATP Config

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
Write-Host "================ M365 ATP Config ================" -ForegroundColor DarkCyan
Write-Host

$logFile = Join-Path $PSScriptRoot "ATPConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

# Function to get admin credentials
function Get-AdminCredentials {
    if (-not $Global:Credential) {
        $Global:Credential = Get-Credential -Message "Enter your admin credentials"
    }
    return $Global:Credential
}

$adminCredential = Get-AdminCredentials
$CusAdminAddress = $adminCredential.UserName

#################################################
## Pre-Reqs & Variables
#################################################

## Global Variables

# Your MSP's information for alerting and support info for end-user notifications
$MSPAlertAddress = $Config.MSPAlertsAddress
$MSPDomain = ($Config.MSPAlertsAddress -split "@")[1]

# Domains and Senders to whitelist by default from ALL POLICIES. This includes Phishing, Anti-Spam, Etc.. Comma seperated.
$ExcludedDomains = "intuit.com", $MSPDomain | Select-Object -Unique # QB Online has been getting popped for phishing lately. Highly reccomended to include Intuit.
$ExcludedSenders = "connect@e.connect.intuit.com", $Config.MSPAlertsAddress, "advanced-threat-protection@protection.outlook.com" | Select-Object -Unique

# File types to be blacklisted in the Anti-Malware Policy. Additional filetypes here to blacklist seperated by comma with quotes
$NewFileTypeBlacklist = "ade", "adp", "app", "application", "arx", "avb", "bas", "bat", "chm", "class", "cmd", "cnv", "com", "cpl", "dll", "docm", "drv", "exe", "fxp", "gadget", "gms", "hlp", "hta", "inf", "ink", "ins", "isp", "jar", "job", "js", "jse", "lnk", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mpd", "msc", "msi", "msp", "mst", "nlm", "ocx", "ops", "ovl", "paf", "pcd", "pif", "prf", "prg", "ps1", "psd1", "psm", "psm1", "reg", "scf", "scr", "sct", "shb", "shs", "sys", "tlb", "tsp", "url", "vb", "vbe", "vbs", "vdl", "vxd", "wbt", "wiz", "wsc", "wsf", "wsh" | Select-Object -Unique
              
#$MSPSupportMail =  $Config.MSPSupportMail

#$MSPSupportInfo = $Config.MSPSupportInfo

########
# Auto Forward and Disable Junk
function Set-AutoForward {
    try {
        Write-Log "Checking existing forwarding settings for $CusAdminAddress" "INFO"
        $existingForwarding = Get-Mailbox -Identity $CusAdminAddress | Select-Object -ExpandProperty ForwardingSMTPAddress

        if ($null -ne $existingForwarding -and $existingForwarding -eq $MSPAlertAddress) {
            Write-Log "Forwarding is already set to $MSPAlertAddress" "INFO"
        }
        else {
            Write-Log "Setting up automatic forwarding from $CusAdminAddress to $MSPAlertAddress" "INFO"
            Set-Mailbox -Identity $CusAdminAddress -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $MSPAlertAddress
            Write-Log "Forwarding has been successfully configured for the specified mailbox." "INFO"
        }
        
        Get-Mailbox -Identity $CusAdminAddress | Format-List Username, ForwardingSMTPAddress, DeliverToMailboxandForward
        
        Write-Log "Disabling Junk Mailbox on $CusAdminAddress" "INFO"
        Set-MailboxJunkEmailConfiguration -Identity $CusAdminAddress -Enabled $false -ErrorAction Stop
        Write-Log "JunkMailbox has been successfully disabled." "INFO"
    }
    catch {
        Write-Log "Error in Set-AutoForward: $_" "ERROR"
    }
}

#################################################
## Anti-Malware
function Set-AntiMalwarePolicy {
    try {
        Write-Log "Configuring the NEW default Anti-Malware Policy..." "INFO"

        $CurrentTypeBlacklist = Get-MalwareFilterPolicy -Identity Default | Select-Object -Expand FileTypes
        $FileTypeBlacklist = $CurrentTypeBlacklist + $NewFileTypeBlacklist | Select-Object -Unique

        Write-Log "Configuring Custom Anti-Malware Policy" "INFO"

        $MalwarePolicyName = Get-MalwareFilterPolicy -Identity Default
        if ($MalwarePolicyName.AdminDisplayName -eq "Custom Anti-Malware Policy") {
            Write-Log "Default Malware Policy is configured and active. Updating File Definitions..." "INFO"
            $FileTypesAdd = Get-MalwareFilterPolicy -Identity Default | Select-Object -Expand FileTypes
            $FileTypesAdd += $FileTypeBlacklist
            Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true -FileTypes $FileTypesAdd
        }
        else {
            Write-Log "Setting up the Default Anti-Malware Policy" "INFO"
            $MalwarePolicyParam = @{
                'AdminDisplayName' = "Custom Anti-Malware Policy";
                'EnableFileFilter' = $true;
                'FileTypes'        = $FileTypeBlacklist;
                'ZapEnabled'       = $true;
            }
            Set-MalwareFilterPolicy Default @MalwarePolicyParam -MakeDefault
            Write-Log "Default Malware Policy is configured" "INFO"
        }

        # Setup bypass policy for admin
        $MalwarePolicyParamAdmin = @{
            'Name'                                   = "Bypass Malware Filter (for Admin)";
            'AdminDisplayName'                       = "Bypass Malware Filter Policy/Rule for Admin";
            'CustomAlertText'                        = "Malware was received and blocked from being delivered. Review the email received in https://protection.office.com/threatreview";
            'Action'                                 = "DeleteAttachmentAndUseCustomAlertText";
            'InternalSenderAdminAddress'             = $CusAdminAddress;
            'EnableInternalSenderAdminNotifications' = $True;
            'ZapEnabled'                             = $False;
        }
        
        $MalwareRuleParamAdmin = @{
            'Name'                = "Bypass Malware Filter (for Admin)";
            'MalwareFilterPolicy' = "Bypass Malware Filter (for Admin)";
            'SentTo'              = $CusAdminAddress;
            'Enabled'             = $True;
        }
        New-MalwareFilterPolicy @MalwarePolicyParamAdmin
        New-MalwareFilterRule @MalwareRuleParamAdmin

        Write-Log "Anti-Malware Policy has been successfully set." "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiMalwarePolicy: $_" "ERROR"
    }
}

#################################################
## Anti-Phishing
function Set-AntiPhishingPolicy {
    try {
        $AcceptedDomains = Get-AcceptedDomain
        $RecipientDomains = $AcceptedDomains.DomainName

        $AlreadyExcludedPhishSenders = Get-Antiphishpolicy "Office365 AntiPhish Default" | Select-Object -Expand ExcludedSenders
        $AlreadyExcludedPhishDomains = Get-Antiphishpolicy "Office365 AntiPhish Default" | Select-Object -Expand ExcludedDomains
        $WhitelistedPhishSenders = $AlreadyExcludedPhishSenders + $ExcludedSenders | Select-Object -Unique
        $WhitelistedPhishDomains = $AlreadyExcludedPhishDomains + $ExcludedDomains | Select-Object -Unique

        $items = Get-Mailbox | Select-Object DisplayName, UserPrincipalName
        $combined = $items | ForEach-Object { $_.DisplayName + ';' + $_.UserPrincipalName }
        $TargetUserstoProtect = $combined

        Write-Log "Modifying the 'Office365 AntiPhish Default' policy with Anti-Phish Baseline Policy AntiPhish Policy" "INFO"

        $PhishPolicyParam = @{
            'AdminDisplayName'                    = "AntiPhish Policy Imported via PS";
            'Enabled'                             = $true;
            'AuthenticationFailAction'            = 'MoveToJmf';
            'EnableMailboxIntelligence'           = $true;
            'EnableMailboxIntelligenceProtection' = $true;
            'EnableOrganizationDomainsProtection' = $true;
            'EnableSimilarDomainsSafetyTips'      = $true;
            'EnableSimilarUsersSafetyTips'        = $true;
            'EnableSpoofIntelligence'             = $true;
            'EnableUnauthenticatedSender'         = $true;
            'EnableUnusualCharactersSafetyTips'   = $true;
            'MailboxIntelligenceProtectionAction' = 'MoveToJmf';
            'ImpersonationProtectionState'        = 'Automatic';
            'EnableTargetedDomainsProtection'     = $True;
            'TargetedDomainProtectionAction'      = 'Quarantine';
            'TargetedDomainsToProtect'            = $RecipientDomains;
            'EnableTargetedUserProtection'        = $True;
            'TargetedUserProtectionAction'        = 'Quarantine';
            'TargetedUsersToProtect'              = $TargetUserstoProtect;
            'ExcludedDomains'                     = $WhitelistedPhishDomains;
            'ExcludedSenders'                     = $WhitelistedPhishSenders;
            'PhishThresholdLevel'                 = 2;
        }
        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishPolicyParam

        Write-Log "Disabling all the old, non-default phishing rules and policies" "INFO"
        Get-AntiPhishPolicy | Where-Object { $_.IsDefault -eq $false } | Remove-AntiPhishPolicy -Confirm:$false
        Get-AntiPhishRule | Remove-AntiPhishRule -Confirm:$false

        Write-Log "AntiPhish Policy has been successfully configured" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiPhishingPolicy: $_" "ERROR"
    }
}

#################################################
## Anti-Spam (Hosted Content Filter)
function Set-AntiSpamPolicy {
    try {
        Write-Log "Setting up the new Default Inbound Anti-Spam Policy" "INFO"
        
        $HostedContentPolicyParam = @{
            'AddXHeaderValue'                      = "M365 ATP Analysis: ";
            'AdminDisplayName'                     = "Inbound Anti-Spam Policy configured via M365 PS Scripting Tools";
            'AllowedSenders'                       = @{add = $ExcludedSenders };
            'AllowedSenderDomains'                 = @{add = $ExcludedDomains };
            'DownloadLink'                         = $false;
            'SpamAction'                           = 'MoveToJMF';
            'HighConfidenceSpamAction'             = 'quarantine';
            'PhishSpamAction'                      = 'quarantine';
            'HighConfidencePhishAction'            = 'quarantine';
            'BulkSpamAction'                       = 'MoveToJMF';
            'BulkThreshold'                        = '8';
            'QuarantineRetentionPeriod'            = 30;
            'InlineSafetyTipsEnabled'              = $true;
            'EnableEndUserSpamNotifications'       = $true;
            'EndUserSpamNotificationFrequency'     = 1;
            'EndUserSpamNotificationCustomSubject' = "Daily Email Quarantine Report";
            'RedirectToRecipients'                 = $CusAdminAddress;
            'ModifySubjectValue'                   = "PhishSpamAction,HighConfidenceSpamAction,BulkSpamAction,SpamAction";
            'SpamZapEnabled'                       = $true;
            'PhishZapEnabled'                      = $true;
            'MarkAsSpamBulkMail'                   = 'on';
            'IncreaseScoreWithImageLinks'          = 'off';
            'IncreaseScoreWithNumericIps'          = 'on';
            'IncreaseScoreWithRedirectToOtherPort' = 'on';
            'IncreaseScoreWithBizOrInfoUrls'       = 'on';
            'MarkAsSpamEmptyMessages'              = 'on';
            'MarkAsSpamJavaScriptInHtml'           = 'on';
            'MarkAsSpamFramesInHtml'               = 'off';
            'MarkAsSpamObjectTagsInHtml'           = 'off';
            'MarkAsSpamEmbedTagsInHtml'            = 'off';
            'MarkAsSpamFormTagsInHtml'             = 'off';
            'MarkAsSpamWebBugsInHtml'              = 'on';
            'MarkAsSpamSensitiveWordList'          = 'off';
            'MarkAsSpamSpfRecordHardFail'          = 'on';
            'MarkAsSpamFromAddressAuthFail'        = 'on';
            'MarkAsSpamNdrBackscatter'             = 'on';
        }
        Set-HostedContentFilterPolicy Default @HostedContentPolicyParam -MakeDefault
        
        Write-Log "Inbound Anti-Spam Policy is deployed and set as Default." "INFO"
        
        $Answer2 = Read-Host "Do you want to DISABLE (not delete) custom anti-spam rules, so that only Anti-Spam Policy Apply? This is recommended unless you have other custom rules in use. Type Y or N and press Enter to continue"
        if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {
            Get-HostedContentFilterRule | Disable-HostedContentFilterRule -Confirm:$false
            Write-Log "All custom anti-spam rules have been disabled; they have not been deleted" "INFO"
            Write-Log "Anti-Spam Policy is set as Default and is the only enforcing Inbound Rule." "INFO"
        }
        else {
            Write-Log "Custom rules have been left enabled. Please manually verify that the new Default Policy is being used in Protection.Office.com." "WARNING"
        }
        
        Write-Log "Setting up a new Inbound/Outbound & Forwarding Anti-Spam Policy for Admin & Allowed-Forwarding group" "INFO"
        
        $OutboundPolicyForITAdmin = @{
            'Name'                          = "Allow Outbound Forwarding Policy"
            'AdminDisplayName'              = "Unrestricted Outbound Forwarding Policy from specified mailboxes (Should only be used for Admin and Service Mailboxes)";
            'AutoForwardingMode'            = "On";
            'RecipientLimitExternalPerHour' = 10000;
            'RecipientLimitInternalPerHour' = 10000;
            'RecipientLimitPerDay'          = 10000;
            'ActionWhenThresholdReached'    = 'Alert';
            'BccSuspiciousOutboundMail'     = $false
        }
        New-HostedOutboundSpamFilterPolicy @OutboundPolicyForITAdmin
        
        $OutboundRuleForAdmin = @{
            'Name'                           = "Allow Outbound Forwarding Rule";
            'Comments'                       = "Unrestricted Outbound Forwarding Policy from specified mailbox";
            'HostedOutboundSpamFilterPolicy' = "Allow Outbound Forwarding Policy";
            'Enabled'                        = $true;
            'From'                           = $CusAdminAddress;
            'Priority'                       = 0
        }
        New-HostedOutboundSpamFilterRule @OutboundRuleForAdmin
        
        $AdminIndoundContentPolicyParam = @{
            'Name'                                 = "Unrestricted Content Filter Policy for Admin"
            'AdminDisplayName'                     = "Inbound ADMIN Policy configured via M365 PS Scripting Tools";
            'AddXHeaderValue'                      = "Unrestricted-Admin-Mail: ";
            'RedirectToRecipients'                 = $MSPAlertAddress;
            'DownloadLink'                         = $false;
            'SpamAction'                           = 'AddXHeader';
            'HighConfidenceSpamAction'             = 'AddXHeader';
            'PhishSpamAction'                      = 'AddXHeader';
            'HighConfidencePhishAction'            = 'Redirect';
            'BulkSpamAction'                       = 'AddXHeader';
            'InlineSafetyTipsEnabled'              = $true;
            'ModifySubjectValue'                   = "PhishSpamAction,HighConfidenceSpamAction,BulkSpamAction,SpamAction";
            'SpamZapEnabled'                       = $false;
            'PhishZapEnabled'                      = $false;
            'QuarantineRetentionPeriod'            = 30;
            'MarkAsSpamBulkMail'                   = 'off';
            'IncreaseScoreWithImageLinks'          = 'off';
            'IncreaseScoreWithNumericIps'          = 'off';
            'IncreaseScoreWithRedirectToOtherPort' = 'off';
            'IncreaseScoreWithBizOrInfoUrls'       = 'off';
            'MarkAsSpamEmptyMessages'              = 'off';
            'MarkAsSpamJavaScriptInHtml'           = 'off';
            'MarkAsSpamFramesInHtml'               = 'off';
            'MarkAsSpamObjectTagsInHtml'           = 'off';
            'MarkAsSpamEmbedTagsInHtml'            = 'off';
            'MarkAsSpamFormTagsInHtml'             = 'off';
            'MarkAsSpamWebBugsInHtml'              = 'off';
            'MarkAsSpamSensitiveWordList'          = 'off';
            'MarkAsSpamSpfRecordHardFail'          = 'off';
            'MarkAsSpamFromAddressAuthFail'        = 'off';
            'MarkAsSpamNdrBackscatter'             = 'off';
        }
        New-HostedContentFilterPolicy @AdminIndoundContentPolicyParam
        
        $AdminIndoundContentRuleParam = @{
            'Name'                      = "Unrestricted Content Filter Rule for Admin"
            'Comments'                  = "Inbound ADMIN Rule configured via M365 PS Scripting Tools";
            'HostedContentFilterPolicy' = "Unrestricted Content Filter Policy for Admin";
            'Enabled'                   = $true;
            'Confirm'                   = $false;
            'Priority'                  = "0";
            'SentTo'                    = $CusAdminAddress
        }
        New-HostedContentFilterRule @AdminIndoundContentRuleParam
        
        Write-Log "Successfully Set up Policy + Rule for Admin" "INFO"
        
        $OutboundPolicyDefault = @{
            'AdminDisplayName'                          = "Outbound Anti-Spam Policy configured via M365 PS Scripting Tools";
            'AutoForwardingMode'                        = "Off";
            'RecipientLimitExternalPerHour'             = 100;
            'RecipientLimitInternalPerHour'             = 100;
            'RecipientLimitPerDay'                      = 500;
            'ActionWhenThresholdReached'                = 'Alert';
            'BccSuspiciousOutboundMail'                 = $true;
            'BccSuspiciousOutboundAdditionalRecipients' = $CusAdminAddress
        }
        Set-HostedOutboundSpamFilterPolicy Default @OutboundPolicyDefault
        
        Write-Log "The admin forwarding and default outbound spam filter have been set to Outbound Anti-Spam Policy" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiSpamPolicy: $_" "ERROR"
    }
}
  
#################################################
## Safe-Attachments
function Set-SafeAttachPolicy {
    try {
        Write-Log "Creating the new Safe Attachments Policy..." "INFO"
        Write-Log "Removing old policies and rules to set up the new ones." "INFO"
        
        Get-SafeAttachmentPolicy | Remove-SafeAttachmentPolicy -Confirm:$false
        Get-SafeAttachmentRule | Disable-SafeAttachmentRule -Confirm:$false
        
        $SafeAttachmentPolicyParamAdmin = @{
            'Name'             = "Safe Attachments Bypass for Admin PS";
            'AdminDisplayName' = "Bypass Rule for Admin/Alerts Mailbox";
            'Action'           = "Allow";
            'Redirect'         = $false;
            'ActionOnError'    = $false;
            'Enable'           = $false
        }
        New-SafeAttachmentPolicy @SafeAttachmentPolicyParamAdmin
        
        $SafeAttachmentRuleParamAdmin = @{
            'Name'                 = "Safe Attachments Bypass for Admin PS";
            'SafeAttachmentPolicy' = "Safe Attachments Bypass for Admin PS";
            'SentTo'               = $CusAdminAddress;
            'Enabled'              = $true
            'Priority'             = 0
        }
        New-SafeAttachmentRule @SafeAttachmentRuleParamAdmin
        
        $SafeAttachmentPolicyParam = @{
            'Name'             = "Safe Attachments Policy";
            'AdminDisplayName' = "Safe Attachments Policy configured via M365 PS Scripting Tools";
            'Action'           = "DynamicDelivery";
            'Redirect'         = $true;
            'RedirectAddress'  = $CusAdminAddress;
            'ActionOnError'    = $true;
            'Enable'           = $true
        }
        New-SafeAttachmentPolicy @SafeAttachmentPolicyParam
        
        $SafeAttachRuleParam = @{
            'Name'                 = "Safe Attachments Rule";
            'SafeAttachmentPolicy' = "Safe Attachments Policy";
            'Comments'             = "Safe Attachments Rule configured via M365 PS Scripting Tools";
            'RecipientDomainIs'    = $RecipientDomains;
            'ExceptIfSentTo'       = $CusAdminAddress;
            'Enabled'              = $true;
            'Priority'             = 1
        }
        New-SafeAttachmentRule @SafeAttachRuleParam
        
        Write-Log "The new Safe Attachments Policies and rules have been deployed." "INFO"
    }
    catch {
        Write-Log "Error in Set-SafeAttachPolicy: $_" "ERROR"
    }
}

#################################################
## Safe-Links
function Set-SafeLinksPolicy {
    try {
        Write-Log "Creating new policies for Safe-Links" "INFO"
        Write-Log "Removing old policies and rules to set up the new ones." "INFO"
        
        Get-SafeLinksPolicy | Remove-SafeLinksPolicy -Confirm:$false
        Get-SafeLinksRule | Remove-SafeLinksRule -Confirm:$false
        
        $AtpSafeLinksO365Param = @{
            'EnableATPForSPOTeamsODB'       = $true;
            'EnableSafeLinksForO365Clients' = $true;
            'EnableSafeDocs'                = $true;
            'AllowSafeDocsOpen'             = $false;
            'TrackClicks'                   = $true;
            'AllowClickThrough'             = $false
        }
        
        Set-AtpPolicyForO365 @AtpSafeLinksO365Param
        
        Write-Log "Global Default Safe Links policy has been set." "INFO"
        Write-Log "Creating new policy: 'Safe Links Policy'" "INFO"
        
        $SafeLinksPolicyParamAdmin = @{
            'Name'                       = "Bypass Safelinks for Admin";
            'AdminDisplayName'           = "Bypass Safe Links Policy configured via M365 PS Scripting Tools";
            'ScanUrls'                   = $false;
            'DeliverMessageAfterScan'    = $False;
            'EnableForInternalSenders'   = $False;
            'AllowClickThrough'          = $True;
            'TrackClicks'                = $True;
            'EnableOrganizationBranding' = $False;
        }
        New-SafeLinksPolicy @SafeLinksPolicyParamAdmin
        
        $SafeLinksRuleParamAdmin = @{
            'Name'            = "Bypass Safelinks for Admin";
            'Comments'        = "Bypass Safe Links Policy configured via M365 PS Scripting Tools";
            'SafeLinksPolicy' = "Bypass Safelinks for Admin";
            'SentTo'          = $CusAdminAddress;
            'Enabled'         = $true;
            'Priority'        = 0
        }
        New-SafeLinksRule @SafeLinksRuleParamAdmin
        
        $SafeLinksPolicyParam = @{
            'Name'                          = "Safe Links Policy";
            'AdminDisplayName'              = "Safe Links Policy configured via M365 PS Scripting Tools";
            'CustomNotificationText'        = "Only click on links from people you trust!"
            'EnableSafeLinksForTeams'       = $true;
            'EnableSafeLinksForEmail'       = $true;
            'ScanUrls'                      = $true;
            'DeliverMessageAfterScan'       = $true;
            'EnableForInternalSenders'      = $true;
            'TrackClicks'                   = $true;
            'AllowClickThrough'             = $false;
            'EnableOrganizationBranding'    = $true;
            'UseTranslatedNotificationText' = $true;
        }
        New-SafeLinksPolicy @SafeLinksPolicyParam 
        
        $SafeLinksRuleParam = @{
            'Name'              = "Safe Links Rule";
            'Comments'          = "Safe Links Rule configured via M365 PS Scripting Tools";
            'SafeLinksPolicy'   = "Safe Links Policy";
            'RecipientDomainIs' = $RecipientDomains;
            'ExceptIfSentTo'    = $CusAdminAddress;
            'Enabled'           = $true;
            'Priority'          = 1
        }
        New-SafeLinksRule @SafeLinksRuleParam
        
        Write-Log "Safe Links Global Defaults, Policies and Rules have been successfully configured" "INFO"
        
        # For some reason, this one policy fails to apply even though it's configured just fine. Try/Catch apparently makes powershell happy.
        Try {
            Get-SafeAttachmentRule "Safe Attachments Rule" -ErrorAction Stop
        }
        Catch {
            Write-Log "Safe Attachments Rule not found. Creating it now." "WARNING"
            New-SafeAttachmentRule -Name "Safe Attachments Rule" -SafeAttachmentPolicy "Safe Attachments Policy" -Comments "Safe Attachments Rule configured via M365 PS Scripting Tools" -RecipientDomainIs $RecipientDomains -ExceptIfSentTo $CusAdminAddress -Enabled $true -Priority 1
        }
        
        Write-Log "Safe Attachments and Safe Links configuration completed." "INFO"
    }
    catch {
        Write-Log "Error in Set-SafeLinksPolicy: $_" "ERROR"
    }
}


## Main Script Logic
Set-AutoForward
Set-AntiMalwarePolicy
Set-AntiPhishingPolicy
Set-AntiSpamPolicy
Set-SafeAttachPolicy
Set-SafeLinksPolicy