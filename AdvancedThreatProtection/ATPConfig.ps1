# M365 Defender for Office 365 Configuration Script
# Version 2.0
# This script configures Microsoft 365 Defender for Office 365 (Plan 2) settings

# Verify/Elevate Admin Session
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Initialize variables
$scriptPath = $PSScriptRoot
$parentDir = Split-Path $scriptPath -Parent
$logFile = Join-Path $scriptPath "ATPConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Check parent directory
if ((Split-Path $parentDir -Leaf) -ne "Auto-M365-TenantMaster") {
    throw "The parent directory must be Auto-M365-TenantMaster."
}
# Construct the path to the config file in the parent directory
$configFile = Join-Path $parentDir "config.json"
# Import configuration
if (Test-Path $configFile) {
    $Config = Get-Content $configFile | ConvertFrom-Json
}
else {
    Write-Error "Configuration file not found. Please create a config.json file in the script directory."
    exit
}

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

###################################
# Function to set up auto-forwarding and disable junk email
function Set-AutoForwardAndJunkConfig {
    param (
        [string]$CusAdminAddress,
        [string]$MSPAlertsAddress
    )
    try {
        Write-Log "Configuring auto-forwarding and junk email settings" "INFO"
        Set-Mailbox -Identity $CusAdminAddress -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $MSPAlertsAddress
        Set-MailboxJunkEmailConfiguration -Identity $CusAdminAddress -Enabled $false
        Write-Log "Auto-forwarding and junk email configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-AutoForwardAndJunkConfig: $_" "ERROR"
    }
}

###################################
# Function to configure Anti-Malware policy
function Set-AntiMalwarePolicy {
    param (
        [string]$CusAdminAddress
    )
    try {
        Write-Log "Configuring Custom Anti-Malware Policy" "INFO"

        $NewFileTypeBlacklist = "ade", "adp", "app", "application", "arx", "avb", "bas", "bat", "chm", "class", "cmd", "cnv", "com", "cpl", "dll", "docm", "drv", "exe", "fxp", "gadget", "gms", "hlp", "hta", "inf", "ink", "ins", "isp", "jar", "job", "js", "jse", "lnk", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mpd", "msc", "msi", "msp", "mst", "nlm", "ocx", "ops", "ovl", "paf", "pcd", "pif", "prf", "prg", "ps1", "psd1", "psm", "psm1", "reg", "scf", "scr", "sct", "shb", "shs", "sys", "tlb", "tsp", "url", "vb", "vbe", "vbs", "vdl", "vxd", "wbt", "wiz", "wsc", "wsf", "wsh" | Select-Object -Unique
        $CurrentTypeBlacklist = Get-MalwareFilterPolicy -Identity Default | Select-Object -Expand FileTypes
        $FileTypeBlacklist = $CurrentTypeBlacklist + $NewFileTypeBlacklist | Select-Object -Unique

        $MalwarePolicyName = Get-MalwareFilterPolicy -Identity Default
        if ($MalwarePolicyName.AdminDisplayName -eq "Custom Anti-Malware Policy") {
            Write-Log "Default Malware Policy is configured and active. Updating File Definitions." "INFO"
            $FileTypesAdd = Get-MalwareFilterPolicy -Identity Default | Select-Object -Expand FileTypes
            $FileTypesAdd += $FileTypeBlacklist
            Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true -FileTypes $FileTypesAdd
        }
        else {
            Write-Log "Modifying the Default Anti-Malware Policy" "INFO"
            $MalwarePolicyParam = @{
                'AdminDisplayName'                       = "Custom Anti-Malware Policy";
                'EnableExternalSenderAdminNotifications' = $true;
                'EnableInternalSenderAdminNotifications' = $true;
                'ExternalSenderAdminAddress'             = $CusAdminAddress;
                'InternalSenderAdminAddress'             = $CusAdminAddress;
                'EnableFileFilter'                       = $true;
                'FileTypes'                              = $FileTypeBlacklist;
                'ZapEnabled'                             = $true;
            }
            Set-MalwareFilterPolicy Default @MalwarePolicyParam -MakeDefault
            Write-Log "Default Global Malware Policy is configured" "INFO"
        }

        $MalwarePolicyParamAdmin = @{
            'Name'             = "Bypass Malware Filter for Admin";
            'AdminDisplayName' = "Bypass Malware Filter Policy/Rule for Admin";
            'EnableFileFilter' = $False;
            'ZapEnabled'       = $False;
        }

        $MalwareRuleParamAdmin = @{
            'Name'                = "Bypass Malware Filter for Admin";
            'MalwareFilterPolicy' = "Bypass Malware Filter for Admin";
            'SentTo'              = $CusAdminAddress;
            'Enabled'             = $True;
        }

        try {
            # Test Existing
            $testMalwarePolicy = Get-MalwareFilterPolicy -Identity "Bypass Malware Filter for Admin" -ErrorAction Stop
            if ($testMalwarePolicy) {
                Write-Log "Bypass Malware Filter for Admin - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Admin-Bypass Anti-Malware Configuration" "INFO"

            # Setup bypass policy for admin

            New-MalwareFilterPolicy @MalwarePolicyParamAdmin
            Write-Log "Admin-Bypass Anti-Malware Policy configuration completed" "INFO"
        
            New-MalwareFilterRule @MalwareRuleParamAdmin
            Write-Log "Admin-Bypass Anti-Malware Rule configuration completed" "INFO"
        }
    }
    catch {
        Write-Log "Error in AntiMalwarePolicy: $_" "ERROR"
    }
}

###################################
# Function to configure Anti-Phishing policy
function Set-AntiPhishingPolicy {

    # Set Domains
    $AcceptedDomains = Get-AcceptedDomain
    $RecipientDomains = $AcceptedDomains.DomainName

    # Add any excluded / Whitelisted senders
    # ExcludedDomains                     = $ExcludedDomains
    # ExcludedSenders                     = $ExcludedSenders

    # Migrate Whitelists
    $AlreadyExcludedPhishSenders = Get-Antiphishpolicy "Office365 AntiPhish Default" | Select-Object -Expand ExcludedSenders
    $AlreadyExcludedPhishDomains = Get-Antiphishpolicy "Office365 AntiPhish Default" | Select-Object -Expand ExcludedDomains
    $WhitelistedPhishSenders = $AlreadyExcludedPhishSenders + $ExcludedSenders | Select-Object -Unique
    $WhitelistedPhishDomains = $AlreadyExcludedPhishDomains + $ExcludedDomains | Select-Object -Unique

    try {
        # Set New Custom Defaults
        Write-Log "Configuring Anti-Phishing Policy" "INFO"
        
        $policyParams = @{
            Identity                                      = "Office365 AntiPhish Default"
            AdminDisplayName                              = "Custom Anti-Phishing Policy set on $(Get-Date -Format 'yyyyMMdd')"
            AuthenticationFailAction                      = "Quarantine"
            DmarcQuarantineAction                         = "Quarantine"
            DmarcRejectAction                             = "Reject"
            EnableFirstContactSafetyTips                  = $true
            EnableMailboxIntelligence                     = $true
            EnableMailboxIntelligenceProtection           = $true
            EnableOrganizationDomainsProtection           = $true
            EnableSimilarDomainsSafetyTips                = $true
            EnableSimilarUsersSafetyTips                  = $true
            EnableSpoofIntelligence                       = $true
            EnableUnauthenticatedSender                   = $true
            EnableUnusualCharactersSafetyTips             = $true
            EnableViaTag                                  = $true
            ExcludedDomains                               = $WhitelistedPhishDomains
            ExcludedSenders                               = $WhitelistedPhishSenders
            HonorDmarcPolicy                              = $true
            ImpersonationProtectionState                  = "Automatic"
            MailboxIntelligenceProtectionAction           = "Quarantine"
            MailboxIntelligenceProtectionActionRecipients = $CusAdminAddress
            PhishThresholdLevel                           = 2
        }
        Set-AntiPhishPolicy @policyParams -MakeDefault

        Write-Log "Anti-Phishing Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiPhishingPolicy: $_" "ERROR"
    }
}

###################################
# Function to configure Anti-Spam policy
function Set-AntiSpamPolicy {
    
    # Add any excluded / Whitelisted senders
    # $ExcludedDomains                     = 
    # $ExcludedSenders                     = 
    
    # Migrate Email White lists
    $AlreadyExcludedSpamSenders = Get-HostedContentFilterPolicy -Identity "Default" | Select-Object -Expand AllowedSenders
    $AlreadyExcludedSpamDomains = Get-HostedContentFilterPolicy -Identity "Default" | Select-Object -Expand AllowedSenderDomains
    $WhitelistedSpamSenders = $AlreadyExcludedSpamSenders + $ExcludedSenders | Select-Object -Unique
    $WhitelistedSpamDomains = $AlreadyExcludedSpamDomains + $ExcludedDomains | Select-Object -Unique
        
    # Migrate Email Black lists
    $AlreadyBlacklistedSpamSenders = Get-HostedContentFilterPolicy -Identity "Default" | Select-Object -Expand BlockedSenders
    $AlreadyBlacklistedSpamDomains = Get-HostedContentFilterPolicy -Identity "Default" | Select-Object -Expand BlockedSenderDomains
    $BlackListedSpamSenders = $AlreadyBlacklistedSpamSenders + $ExcludedSenders | Select-Object -Unique
    $BlackListedSpamDomains = $AlreadyBlacklistedSpamDomains + $ExcludedDomains | Select-Object -Unique

    # Configure Anti-Spam Settings
    try {
        Write-Log "Configuring Default Anti-Spam Inbound Policy" "INFO"
        $policyParams = @{
            Identity                             = "Default"
            AdminDisplayName                     = "Custom Anti-Spam Policy set on $(Get-Date -Format 'yyyyMMdd')"
            BulkSpamAction                       = "MoveToJmf"
            BulkThreshold                        = 6
            PhishSpamAction                      = "Quarantine"
            SpamAction                           = "Quarantine"
            HighConfidencePhishAction            = "Quarantine"
            HighConfidencePhishQuarantineTag     = "AdminOnlyAccessPolicy"
            HighConfidenceSpamAction             = "Quarantine"
            IncreaseScoreWithBizOrInfoUrls       = "On"
            IncreaseScoreWithNumericIps          = "On"
            IncreaseScoreWithRedirectToOtherPort = "On"
            InlineSafetyTipsEnabled              = $true
            IntraOrgFilterState                  = "HighConfidenceSpam"
            MarkAsSpamBulkMail                   = "On"
            MarkAsSpamFromAddressAuthFail        = "On"
            MarkAsSpamJavaScriptInHtml           = "On"
            MarkAsSpamNdrBackscatter             = "On"
            MarkAsSpamSpfRecordHardFail          = "On"
            SpamZapEnabled                       = $true
            PhishZapEnabled                      = $true
            QuarantineRetentionPeriod            = 30
            AllowedSenders                       = $WhitelistedSpamSenders
            AllowedSenderDomains                 = $WhitelistedSpamDomains
            BlockedSenderDomains                 = $BlackListedSpamSenders
            BlockedSenders                       = $BlackListedSpamDomains

        }
        Set-HostedContentFilterPolicy @policyParams -MakeDefault
        Write-Log "Configured Default Anti-Spam Policy" "INFO"

        Write-Log "Configuring Default Anti-Spam Outbound Policy" "INFO"
        $OutboundPolicyDefault = @{
            Identity                                    = "Default"
            'AdminDisplayName'                          = "Custom Outbound Mail Policy set on $(Get-Date -Format 'yyyyMMdd')";
            'AutoForwardingMode'                        = "Off";
            'RecipientLimitExternalPerHour'             = 100;
            'RecipientLimitInternalPerHour'             = 100;
            'RecipientLimitPerDay'                      = 500;
            'ActionWhenThresholdReached'                = 'Alert';
            NotifyOutboundSpam                          = $true
            NotifyOutboundSpamRecipients                = $CusAdminAddress
            'BccSuspiciousOutboundMail'                 = $true;
            'BccSuspiciousOutboundAdditionalRecipients' = $CusAdminAddress
        }
        Set-HostedOutboundSpamFilterPolicy @OutboundPolicyDefault
        Write-Log "Configured Default Anti-Spam Outbound Policy" "INFO"


        # Bypass Inbound policy for admin
        $bypassInboundPolicyParams = @{
            Name                                   = "Bypass Spam Filter for Admin"
            AdminDisplayName                       = "Bypass Spam Filter for Admin set on $(Get-Date -Format 'yyyyMMdd')"
            'SpamAction'                           = 'AddXHeader'
            'HighConfidenceSpamAction'             = 'Redirect'
            'PhishSpamAction'                      = 'AddXHeader'
            'BulkSpamAction'                       = 'AddXHeader'
            'HighConfidencePhishAction'            = 'Redirect'
            'RedirectToRecipients'                 = $Config.MSPAlertsAddress
            'AddXHeaderValue'                      = "Unrestricted-Admin-Mail-ATP-BYPASS"
            'SpamZapEnabled'                       = $false
            'PhishZapEnabled'                      = $false
            'QuarantineRetentionPeriod'            = 30
            'BulkThreshold'                        = 9
            'MarkAsSpamBulkMail'                   = 'off'
            'IncreaseScoreWithImageLinks'          = 'off'
            'IncreaseScoreWithNumericIps'          = 'off'
            'IncreaseScoreWithRedirectToOtherPort' = 'off'
            'IncreaseScoreWithBizOrInfoUrls'       = 'off'
            'MarkAsSpamEmptyMessages'              = 'off'
            'MarkAsSpamJavaScriptInHtml'           = 'off'
            'MarkAsSpamFramesInHtml'               = 'off'
            'MarkAsSpamObjectTagsInHtml'           = 'off'
            'MarkAsSpamEmbedTagsInHtml'            = 'off'
            'MarkAsSpamFormTagsInHtml'             = 'off'
            'MarkAsSpamWebBugsInHtml'              = 'off'
            'MarkAsSpamSensitiveWordList'          = 'off'
            'MarkAsSpamSpfRecordHardFail'          = 'off'
            'MarkAsSpamFromAddressAuthFail'        = 'off'
            'MarkAsSpamNdrBackscatter'             = 'off'
        }
        $bypassInboundRuleParams = @{
            Name                      = "Bypass Spam Filter for Admin Rule"
            HostedContentFilterPolicy = "Bypass Spam Filter for Admin"
            'Enabled'                 = $true
            'Priority'                = "0"
            'SentTo'                  = $CusAdminAddress
        }
        # Inbound Admin Policy
        try {
            # Test Existing
            $testAdminSpamPolicy = Get-HostedContentFilterPolicy -Identity "Bypass Spam Filter for Admin" -ErrorAction Stop
            if ($testAdminSpamPolicy) {
                Write-Log "Bypass Spam Filter for Admin - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Admin-Bypass Anti-Spam Configuration" "INFO"

            # Setup bypass policy for admin

            New-HostedContentFilterPolicy @bypassInboundPolicyParams
            Write-Log "Admin-Bypass Anti-Spam Policy configuration completed" "INFO"
        
            New-HostedContentFilterRule @bypassInboundRuleParams
            Write-Log "Admin-Bypass Anti-Spam Rule configuration completed" "INFO"
        }

        # Bypass Outbound policy
        $OutboundPolicyForAdmin = @{
            'Name'                          = "Bypass Outbound Policy for Admin"
            'AdminDisplayName'              = "Unrestricted Outbound Forwarding Policy from specified mailboxes (Should only be used for Admin and Service Mailboxes)";
            'AutoForwardingMode'            = "On";
            'RecipientLimitExternalPerHour' = 10000;
            'RecipientLimitInternalPerHour' = 10000;
            'RecipientLimitPerDay'          = 10000;
            'ActionWhenThresholdReached'    = 'Alert';
            'BccSuspiciousOutboundMail'     = $false
        }
        $OutboundRuleForAdmin = @{
            'Name'                           = "Bypass Outbound Rule for Admin";
            'Comments'                       = "Unrestricted Outbound Forwarding Policy from specified mailbox";
            'HostedOutboundSpamFilterPolicy' = "Bypass Outbound Policy for Admin";
            'Enabled'                        = $true;
            'From'                           = $CusAdminAddress;
            'Priority'                       = 0
        }
        # Outbound Admin Policy
        try {
            # Test Existing
            $testAdminSpamPolicy = Get-HostedOutboundSpamFilterPolicy -Identity "Bypass Outbound Policy for Admin" -ErrorAction Stop
            if ($testAdminSpamPolicy) {
                Write-Log "Bypass Spam Filter for Admin - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Admin-Bypass Anti-Spam Outbound Configuration" "INFO"

            # Setup bypass policy for admin

            New-HostedOutboundSpamFilterPolicy @OutboundPolicyForAdmin
            Write-Log "Admin-Bypass Anti-Spam Outbound Policy configuration completed" "INFO"
        
            New-HostedOutboundSpamFilterRule @OutboundRuleForAdmin
            Write-Log "Admin-Bypass Anti-Spam Outbound Rule configuration completed" "INFO"
        }

        Write-Log "Anti-Spam Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiSpamPolicy: $_" "ERROR"
    }
}

# Function to configure Safe Attachments policy
function Set-SafeAttachmentsPolicy {
    try {
        Write-Log "Configuring Default Safe Attachments Policy" "INFO"
        
        # Create bypass policy for admin
        $bypassPolicyParams = @{
            Name             = "Bypass Safe Attachments for Admin"
            AdminDisplayName = "Bypass Safe Attachments for Admin"
            Action           = "Allow"
            Enable           = $true
        }
        $bypassRuleParams = @{
            Name                 = "Bypass Safe Attachments Rule for Admin"
            SafeAttachmentPolicy = "Bypass Safe Attachments for Admin"
            SentTo               = $CusAdminAddress
            Enabled              = $true
            Priority             = 0
        }
        # Configure Bypass Safe Attachments for Admin
        try {
            # Test Existing
            $testAdminSafeAttach = Get-SafeAttachmentPolicy -Identity "Bypass Safe Attachments for Admin" -ErrorAction Stop
            if ($testAdminSafeAttach) {
                Write-Log "Bypass Safe Attachments for Admin - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Bypass Safe Attachments for Admin Policy Configuration" "INFO"
        
            # Setup Default Safe Attachments Policy
        
            New-SafeAttachmentPolicy @bypassPolicyParams
            Write-Log "Bypass Safe Attachments for Admin Policy configuration completed" "INFO"
                
            New-SafeAttachmentRule @bypassRuleParams
            Write-Log "Bypass Safe Attachments for Admin Rule configuration completed" "INFO"
        }

        # Default Safe Attach Params
        $policyParams = @{
            Name             = "Default Safe Attachments Policy"
            AdminDisplayName = "Default Safe Attachments Policy"
            Action           = "Block"
            Enable           = $true
            Redirect         = $true
            RedirectAddress  = $CusAdminAddress
        }
        $ruleParams = @{
            Name                 = "Default Safe Attachments Rule"
            SafeAttachmentPolicy = "Default Safe Attachments Policy"
            Enabled              = $true
            Priority             = 1
        }
        # Default Safe Attachment
        try {
            # Test Existing
            $testDefaultSafeAttach = Get-SafeAttachmentPolicy -Identity "Default Safe Attachments Policy" -ErrorAction Stop
            if ($testDefaultSafeAttach) {
                Write-Log "Default Safe Attachments Policy - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Default Safe Attachments Policy Configuration" "INFO"

            # Setup Default Safe Attachments Policy

            New-SafeAttachmentPolicy @policyParams
            Write-Log "Default Safe Attachments Policy configuration completed" "INFO"
        
            New-SafeAttachmentRule @ruleParams
            Write-Log "Default Safe Attachments Rule configuration completed" "INFO"
        }

        Write-Log "All Safe Attachments Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-SafeAttachmentsPolicy: $_" "ERROR"
    }
}

# Function to configure Safe Links policy
function Set-SafeLinksPolicy {
    param (
        [string]$CusAdminAddress
    )
    try {
        Write-Log "Configuring Safe Links Policy" "INFO"
        
        # Bypass policy params for admin
        $bypassPolicyParams = @{
            Name                     = "Bypass Safe Links for Admin"
            AdminDisplayName         = "Bypass Safe Links for Admin"
            EnableSafeLinksForEmail  = $false
            EnableSafeLinksForTeams  = $false
            EnableSafeLinksForOffice = $false
            TrackClicks              = $false
            AllowClickThrough        = $true
            ScanUrls                 = $false
            EnableForInternalSenders = $false
            DeliverMessageAfterScan  = $false
            DisableUrlRewrite        = $true
        }
        $bypassRuleParams = @{
            Name            = "Bypass Safe Links Rule for Admin"
            SafeLinksPolicy = "Bypass Safe Links for Admin"
            SentTo          = $CusAdminAddress
            Enabled         = $true
            Priority        = 0
        }
        # Bypass Safe Links
        try {
            # Test Existing
            $testAdminSafeLink = Get-SafeLinksPolicy -Identity "Bypass Safe Links for Admin" -ErrorAction Stop
            if ($testAdminSafeLink) {
                Write-Log "Bypass Safe Links for Admin - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Bypass Safe Links for Admin Configuration" "INFO"

            # Setup Default Safe Attachments Policy

            New-SafeLinksPolicy @bypassPolicyParams
            Write-Log "Bypass Safe Links for Admin configuration completed" "INFO"
        
            New-SafeLinksRule @bypassRuleParams
            Write-Log "Bypass Safe Links for Admin Rule configuration completed" "INFO"
        }

        # Default Safe Link Param
        $policyParams = @{
            Name                     = "Default Safe Links Policy"
            AdminDisplayName         = "Default Safe Links Policy"
            EnableSafeLinksForEmail  = $true
            EnableSafeLinksForTeams  = $true
            EnableSafeLinksForOffice = $true
            TrackClicks              = $true
            AllowClickThrough        = $false
            ScanUrls                 = $true
            EnableForInternalSenders = $true
            DeliverMessageAfterScan  = $true
            DisableUrlRewrite        = $false
            CustomNotificationText   = "The link you clicked was scanned by our Safe Links feature."
        }
        $ruleParams = @{
            Name            = "Default Safe Links Rule"
            SafeLinksPolicy = "Default Safe Links Policy"
            Enabled         = $true
            Priority        = 1
        }
        # Default Safe Links Policy
        try {
            # Test Existing
            $testDefaultSafeLink = Get-SafeLinksPolicy -Identity "Default Safe Links Policy" -ErrorAction Stop
            if ($testDefaultSafeLink) {
                Write-Log "Default Safe Links Policy - Already Exists" "INFO"
            }
        }
        catch {
            # Write New
            Write-Log "Starting Default Safe Links Policy Configuration" "INFO"
        
            # Setup Default Safe Attachments Policy
        
            New-SafeLinksPolicy @policyParams
            Write-Log "Default Safe Links Policy configuration completed" "INFO"
                
            New-SafeLinksRule @ruleParams
            Write-Log "Default Safe Links Rule configuration completed" "INFO"
        }

        Write-Log "Safe Links Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-SafeLinksPolicy: $_" "ERROR"
    }
}

# Function to configure Tenant Allow/Block List
function Set-TenantAllowBlockList {
    param (
        [array]$AllowedSenders,
        [array]$AllowedDomains,
        [array]$BlockedSenders,
        [array]$BlockedDomains
    )
    try {
        Write-Log "Configuring Tenant Allow/Block List" "INFO"
        
        foreach ($sender in $AllowedSenders) {
            New-TenantAllowBlockListItems -ListType Sender -Entries $sender -Allow $true
        }
        
        foreach ($domain in $AllowedDomains) {
            New-TenantAllowBlockListItems -ListType Domain -Entries $domain -Allow $true
        }
        
        foreach ($sender in $BlockedSenders) {
            New-TenantAllowBlockListItems -ListType Sender -Entries $sender -Block $true
        }
        
        foreach ($domain in $BlockedDomains) {
            New-TenantAllowBlockListItems -ListType Domain -Entries $domain -Block $true
        }

        Write-Log "Tenant Allow/Block List configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-TenantAllowBlockList: $_" "ERROR"
    }
}

# Function to configure User Reported Messages
function Set-UserReportedMessages {
    param (
        [string]$CusAdminAddress
    )
    try {
        Write-Log "Configuring User Reported Messages" "INFO"
        
        $params = @{
            EnableReportToMicrosoft = $true
            EnableUserSubmission    = $true
            SubmissionReportOptions = "AllReports"
            AdminAddress            = $CusAdminAddress
        }
        Set-ReportSubmissionPolicy @params

        Write-Log "User Reported Messages configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-UserReportedMessages: $_" "ERROR"
    }
}


##############################################################################
### Main script logic
##############################################################################

Write-Host
Write-Host "================ M365 ATP Configuration ================" -ForegroundColor DarkCyan
Write-Host

try {
    # Check/Enter Admin Creds
    If ($null -eq $Global:Credential.UserName) {
        Write-Host
        Write-Host "Please enter the Global Admin Account into the PowerShell Credential Prompt" -ForegroundColor Green
        Write-Host
        try {
            $Global:Credential = Get-Credential -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "Credentials not entered. Exiting..."
            exit
        }
        Write-Host
    }
    else {
        Write-Log "$Global:TenantDomain Credentials $($Global:Credential.UserName) being used"
    }
    $CusAdminAddress = $Global:Credential.UserName

    # Verify Service Connections
    Verify-ServiceConnections

    # Menu system
    do {
        #Write-Host "Debug List-------"
        #Write-Host "Admin Accnt: $CusAdminAddress"
        #Write-Host "MSP Alert Addr: $($Config.MSPAlertsAddress)"
        #Write-Host "Config File: $Config"
        #Write-Host "Config Path: $configFile"
        #Write-Host
        #Write-Host
        Write-Host
        Write-Host "====== M365 Defender P2 (ATP) Configuration Menu =======" -ForegroundColor DarkCyan
        Write-Host "1. Configure Auto-Forward and Junk Email Settings"
        Write-Host "2. Configure Anti-Malware Policy"
        Write-Host "3. Configure Anti-Phishing Policy"
        Write-Host "4. Configure Anti-Spam Policy"
        Write-Host "5. Configure Safe Attachments Policy"
        Write-Host "6. Configure Safe Links Policy"
        Write-Host "7. Configure Tenant Allow/Block List"
        Write-Host "8. Configure User Reported Messages"
        Write-Host "A: Configure ALL Policies" -ForegroundColor Yellow
        Write-Host "Q: Back to Main Menu"
        Write-Host

        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            '1' {
                Set-AutoForwardAndJunkConfig -CusAdminAddress $CusAdminAddress -MSPAlertsAddress $Config.MSPAlertsAddress
            }
            '2' {
                Set-AntiMalwarePolicy -CusAdminAddress $CusAdminAddress
            }
            '3' {
                Set-AntiPhishingPolicy
            }
            '4' {
                Set-AntiSpamPolicy -CusAdminAddress $CusAdminAddress -ExcludedSenders $Config.ExcludedSenders -ExcludedDomains $Config.ExcludedDomains
            }
            '5' {
                Set-SafeAttachmentsPolicy -CusAdminAddress $CusAdminAddress
            }
            '6' {
                Set-SafeLinksPolicy -CusAdminAddress $CusAdminAddress
            }
            '7' {
                Set-TenantAllowBlockList -AllowedSenders $Config.AllowedSenders -AllowedDomains $Config.AllowedDomains -BlockedSenders $Config.BlockedSenders -BlockedDomains $Config.BlockedDomains
            }
            '8' {
                Set-UserReportedMessages -CusAdminAddress $CusAdminAddress
            }
            'A' {
                Set-AutoForwardAndJunkConfig -CusAdminAddress $CusAdminAddress -MSPAlertsAddress $Config.MSPAlertsAddress
                Set-AntiMalwarePolicy -CusAdminAddress $CusAdminAddress
                Set-AntiPhishingPolicy
                Set-AntiSpamPolicy -CusAdminAddress $CusAdminAddress -ExcludedSenders $Config.ExcludedSenders -ExcludedDomains $Config.ExcludedDomains
                Set-SafeAttachmentsPolicy -CusAdminAddress $CusAdminAddress
                Set-SafeLinksPolicy -CusAdminAddress $CusAdminAddress
                Set-TenantAllowBlockList -AllowedSenders $Config.AllowedSenders -AllowedDomains $Config.AllowedDomains -BlockedSenders $Config.BlockedSenders -BlockedDomains $Config.BlockedDomains
                Set-UserReportedMessages -CusAdminAddress $CusAdminAddress
                Write-Log "All configurations completed successfully" "INFO"
            }
            'Q' {
                Write-Host "Exiting..." -ForegroundColor DarkYellow
                break
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor DarkRed
            }
        }
    } while ($choice -ne 'q')
}
catch {
    Write-Log "An error occurred during script execution: $_" "ERROR"
}
finally {
    Write-Log "Script execution completed." "INFO"
}