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

# Function to configure Anti-Phishing policy
function Set-AntiPhishingPolicy {
    param (
        [array]$RecipientDomains,
        [array]$TargetedUsersToProtect,
        [array]$ExcludedDomains,
        [array]$ExcludedSenders
    )
    try {
        Write-Log "Configuring Anti-Phishing Policy" "INFO"
        
        $policyParams = @{
            Identity                            = "Office365 AntiPhish Default"
            AdminDisplayName                    = "Default Anti-Phishing Policy"
            EnableOrganizationDomainsProtection = $true
            EnableTargetedDomainsProtection     = $true
            TargetedDomainsToProtect            = $RecipientDomains
            EnableTargetedUserProtection        = $true
            TargetedUsersToProtect              = $TargetedUsersToProtect
            EnableMailboxIntelligence           = $true
            EnableMailboxIntelligenceProtection = $true
            MailboxIntelligenceProtectionAction = "Quarantine"
            EnableSpoofIntelligence             = $true
            AuthenticationFailAction            = "MoveToJmf"
            PhishThresholdLevel                 = 2
            Enabled                             = $true
            ExcludedDomains                     = $ExcludedDomains
            ExcludedSenders                     = $ExcludedSenders
        }
        Set-AntiPhishPolicy @policyParams

        Write-Log "Anti-Phishing Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiPhishingPolicy: $_" "ERROR"
    }
}

# Function to configure Anti-Spam policy
function Set-AntiSpamPolicy {
    param (
        [string]$CusAdminAddress,
        [array]$ExcludedSenders,
        [array]$ExcludedDomains
    )
    try {
        Write-Log "Configuring Anti-Spam Policy" "INFO"
        
        $policyParams = @{
            Identity                             = "Default"
            AdminDisplayName                     = "Default Anti-Spam Policy"
            BulkThreshold                        = 6
            MarkAsSpamBulkMail                   = "On"
            IncreaseScoreWithImageLinks          = "On"
            IncreaseScoreWithNumericIps          = "On"
            IncreaseScoreWithRedirectToOtherPort = "On"
            IncreaseScoreWithBizOrInfoUrls       = "On"
            MarkAsSpamEmptyMessages              = "On"
            MarkAsSpamJavaScriptInHtml           = "On"
            MarkAsSpamFramesInHtml               = "On"
            MarkAsSpamObjectTagsInHtml           = "On"
            MarkAsSpamEmbedTagsInHtml            = "On"
            MarkAsSpamFormTagsInHtml             = "On"
            MarkAsSpamWebBugsInHtml              = "On"
            MarkAsSpamSensitiveWordList          = "On"
            MarkAsSpamSpfRecordHardFail          = "On"
            MarkAsSpamFromAddressAuthFail        = "On"
            MarkAsSpamNdrBackscatter             = "On"
            QuarantineRetentionPeriod            = 30
            InlineSafetyTipsEnabled              = $true
            BulkSpamAction                       = "MoveToJmf"
            PhishSpamAction                      = "Quarantine"
            SpamAction                           = "MoveToJmf"
            EnableEndUserSpamNotifications       = $true
            EndUserSpamNotificationFrequency     = 1
            SpamZapEnabled                       = $true
            PhishZapEnabled                      = $true
            AllowedSenders                       = $ExcludedSenders
            AllowedSenderDomains                 = $ExcludedDomains
        }
        Set-HostedContentFilterPolicy @policyParams

        # Create bypass policy for admin
        $bypassPolicyParams = @{
            Name                     = "Bypass Spam Filter for Admin"
            AdminDisplayName         = "Bypass Spam Filter for Admin"
            SpamAction               = "AddXHeader"
            HighConfidenceSpamAction = "AddXHeader"
            BulkSpamAction           = "AddXHeader"
        }
        New-HostedContentFilterPolicy @bypassPolicyParams

        $bypassRuleParams = @{
            Name                      = "Bypass Spam Filter Rule for Admin"
            HostedContentFilterPolicy = "Bypass Spam Filter for Admin"
            SentTo                    = $CusAdminAddress
            Enabled                   = $true
        }
        New-HostedContentFilterRule @bypassRuleParams

        Write-Log "Anti-Spam Policy configuration completed" "INFO"
    }
    catch {
        Write-Log "Error in Set-AntiSpamPolicy: $_" "ERROR"
    }
}

# Function to configure Safe Attachments policy
function Set-SafeAttachmentsPolicy {
    param (
        [string]$CusAdminAddress
    )
    try {
        Write-Log "Configuring Safe Attachments Policy" "INFO"
        
        $policyParams = @{
            Name                     = "Default Safe Attachments Policy"
            AdminDisplayName         = "Default Safe Attachments Policy"
            Action                   = "DynamicDelivery"
            ActionOnError            = $true
            Enable                   = $true
            Redirect                 = $true
            RedirectAddress          = $CusAdminAddress
            EnableForInternalSenders = $true
        }
        New-SafeAttachmentPolicy @policyParams

        $ruleParams = @{
            Name                 = "Default Safe Attachments Rule"
            SafeAttachmentPolicy = "Default Safe Attachments Policy"
            RecipientDomainIs    = (Get-AcceptedDomain).Name
            Enabled              = $true
        }
        New-SafeAttachmentRule @ruleParams

        # Create bypass policy for admin
        $bypassPolicyParams = @{
            Name             = "Bypass Safe Attachments for Admin"
            AdminDisplayName = "Bypass Safe Attachments for Admin"
            Action           = "Allow"
            Enable           = $true
        }
        New-SafeAttachmentPolicy @bypassPolicyParams

        $bypassRuleParams = @{
            Name                 = "Bypass Safe Attachments Rule for Admin"
            SafeAttachmentPolicy = "Bypass Safe Attachments for Admin"
            SentTo               = $CusAdminAddress
            Enabled              = $true
        }
        New-SafeAttachmentRule @bypassRuleParams

        Write-Log "Safe Attachments Policy configuration completed" "INFO"
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
        New-SafeLinksPolicy @policyParams

        $ruleParams = @{
            Name              = "Default Safe Links Rule"
            SafeLinksPolicy   = "Default Safe Links Policy"
            RecipientDomainIs = (Get-AcceptedDomain).Name
            Enabled           = $true
        }
        New-SafeLinksRule @ruleParams

        # Create bypass policy for admin
        $bypassPolicyParams = @{
            Name                     = "Bypass Safe Links for Admin"
            AdminDisplayName         = "Bypass Safe Links for Admin"
            ScanUrls                 = $false
            EnableSafeLinksForEmail  = $false
            EnableSafeLinksForTeams  = $false
            EnableSafeLinksForOffice = $false
        }
        New-SafeLinksPolicy @bypassPolicyParams

        $bypassRuleParams = @{
            Name            = "Bypass Safe Links Rule for Admin"
            SafeLinksPolicy = "Bypass Safe Links for Admin"
            SentTo          = $CusAdminAddress
            Enabled         = $true
        }
        New-SafeLinksRule @bypassRuleParams

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
        Write-Host "A: Run All Configurations" -ForegroundColor Yellow
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
                $recipientDomains = (Get-AcceptedDomain).Name
                $targetedUsers = (Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty UserPrincipalName)
                Set-AntiPhishingPolicy -RecipientDomains $recipientDomains -TargetedUsersToProtect $targetedUsers -ExcludedDomains $Config.ExcludedDomains -ExcludedSenders $Config.ExcludedSenders
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
                $recipientDomains = (Get-AcceptedDomain).Name
                $targetedUsers = (Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty UserPrincipalName)
                Set-AntiPhishingPolicy -RecipientDomains $recipientDomains -TargetedUsersToProtect $targetedUsers -ExcludedDomains $Config.ExcludedDomains -ExcludedSenders $Config.ExcludedSenders
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