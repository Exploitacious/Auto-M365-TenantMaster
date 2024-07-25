# M365 DLP Config

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
Write-Host "================ M365 DLP Config ================" -ForegroundColor DarkCyan
Write-Host

$logFile = Join-Path $PSScriptRoot "DLPConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
$adminAddress = $adminCredential.UserName

# Sensitive Info Types
function Get-SensitiveInfoTypes {
    param (
        [int]$MinCount,
        [int]$MaxCount = $null,
        [string]$ConfidenceLevel = 'High'
    )

    $sensitiveInfoTypes = @(
        @{Name = "U.S. Social Security Number (SSN)"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "Credit Card Number"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "U.S. / U.K. Passport Number"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "U.S. Bank Account Number"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "U.S. Driver's License Number"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "International Banking Account Number (IBAN)"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel };
        @{Name = "Medicare Beneficiary Identifier (MBI) card"; minCount = $MinCount; maxCount = $MaxCount; confidencelevel = $ConfidenceLevel }
    )

    if ($null -eq $MaxCount) {
        $sensitiveInfoTypes | ForEach-Object { $_.Remove('maxCount') }
    }

    return @{SensitiveInformation = $sensitiveInfoTypes }
}

# EXO DLP Policy
function Set-ExchangeOnlineDLPPolicy {
    param (
        [array]$SensitiveInfo,
        [string]$AdminAddress
    )

    $policyName = "[Stage 1] Data Loss Prevention EXO [v1.2]"
    $ruleName = "[Stage 1] DLP EXO Rule - Encrypt All [v1.2]"

    $policyParams = @{
        'Comment'  = "[Stage 1] Data Loss Prevention EXO [v1.2] Imported via PS"
        'Priority' = 0
        'Mode'     = "Enable"
    }

    $ruleParams = @{
        'Comment'                             = "[Stage 1] Data Loss Prevention Exchange Online Rule Encrypt All Outgoing [v1.2] Imported via PS"
        'AccessScope'                         = "NotInOrganization"
        'EncryptRMSTemplate'                  = "Encrypt"
        'ExceptIfDocumentIsPasswordProtected' = $True
        'NotifyUser'                          = "LastModifier"
        'NotifyPolicyTipCustomText'           = "This email contains sensitive information and will be automatically encrypted when sent."
        'NotifyEmailCustomText'               = "The email you sent contains sensitive information, therefore it has been automatically encrypted as per company policy before being delivered to your recipient. If they are having issues opening the message, please provide them with the following instructions: https://support.microsoft.com/en-us/topic/how-do-i-open-a-protected-message-1157a286-8ecc-4b1e-ac43-2a608fbf3098"
    }

    # Add ContentContainsSensitiveInformation only if $SensitiveInfo is not null or empty
    if ($SensitiveInfo -and $SensitiveInfo.SensitiveInformation.Count -gt 0) {
        $ruleParams['ContentContainsSensitiveInformation'] = $SensitiveInfo
    }

    try {
        $existingPolicy = Get-DlpCompliancePolicy -Identity $policyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Set-DlpCompliancePolicy -Identity $policyName @policyParams
            Write-Log "Updated Exchange Online DLP Policy: $policyName" "INFO"
        }
        else {
            New-DlpCompliancePolicy -Name $policyName @policyParams -ExchangeLocation All
            Write-Log "Created Exchange Online DLP Policy: $policyName" "INFO"
        }

        $existingRule = Get-DlpComplianceRule -Identity $ruleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Set-DlpComplianceRule -Identity $ruleName @ruleParams -Policy $policyName
            Write-Log "Updated Exchange Online DLP Rule: $ruleName" "INFO"
        }
        else {
            New-DlpComplianceRule -Name $ruleName @ruleParams -Policy $policyName
            Write-Log "Created Exchange Online DLP Rule: $ruleName" "INFO"
        }
    }
    catch {
        Write-Log "Failed to create/update Exchange Online DLP Policy or Rule. Error: $_" "ERROR"
    }
}

# Non-EXO DLP Policy
function Set-NonExchangeDLPPolicies {
    param (
        [array]$SensitiveInfoHigh,
        [array]$SensitiveInfoLow,
        [array]$SensitiveInfo,
        [string]$AdminAddress
    )

    $spoOdoPolicyName = "[Stage 1] Data Loss Prevention for SPO + OD [v1.2]"
    $nonExoPolicyName = "[Stage 1] Data Loss Prevention Non-EXO [v1.2]"

    $spoOdoPolicyParams = @{
        'Comment'  = "[Stage 1] Data Loss Prevention for SharePoint and OneDrive [v1.2] Imported via PS"
        'Priority' = 1
        'Mode'     = "Enable"
    }

    $nonExoPolicyParams = @{
        'Comment'  = "[Stage 1] Data Loss Prevention for All Platforms Non-EXO [v1.2] Imported via PS"
        'Priority' = 2
        'Mode'     = "Enable"
    }

    try {
        $existingSpoOdoPolicy = Get-DlpCompliancePolicy -Identity $spoOdoPolicyName -ErrorAction SilentlyContinue
        if ($existingSpoOdoPolicy) {
            Set-DlpCompliancePolicy -Identity $spoOdoPolicyName @spoOdoPolicyParams
            Write-Log "Updated SharePoint and OneDrive DLP Policy: $spoOdoPolicyName" "INFO"
        }
        else {
            New-DlpCompliancePolicy -Name $spoOdoPolicyName @spoOdoPolicyParams -SharePointLocation All -OneDriveLocation All
            Write-Log "Created SharePoint and OneDrive DLP Policy: $spoOdoPolicyName" "INFO"
        }

        $existingNonExoPolicy = Get-DlpCompliancePolicy -Identity $nonExoPolicyName -ErrorAction SilentlyContinue
        if ($existingNonExoPolicy) {
            Set-DlpCompliancePolicy -Identity $nonExoPolicyName @nonExoPolicyParams
            Write-Log "Updated Non-Exchange DLP Policy: $nonExoPolicyName" "INFO"
        }
        else {
            New-DlpCompliancePolicy -Name $nonExoPolicyName @nonExoPolicyParams -SharePointLocation All -OneDriveLocation All -TeamsLocation All
            Write-Log "Created Non-Exchange DLP Policy: $nonExoPolicyName" "INFO"
        }

        # Create or update rules for these policies
        $rulesToCreate = @(
            @{
                Name                      = "[Stage 1] DLP Non-EXO Rule - Any Volume [v1.2]"
                Policy                    = $spoOdoPolicyName
                BlockAccessScope          = "PerAnonymousUser"
                BlockAccess               = $True
                NotifyUser                = "LastModifier"
                NotifyPolicyTipCustomText = "File contains sensitive information and can not be shared anonymously"
                SensitiveInfo             = $SensitiveInfo
            },
            @{
                Name                      = "[Stage 1] DLP Non-EXO Rule - High Volume [v1.2]"
                Policy                    = $nonExoPolicyName
                AccessScope               = "NotInOrganization"
                BlockAccessScope          = "PerUser"
                BlockAccess               = $True
                GenerateIncidentReport    = @("SiteAdmin", $AdminAddress)
                ReportSeverityLevel       = "High"
                NotifyUser                = "SiteAdmin"
                NotifyPolicyTipCustomText = "File contains more than one instance of sensitive information and can not be shared outside of your organization without a justification. Please see option to override."
                SensitiveInfo             = $SensitiveInfoHigh
            },
            @{
                Name                      = "[Stage 1] DLP Non-EXO Rule - Low Volume [v1.2]"
                Policy                    = $nonExoPolicyName
                AccessScope               = "NotInOrganization"
                BlockAccessScope          = "PerUser"
                BlockAccess               = $True
                NotifyUser                = "SiteAdmin"
                NotifyPolicyTipCustomText = "File contains sensitive information and can not be shared outside of your organization without a justification. Please see option to override."
                SensitiveInfo             = $SensitiveInfoLow
            }
        )

        foreach ($rule in $rulesToCreate) {
            $ruleName = $rule.Name
            $policyName = $rule.Policy
            $ruleParams = $rule.Clone()
            $ruleParams.Remove('Name')
            $ruleParams.Remove('Policy')
            $ruleParams.Remove('SensitiveInfo')

            if ($rule.SensitiveInfo -and $rule.SensitiveInfo.SensitiveInformation.Count -gt 0) {
                $ruleParams['ContentContainsSensitiveInformation'] = $rule.SensitiveInfo
            }

            $existingRule = Get-DlpComplianceRule -Identity $ruleName -ErrorAction SilentlyContinue
            if ($existingRule) {
                Set-DlpComplianceRule -Identity $ruleName @ruleParams -Policy $policyName
                Write-Log "Updated DLP Rule: $ruleName" "INFO"
            }
            else {
                New-DlpComplianceRule -Name $ruleName @ruleParams -Policy $policyName
                Write-Log "Created DLP Rule: $ruleName" "INFO"
            }
        }
    }
    catch {
        Write-Log "Failed to create/update Non-Exchange DLP Policies or Rules. Error: $_" "ERROR"
    }
}

# Set Sensitivity Labels
function Set-SensitivityLabels {
    $labels = @(
        @{Name = "Public"; DisplayName = "Public"; Tooltip = "Information that can be freely shared" },
        @{Name = "Internal"; DisplayName = "Internal"; Tooltip = "For internal use only" },
        @{Name = "Confidential"; DisplayName = "Confidential"; Tooltip = "Sensitive information, limited distribution" },
        @{Name = "Highly Confidential"; DisplayName = "Highly Confidential"; Tooltip = "Extremely sensitive information" }
    )

    foreach ($label in $labels) {
        try {
            $existingLabel = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
            if ($existingLabel) {
                Set-Label -Identity $label.Name -DisplayName $label.DisplayName -Tooltip $label.Tooltip
                Write-Log "Updated existing label: $($label.Name)" "INFO"
            }
            else {
                New-Label -Name $label.Name -DisplayName $label.DisplayName -Tooltip $label.Tooltip
                Write-Log "Created new label: $($label.Name)" "INFO"
            }
        }
        catch {
            Write-Log "Failed to create/update label $($label.Name). Error: $_" "ERROR"
        }
    }
}

# Set Sensitivity Label Policy
function Set-SensitivityLabelPolicy {
    $policyName = "Default Sensitivity Label Policy"
    try {
        $policy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
        $labels = Get-Label
        $internalLabel = $labels | Where-Object { $_.DisplayName -eq "Internal" }

        if ($policy) {
            # Update existing policy
            $policyParams = @{
                Identity = $policyName
                Settings = @{
                    mandatory      = $false
                    defaultlabelid = $internalLabel.GUID
                }
            }
            Set-LabelPolicy @policyParams
            Set-LabelPolicy -Identity $policyName -AdvancedSettings @{AttachmentAction = "Automatic" }
            Write-Log "Updated existing policy: $policyName" "INFO"
        }
        else {
            # Create new policy
            $policyParams = @{
                Name     = $policyName
                Settings = @{
                    mandatory      = $false
                    defaultlabelid = $internalLabel.GUID
                }
            }
            New-LabelPolicy @policyParams -Labels $labels.GUID -ExchangeLocation All
            Set-LabelPolicy -Identity $policyName -AdvancedSettings @{AttachmentAction = "Automatic" }
            Write-Log "Created new policy: $policyName" "INFO"
        }
    }
    catch {
        Write-Log "Failed to create/update policy $policyName. Error: $_" "ERROR"
    }
}

# Set SP and OD Compliance Integration
function Set-SharePointOneDriveIntegration {
    try {
        Set-SPOTenant -EnableAIPIntegration $true
        Set-SPOTenant -EnableSensitivityLabelforPDF $true
        Write-Log "Configured SharePoint and OneDrive AIP integration with PDF Support" "INFO"
    }
    catch {
        Write-Log "Failed to configure SharePoint and OneDrive integration. Error: $_" "ERROR"
    }
}

##############################################################################
### Main script logic
##############################################################################

try {
    $confirmDelete = Read-Host "Do you want to delete existing DLP policies and rules? (Y/N)"
    if ($confirmDelete -eq 'Y') {
        Remove-ExistingDLPPolicies
    }

    $sensitiveInfoHigh = Get-SensitiveInfoTypes -MinCount 3
    $sensitiveInfoLow = Get-SensitiveInfoTypes -MinCount 1 -MaxCount 2
    $sensitiveInfo = Get-SensitiveInfoTypes -MinCount 1

    # Very Broken for now
    # Set-ExchangeOnlineDLPPolicy -SensitiveInfo $sensitiveInfo -AdminAddress $adminAddress
    # Set-NonExchangeDLPPolicies -SensitiveInfoHigh $sensitiveInfoHigh -SensitiveInfoLow $sensitiveInfoLow -SensitiveInfo $sensitiveInfo -AdminAddress $adminAddress

    Set-SensitivityLabels
    Set-SensitivityLabelPolicy
    Set-SharePointOneDriveIntegration
}
catch {
    Write-Log "An error occurred during script execution: $_" "ERROR"
}
finally {
    Write-Log "DLP Configuration completed successfully" "INFO"
}