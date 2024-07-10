<#
#################################################
## CONFIGURE OFFICE 365 Data Loss Prevention Policies (DLP)
#################################################


Updates for v1.2:
- Removed some Sensitive Info Types and policy
    - Added Connect-CMDlet Option
    - Changed Confidence Level to "High" on High Volume Policy
    - Changed Confidence Level to "High" on Low Volume Policy
- Removed Email policytip/notification for "LastModifier" due to excessive notifications during 'OneDrive Known Folder Migrations'.
- Removed "AzureAD Storage Account Key (Generic)" Information Type which was causing excessive false positives
- Some light script cleanup


Connect to Exchange Online via PowerShell using MFA: (Connect-ExchangeOnline)
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

Connect to Connect to Security & Compliance Center (Connect-IPPSSession)
https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps

## Create New DLP Policy
## https://docs.microsoft.com/en-us/powershell/module/exchange/new-classificationrulecollection?view=exchange-ps

## Create New DLP Rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/new-dlpcompliancerule?view=exchange-ps

Structure of the script:
#  - Policy: Location
#  - - Rule1: Priority 0 
#  - - Rule2: Priority 1

Created By: Alex Ivantsov
Email: Alex@ivantsov.tech

#>


#################################################
## Variables - Set your organization's variables
#################################################




# Other Variables

$MessageColor = "Green"
$AssessmentColor = "Yellow"
$ErrorColor = 'Red'
# $AllowedForwardingGroup =  Read-Host "Enter the GUID of the SECURITY GROUP ** IN " QUOTES ** which will allow forwarding to external receipients. (MUST BE ACTIVE IN AAD)"
# Allowed Forwarding by security groups doesn't work well in practice due to Microsoft. No fix available yet.

# Increase the Function Count in Powershell
$MaximumFunctionCount = 32768
# Increase the Variable Count in Powershell
$MaximumVariableCount = 32768


#################################################
## Module Check
#################################################

$Answer = Read-Host "Would you like this script to run a check to make sure you have all the modules correctly installed? *Recommended*"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

   Write-Host
   Write-Host -ForegroundColor $AssessmentColor "Checking for Installed Modules..."

   $Modules = @(
      "ExchangeOnlineManagement"; 
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

} 

#################################################
## Module Connection
#################################################

$Answer = Read-Host "Would you like the script to connect all modules? ('N' to skip automatic module connection)"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

   $Cred = Get-Credential

   $AlertAddress = $Cred.UserName

   if ($null -eq $AlertAddress) {
      Write-Host
      Write-Host
      $AlertAddress = Read-Host "Enter the Customer's ADMIN EMAIL ADDRESS. This is where you will recieve alerts, notifications and set up admin access to all mailboxes. MUST BE AN INTERNAL ADMIN ADDRESS"
   }

   # Exchange
   Connect-ExchangeOnline -UserPrincipalName $Cred.Username
   Write-Host -ForegroundColor $MessageColor "Exchange Online Connected!"
   Write-Host

   # Azure Information Protection
   Connect-AipService
   Write-Host -ForegroundColor $MessageColor "Azure Information Protection Connected!"
   Write-Host

   # Information Protection Service
   Connect-IPPSSession
   Write-Host -ForegroundColor $MessageColor "Information Protection Service Connected!"            
   Write-Host

}

########
# The Fun Parts
########

$Answer = Read-Host "Would you like the script to begin the DLP Configuration for this tenant? (Y / N)"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {


   $AlertAddress = $Cred.UserName

   if ($null -eq $AlertAddress) {
      Write-Host
      Write-Host
      $AlertAddress = Read-Host "Enter the Customer's ADMIN EMAIL ADDRESS. This is where you will recieve alerts, notifications and set up admin access to all mailboxes. MUST BE AN INTERNAL ADMIN ADDRESS"
   }

   ##############
   # SENSITIVE INFO Definitions - Sensitive Info High Volume (Count 2+) & Any Volume (1+)
   ##############


   $SensitiveInfoHigh = @(
      @{Name = "U.S. Social Security Number (SSN)"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Credit Card Number"; minCount = "3"; confidencelevel = 'High' };
      #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="3"; confidencelevel = 'High'};
      #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
      @{Name = "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount = "1"; confidencelevel = 'High' }; # U.S. / U.K. Passport Number
      @{Name = "U.S. Bank Account Number"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "U.S. Driver's License Number"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "International Banking Account Number (IBAN)"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Medicare Beneficiary Identifier (MBI) card"; minCount = "3"; confidencelevel = 'High' };

      @{Name = "Azure DocumentDB Auth Key"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure IoT Connection String"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure Publish Setting Password"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure Redis Cache Connection String"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure SAS"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure Service Bus Connection String"; minCount = "3"; confidencelevel = 'High' };
      @{Name = "Azure Storage Account Key"; minCount = "3"; confidencelevel = 'High' };
      #   @{Name= "Azure Storage Account Key (Generic)"; minCount="3"; confidencelevel = 'High'};
   )

   $SensitiveInfoLow = @(
      @{Name = "U.S. Social Security Number (SSN)"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Credit Card Number"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="1"; maxCount="2"; confidencelevel = 'High'};
      #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
      @{Name = "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount = "1"; confidencelevel = 'High' }; # U.S. / U.K. Passport Number
      @{Name = "U.S. Bank Account Number"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "U.S. Driver's License Number"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "International Banking Account Number (IBAN)"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Medicare Beneficiary Identifier (MBI) card"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };

      @{Name = "Azure DocumentDB Auth Key"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure IoT Connection String"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure Publish Setting Password"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure Redis Cache Connection String"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure SAS"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure Service Bus Connection String"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      @{Name = "Azure Storage Account Key"; minCount = "1"; maxCount = "2"; confidencelevel = 'High' };
      #   @{Name= "Azure Storage Account Key (Generic)"; minCount="1"; maxCount="2"; confidencelevel = 'High'};
   )

   $SensitiveInfo = @(
      @{Name = "U.S. Social Security Number (SSN)"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Credit Card Number"; minCount = "1"; confidencelevel = 'High' };
      #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="1"; confidencelevel = 'High'};
      #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
      @{Name = "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount = "1"; confidencelevel = 'High' }; # U.S. / U.K. Passport Number
      @{Name = "U.S. Bank Account Number"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "U.S. Driver's License Number"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "International Banking Account Number (IBAN)"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Medicare Beneficiary Identifier (MBI) card"; minCount = "1"; confidencelevel = 'High' };

      @{Name = "Azure DocumentDB Auth Key"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure IoT Connection String"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure Publish Setting Password"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure Redis Cache Connection String"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure SAS"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure Service Bus Connection String"; minCount = "1"; confidencelevel = 'High' };
      @{Name = "Azure Storage Account Key"; minCount = "1"; confidencelevel = 'High' };
      #   @{Name= "Azure Storage Account Key (Generic)"; minCount="1"; confidencelevel = 'High'};
   )


   #######
   # Delete All Other conflicting policies and rules. Only run Once per 60 minutes
   #######

   Write-Host
   Write-Host
   $Answer2 = Read-Host "Do you want to Delete all custom DLP rules and Policices, so that only the new [v1.2] Data Loss Prevention Policies and Rules Apply? This is recommended to do only once, unless you have other custom rules you wish to keep. Type Y or N and press Enter to continue"
   if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {

      Get-DlpCompliancePolicy | Remove-DlpCompliancePolicy
      Get-DlpComplianceRule | Remove-DlpComplianceRule

      Write-Host
      Write-Host
      Write-Host -ForegroundColor yellow "All Custom Policies have been deleted."


   }




   ##########
   # Exchange Online Policy + Rule - Applies only to Exchange Online
   ##########

   Write-Host
   Write-Host
   Write-Host -ForegroundColor green "Creating [v1.2] Data Loss Prevention Policy and Rules for Exchange Online."

   $EXoDLPparam = @{
      'Name'             = "[Stage 1] Data Loss Prevention EXO [v1.2]";
      'Comment'          = "[Stage 1] Data Loss Prevention EXO [v1.2] Imported via PS";
      'Priority'         = 0;
      'Mode'             = "Enable";
      'ExchangeLocation' = "All"
   }

   New-DlpCompliancePolicy @EXoDLPparam


   # All Exchange ; Encrypt-All Automatically and provide policy tip (your message was encrypted...)

   $EXoDLruleParam = @{
      'Name'                                = "[Stage 1] DLP EXO Rule - Encrypt All [v1.2]";
      'Comment'                             = "[Stage 1] Data Loss Prevention Exchange Online Rule Encrypt All Outgoing [v1.2] Imported via PS";
      'Disabled'                            = $False;
      'Priority'                            = 0;
      'Policy'                              = "[Stage 1] Data Loss Prevention EXO [v1.2]";
      'ContentContainsSensitiveInformation' = $SensitiveInfo;
         
      'AccessScope'                         = "NotInOrganization";
      #   'BlockAccessScope' = "PerUser";
      'EncryptRMSTemplate'                  = "Encrypt"; ## Exchange Only
      #  'DocumentIsPasswordProtected' = $True;
      'ExceptIfDocumentIsPasswordProtected' = $True;

      'NotifyUser'                          = "LastModifier";
      'NotifyPolicyTipCustomText'           = "This email contains sensitive information and will be automatically encrypted when sent.";
      'NotifyEmailCustomText'               = "The email you sent contains sensitive information, therefore it has been automatically encrypted as per company policy before being delivered to your recipient. If they are having issues opening the message, please provide them with the following instructions: https://support.microsoft.com/en-us/topic/how-do-i-open-a-protected-message-1157a286-8ecc-4b1e-ac43-2a608fbf3098";

      'StopPolicyProcessing'                = $False;

   }

   New-DlpComplianceRule @EXoDLruleParam

   Write-Host
   Write-Host
   Write-Host -ForegroundColor green "[v1.2] Data Loss Prevention Policy and Rules for Exchange Online [Encrypt All] has been created."



   ##########
   # All Locations Policies + Rule(s) - Applies to Teams, SharePoint and OneDrive. Detects and Labels All Sensitive Info.
   ##########

   Write-Host
   Write-Host -ForegroundColor green "Creating [v1.2] Data Loss Prevention Policy and Rules for All Non-Exchange Platforms."

   $SPO_ODO_DLP_param = @{
      'Name'               = "[Stage 1] Data Loss Prevention for SPO + OD [v1.2]";
      'Comment'            = "[Stage 1] Data Loss Prevention for SharePoint and OneDrive [v1.2] Imported via PS";
      'Priority'           = 1;
      'Mode'               = "Enable";

      'SharePointLocation' = "All";

      'OneDriveLocation'   = "All";

   }

   New-DlpCompliancePolicy @SPO_ODO_DLP_param

   $NonEXoDLPparam = @{
      'Name'               = "[Stage 1] Data Loss Prevention Non-EXO [v1.2]";
      'Comment'            = "[Stage 1] Data Loss Prevention for All Platforms Non-EXO [v1.2] Imported via PS";
      'Priority'           = 2;
      'Mode'               = "Enable";

      'TeamsLocation'      = "All";

      'SharePointLocation' = "All";

      'OneDriveLocation'   = "All";

   }

   New-DlpCompliancePolicy @NonEXoDLPparam


   # SPO + OD ; Any Volume - Block Access to Anonymous Users

   $NonEXoDLruleParamAny = @{
      'Name'                                = "[Stage 1] DLP Non-EXO Rule - Any Volume [v1.2]";
      'Comment'                             = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule ANY Volume (Block Anonymous) [v1.2] Imported via PS";
      'Disabled'                            = $False;
      'Priority'                            = 0;
      'Policy'                              = "[Stage 1] Data Loss Prevention for SPO + OD [v1.2]";

      'BlockAccessScope'                    = "PerAnonymousUser";
      'BlockAccess'                         = $True;
      'NotifyUser'                          = "LastModifier";
      'NotifyPolicyTipCustomText'           = "File contains sensitive information and can not be shared anonymously";

      'RemoveRMSTemplate'                   = $False;
      'ContentContainsSensitiveInformation' = $SensitiveInfo;
      'StopPolicyProcessing'                = $False;
      'DocumentIsPasswordProtected'         = $False;
      'ExceptIfDocumentIsPasswordProtected' = $False;
      'DocumentIsUnsupported'               = $False;
      'ExceptIfDocumentIsUnsupported'       = $False;
      'HasSenderOverride'                   = $False;
      'ExceptIfHasSenderOverride'           = $False;
      'ProcessingLimitExceeded'             = $False;
      'ExceptIfProcessingLimitExceeded'     = $False;
      # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
   }

   New-DlpComplianceRule @NonEXoDLruleParamAny


   # Non-Exchange ; High-Volume (3 or more occurrences) - Record and Generate Report of High-Volume Sharing

   $NonEXoDLruleParamHigh = @{
      'Name'                                = "[Stage 1] DLP Non-EXO Rule - High Volume [v1.2]";
      'Comment'                             = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule High Volume (3+ occurrences) [v1.2] Imported via PS";
      'Disabled'                            = $False;
      'Priority'                            = 0;
      'Policy'                              = "[Stage 1] Data Loss Prevention Non-EXO [v1.2]";

      'AccessScope'                         = "NotInOrganization";
      'BlockAccessScope'                    = "PerUser";
      'BlockAccess'                         = $True;
      'RemoveRMSTemplate'                   = $False;
      'ReportSeverityLevel'                 = "High";
      'GenerateIncidentReport'              = "SiteAdmin", $AlertAddress;
      'IncidentReportContent'               = "Title, DocumentAuthor, DocumentLastModifier, Service, MatchedItem, RulesMatched, Detections, Severity, DetectionDetails, RetentionLabel, SensitivityLabel";
      'NotifyUser'                          = "SiteAdmin";
      'NotifyAllowOverride'                 = "FalsePositive", "WithJustification";
      'NotifyPolicyTipCustomText'           = "File contains more than one instance of sensitive information and can not be shared outside of your organization without a justification. Please see option to override.";

      'ContentContainsSensitiveInformation' = $SensitiveInfoHigh;
      'StopPolicyProcessing'                = $False;
      'DocumentIsPasswordProtected'         = $False;
      'ExceptIfDocumentIsPasswordProtected' = $False;
      'DocumentIsUnsupported'               = $False;
      'ExceptIfDocumentIsUnsupported'       = $False;
      'HasSenderOverride'                   = $False;
      'ExceptIfHasSenderOverride'           = $False;
      'ProcessingLimitExceeded'             = $False;
      'ExceptIfProcessingLimitExceeded'     = $False;
      # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
   }

   New-DlpComplianceRule @NonEXoDLruleParamHigh


   # Non-Exchange ; Low-Volume (1-2 occurrences) (No-Admin Report)

   $NonEXoDLruleParamLow = @{
      'Name'                                = "[Stage 1] DLP Non-EXO Rule - Low Volume [v1.2]";
      'Comment'                             = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule Low Volume (1-2 occurrences) [v1.2] Imported via PS";
      'Disabled'                            = $False;
      'Priority'                            = 1;
      'Policy'                              = "[Stage 1] Data Loss Prevention Non-EXO [v1.2]";

      'AccessScope'                         = "NotInOrganization";
      'BlockAccessScope'                    = "PerUser";
      'BlockAccess'                         = $True;
      'RemoveRMSTemplate'                   = $False;

      'NotifyUser'                          = "SiteAdmin";
      'NotifyAllowOverride'                 = "FalsePositive", "WithJustification";
      'NotifyPolicyTipCustomText'           = "File contains more than one instance of sensitive information and can not be shared outside of your organization without a justification. Please see option to override.";

      'ContentContainsSensitiveInformation' = $SensitiveInfoLow;
      'StopPolicyProcessing'                = $False;
      'DocumentIsPasswordProtected'         = $False;
      'ExceptIfDocumentIsPasswordProtected' = $False;
      'DocumentIsUnsupported'               = $False;
      'ExceptIfDocumentIsUnsupported'       = $False;
      'HasSenderOverride'                   = $False;
      'ExceptIfHasSenderOverride'           = $False;
      'ProcessingLimitExceeded'             = $False;
      'ExceptIfProcessingLimitExceeded'     = $False;
      # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
   }

   New-DlpComplianceRule @NonEXoDLruleParamLow


   Write-Host
   Write-Host
   Write-Host -ForegroundColor green "[v1.2] Data Loss Prevention Policy and Rules for All Non-Exchange Platforms have been created."

} ## End Of Script


#>


# Connect to Security & Compliance Center PowerShell
try {
   Connect-IPPSSession
}
catch {
   Write-Error "Failed to connect to Security & Compliance Center. Error: $_"
   exit
}

# Function to create or update a label
function Set-SensitivityLabel {
   param (
      [string]$Name,
      [string]$DisplayName,
      [string]$Tooltip
   )
   try {
      $label = Get-Label -Identity $Name -ErrorAction SilentlyContinue
      if ($label) {
         Set-Label -Identity $Name -DisplayName $DisplayName -Tooltip $Tooltip
         Write-Host "Updated existing label: $Name"
      }
      else {
         New-Label -Name $Name -DisplayName $DisplayName -Tooltip $Tooltip
         Write-Host "Created new label: $Name"
      }
   }
   catch {
      Write-Error "Failed to create/update label $Name. Error: $_"
   }
}

# Create or update sensitivity labels
$labels = @(
   @{Name = "Public"; DisplayName = "Public"; Tooltip = "Information that can be freely shared" },
   @{Name = "Internal"; DisplayName = "Internal"; Tooltip = "For internal use only" },
   @{Name = "Confidential"; DisplayName = "Confidential"; Tooltip = "Sensitive information, limited distribution" },
   @{Name = "Highly Confidential"; DisplayName = "Highly Confidential"; Tooltip = "Extremely sensitive information" }
)

foreach ($label in $labels) {
   Set-SensitivityLabel @label
}

# Create or update label policy
$policyName = "Default Sensitivity Label Policy"
try {
   $policy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
   if ($policy) {
      Set-LabelPolicy -Identity $policyName -AdvancedSettings @{AttachmentAction = "Automatic" }
      Write-Host "Updated existing policy: $policyName"
   }
   else {
      New-LabelPolicy -Name $policyName -Labels $labels.Name -Settings @{mandatory = $false; defaultlabelid = "Internal" }
      Set-LabelPolicy -Identity $policyName -AdvancedSettings @{AttachmentAction = "Automatic" }
      Write-Host "Created new policy: $policyName"
   }
}
catch {
   Write-Error "Failed to create/update policy $policyName. Error: $_"
}

# Configure SharePoint and OneDrive integration
try {
   Set-SPOTenant -EnableAIPIntegration $true
   Set-SPOTenant -EnableSensitivityLabelInOffice $true
   Write-Host "Configured SharePoint and OneDrive integration"
}
catch {
   Write-Error "Failed to configure SharePoint and OneDrive integration. Error: $_"
}

Write-Host "Sensitivity labeling configuration complete."